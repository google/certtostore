// +build windows

// Copyright 2017 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package certtostore

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
	"github.com/google/logger"
)

const (
	// wincrypt.h constants
	acquireCached           = 0x1                                             // CRYPT_ACQUIRE_CACHE_FLAG
	acquireSilent           = 0x40                                            // CRYPT_ACQUIRE_SILENT_FLAG
	acquireOnlyNCryptKey    = 0x40000                                         // CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG
	encodingX509ASN         = 1                                               // X509_ASN_ENCODING
	encodingPKCS7           = 65536                                           // PKCS_7_ASN_ENCODING
	certStoreProvSystem     = 10                                              // CERT_STORE_PROV_SYSTEM
	certStoreCurrentUser    = uint32(certStoreCurrentUserID << compareShift)  // CERT_SYSTEM_STORE_CURRENT_USER
	certStoreLocalMachine   = uint32(certStoreLocalMachineID << compareShift) // CERT_SYSTEM_STORE_LOCAL_MACHINE
	certStoreCurrentUserID  = 1                                               // CERT_SYSTEM_STORE_CURRENT_USER_ID
	certStoreLocalMachineID = 2                                               // CERT_SYSTEM_STORE_LOCAL_MACHINE_ID
	infoIssuerFlag          = 4                                               // CERT_INFO_ISSUER_FLAG
	compareNameStrW         = 8                                               // CERT_COMPARE_NAME_STR_A
	compareShift            = 16                                              // CERT_COMPARE_SHIFT
	findIssuerStr           = compareNameStrW<<compareShift | infoIssuerFlag  // CERT_FIND_ISSUER_STR_W
	signatureKeyUsage       = 0x80                                            // CERT_DIGITAL_SIGNATURE_KEY_USAGE
	ncryptKeySpec           = 0xFFFFFFFF                                      // CERT_NCRYPT_KEY_SPEC

	// Legacy CryptoAPI flags
	bCryptPadPKCS1 uintptr = 0x2

	// Magic numbers for public key blobs.
	rsa1Magic = 0x31415352 // "RSA1" BCRYPT_RSAPUBLIC_MAGIC
	ecs1Magic = 0x31534345 // "ECS1" BCRYPT_ECDSA_PUBLIC_P256_MAGIC
	ecs3Magic = 0x33534345 // "ECS3" BCRYPT_ECDSA_PUBLIC_P384_MAGIC
	ecs5Magic = 0x35534345 // "ECS5" BCRYPT_ECDSA_PUBLIC_P521_MAGIC

	// ncrypt.h constants
	ncryptPersistFlag           = 0x80000000 // NCRYPT_PERSIST_FLAG
	ncryptAllowDecryptFlag      = 0x1        // NCRYPT_ALLOW_DECRYPT_FLAG
	ncryptAllowSigningFlag      = 0x2        // NCRYPT_ALLOW_SIGNING_FLAG
	ncryptWriteKeyToLegacyStore = 0x00000200 // NCRYPT_WRITE_KEY_TO_LEGACY_STORE_FLAG

	// NCryptPadOAEPFlag is used with Decrypt to specify whether to use OAEP.
	NCryptPadOAEPFlag = 0x00000004 // NCRYPT_PAD_OAEP_FLAG

	// key creation flags.
	nCryptMachineKey   = 0x20 // NCRYPT_MACHINE_KEY_FLAG
	nCryptOverwriteKey = 0x80 // NCRYPT_OVERWRITE_KEY_FLAG

	// winerror.h constants
	cryptENotFound = 0x80092004 // CRYPT_E_NOT_FOUND

	// ProviderMSPlatform represents the Microsoft Platform Crypto Provider
	ProviderMSPlatform = "Microsoft Platform Crypto Provider"
	// ProviderMSSoftware represents the Microsoft Software Key Storage Provider
	ProviderMSSoftware = "Microsoft Software Key Storage Provider"
	// ProviderMSLegacy represents the CryptoAPI compatible Enhanced Cryptographic Provider
	ProviderMSLegacy = "Microsoft Enhanced Cryptographic Provider v1.0"
)

var (
	// Key blob type constants.
	bCryptRSAPublicBlob = wide("RSAPUBLICBLOB")
	bCryptECCPublicBlob = wide("ECCPUBLICBLOB")

	// Key storage properties
	nCryptAlgorithmGroupProperty = wide("Algorithm Group") // NCRYPT_ALGORITHM_GROUP_PROPERTY
	nCryptUniqueNameProperty     = wide("Unique Name")     // NCRYPT_UNIQUE_NAME_PROPERTY

	// curveIDs maps bcrypt key blob magic numbers to elliptic curves.
	curveIDs = map[uint32]elliptic.Curve{
		ecs1Magic: elliptic.P256(), // BCRYPT_ECDSA_PUBLIC_P256_MAGIC
		ecs3Magic: elliptic.P384(), // BCRYPT_ECDSA_PUBLIC_P384_MAGIC
		ecs5Magic: elliptic.P521(), // BCRYPT_ECDSA_PUBLIC_P521_MAGIC
	}

	// algIDs maps crypto.Hash values to bcrypt.h constants.
	algIDs = map[crypto.Hash]*uint16{
		crypto.SHA1:   wide("SHA1"),   // BCRYPT_SHA1_ALGORITHM
		crypto.SHA256: wide("SHA256"), // BCRYPT_SHA256_ALGORITHM
		crypto.SHA384: wide("SHA384"), // BCRYPT_SHA384_ALGORITHM
		crypto.SHA512: wide("SHA512"), // BCRYPT_SHA512_ALGORITHM
	}

	// MY, CA and ROOT are well-known system stores that holds certificates.
	// The store that is opened (system or user) depends on the system call used.
	// see https://msdn.microsoft.com/en-us/library/windows/desktop/aa376560(v=vs.85).aspx)
	my   = wide("MY")
	ca   = wide("CA")
	root = wide("ROOT")

	crypt32 = windows.MustLoadDLL("crypt32.dll")
	nCrypt  = windows.MustLoadDLL("ncrypt.dll")

	certDeleteCertificateFromStore    = crypt32.MustFindProc("CertDeleteCertificateFromStore")
	certFindCertificateInStore        = crypt32.MustFindProc("CertFindCertificateInStore")
	certGetIntendedKeyUsage           = crypt32.MustFindProc("CertGetIntendedKeyUsage")
	cryptAcquireCertificatePrivateKey = crypt32.MustFindProc("CryptAcquireCertificatePrivateKey")
	cryptFindCertificateKeyProvInfo   = crypt32.MustFindProc("CryptFindCertificateKeyProvInfo")
	nCryptCreatePersistedKey          = nCrypt.MustFindProc("NCryptCreatePersistedKey")
	nCryptDecrypt                     = nCrypt.MustFindProc("NCryptDecrypt")
	nCryptExportKey                   = nCrypt.MustFindProc("NCryptExportKey")
	nCryptFinalizeKey                 = nCrypt.MustFindProc("NCryptFinalizeKey")
	nCryptOpenKey                     = nCrypt.MustFindProc("NCryptOpenKey")
	nCryptOpenStorageProvider         = nCrypt.MustFindProc("NCryptOpenStorageProvider")
	nCryptGetProperty                 = nCrypt.MustFindProc("NCryptGetProperty")
	nCryptSetProperty                 = nCrypt.MustFindProc("NCryptSetProperty")
	nCryptSignHash                    = nCrypt.MustFindProc("NCryptSignHash")
)

// paddingInfo is the BCRYPT_PKCS1_PADDING_INFO struct in bcrypt.h.
type paddingInfo struct {
	pszAlgID *uint16
}

// wide returns a pointer to a a uint16 representing the equivalent
// to a Windows LPCWSTR.
func wide(s string) *uint16 {
	w := utf16.Encode([]rune(s))
	w = append(w, 0)
	return &w[0]
}

func openProvider(provider string) (uintptr, error) {
	var err error
	var hProv uintptr
	pname := wide(provider)
	// Open the provider, the last parameter is not used
	r, _, err := nCryptOpenStorageProvider.Call(uintptr(unsafe.Pointer(&hProv)), uintptr(unsafe.Pointer(pname)), 0)
	if r == 0 {
		return hProv, nil
	}
	return hProv, fmt.Errorf("NCryptOpenStorageProvider returned %X: %v", r, err)
}

// findCert wraps the CertFindCertificateInStore call. Note that any cert context passed
// into prev will be freed. If no certificate was found, nil will be returned.
func findCert(store windows.Handle, enc, findFlags, findType uint32, para *uint16, prev *windows.CertContext) (*windows.CertContext, error) {
	h, _, err := certFindCertificateInStore.Call(
		uintptr(store),
		uintptr(enc),
		uintptr(findFlags),
		uintptr(findType),
		uintptr(unsafe.Pointer(para)),
		uintptr(unsafe.Pointer(prev)),
	)
	if h == 0 {
		// Actual error, or simply not found?
		if errno, ok := err.(syscall.Errno); ok && errno == cryptENotFound {
			return nil, nil
		}
		return nil, err
	}
	return (*windows.CertContext)(unsafe.Pointer(h)), nil
}

// intendedKeyUsage wraps CertGetIntendedKeyUsage. If there are key usage bytes they will be returned,
// otherwise 0 will be returned. The final parameter (2) represents the size in bytes of &usage.
func intendedKeyUsage(enc uint32, cert *windows.CertContext) (usage uint16) {
	certGetIntendedKeyUsage.Call(uintptr(enc), uintptr(unsafe.Pointer(cert.CertInfo)), uintptr(unsafe.Pointer(&usage)), 2)
	return
}

// WinCertStore is a CertStorage implementation for the Windows Certificate Store.
type WinCertStore struct {
	CStore              windows.Handle
	Prov                uintptr
	ProvName            string
	issuers             []string
	intermediateIssuers []string
	container           string
	keyStorageFlags     uintptr
}

// OpenWinCertStore creates a WinCertStore.
func OpenWinCertStore(provider, container string, issuers, intermediateIssuers []string, legacyKey bool) (*WinCertStore, error) {
	// Open a handle to the crypto provider we will use for private key operations
	cngProv, err := openProvider(provider)
	if err != nil {
		return nil, fmt.Errorf("unable to open crypto provider or provider not available: %v", err)
	}

	wcs := &WinCertStore{
		Prov:                cngProv,
		ProvName:            provider,
		issuers:             issuers,
		intermediateIssuers: intermediateIssuers,
		container:           container,
	}

	if legacyKey {
		wcs.keyStorageFlags = ncryptWriteKeyToLegacyStore
		wcs.ProvName = ProviderMSLegacy
	}

	return wcs, nil
}

// Cert returns the current cert associated with this WinCertStore or nil if there isn't one.
func (w *WinCertStore) Cert() (*x509.Certificate, error) {
	c, _, err := w.cert(w.issuers, my, certStoreLocalMachine)
	return c, err
}

// cert is a helper function to lookup certificates based on a known issuer.
// store is used to specify which store to perform the lookup in (system or user).
func (w *WinCertStore) cert(issuers []string, searchRoot *uint16, store uint32) (*x509.Certificate, *windows.CertContext, error) {
	// Open a handle to the system cert store
	certStore, err := windows.CertOpenStore(
		certStoreProvSystem,
		0,
		0,
		store,
		uintptr(unsafe.Pointer(searchRoot)))
	if err != nil {
		return nil, nil, fmt.Errorf("CertOpenStore returned: %v", err)
	}
	defer windows.CertCloseStore(certStore, 0)

	var prev *windows.CertContext
	var cert *x509.Certificate
	for _, issuer := range issuers {
		i, err := windows.UTF16PtrFromString(issuer)
		if err != nil {
			return nil, nil, err
		}

		// pass 0 as the third parameter because it is not used
		// https://msdn.microsoft.com/en-us/library/windows/desktop/aa376064(v=vs.85).aspx
		nc, err := findCert(certStore, encodingX509ASN|encodingPKCS7, 0, findIssuerStr, i, prev)
		if err != nil {
			return nil, nil, fmt.Errorf("finding certificates: %v", err)
		}
		if nc == nil {
			// No certificate found
			continue
		}
		prev = nc
		if (intendedKeyUsage(encodingX509ASN, nc) & signatureKeyUsage) == 0 {
			continue
		}

		// Extract the DER-encoded certificate from the cert context.
		var der []byte
		slice := (*reflect.SliceHeader)(unsafe.Pointer(&der))
		slice.Data = uintptr(unsafe.Pointer(nc.EncodedCert))
		slice.Len = int(nc.Length)
		slice.Cap = int(nc.Length)

		xc, err := x509.ParseCertificate(der)
		if err != nil {
			continue
		}

		cert = xc
		break
	}
	if cert == nil {
		return nil, nil, nil
	}
	return cert, prev, nil
}

// Link will associate the certificate installed in the system store to the user store.
func (w *WinCertStore) Link() error {
	cert, _, err := w.cert(w.issuers, my, certStoreLocalMachine)
	if err != nil {
		return fmt.Errorf("checking for existing machine certificates returned: %v", err)
	}

	if cert == nil {
		return nil
	}

	// If the user cert is already there and matches the system cert, return early.
	userCert, _, err := w.cert(w.issuers, my, certStoreCurrentUser)
	if err != nil {
		return fmt.Errorf("checking for existing user certificates returned: %v", err)
	}
	if userCert != nil {
		if cert.SerialNumber.Cmp(userCert.SerialNumber) == 0 {
			fmt.Fprintf(os.Stdout, "Certificate %s is already linked to the user certificate store.\n", cert.SerialNumber)
			return nil
		}
	}

	// The user context is missing the cert, or it doesn't match, so proceed with the link.
	certContext, err := windows.CertCreateCertificateContext(
		encodingX509ASN|encodingPKCS7,
		&cert.Raw[0],
		uint32(len(cert.Raw)))
	if err != nil {
		return fmt.Errorf("CertCreateCertificateContext returned: %v", err)
	}
	defer windows.CertFreeCertificateContext(certContext)

	// Associate the private key we previously generated
	r, _, err := cryptFindCertificateKeyProvInfo.Call(
		uintptr(unsafe.Pointer(certContext)),
		uintptr(uint32(0)),
		0,
	)
	// Windows calls will fill err with a success message, r is what must be checked instead
	if r == 0 {
		fmt.Printf("found a matching private key for the certificate, but association failed: %v", err)
	}

	// Open a handle to the user cert store
	userStore, err := windows.CertOpenStore(
		certStoreProvSystem,
		0,
		0,
		certStoreCurrentUser,
		uintptr(unsafe.Pointer(my)))
	if err != nil {
		return fmt.Errorf("CertOpenStore for the user store returned: %v", err)
	}
	defer windows.CertCloseStore(userStore, 0)

	// Add the cert context to the users certificate store
	if err := windows.CertAddCertificateContextToStore(userStore, certContext, windows.CERT_STORE_ADD_ALWAYS, nil); err != nil {
		return fmt.Errorf("CertAddCertificateContextToStore returned: %v", err)
	}

	logger.Infof("Successfully linked to existing system certificate with serial %s.", cert.SerialNumber)
	fmt.Fprintf(os.Stdout, "Successfully linked to existing system certificate with serial %s.\n", cert.SerialNumber)

	// Link legacy crypto only if requested.
	if w.ProvName == ProviderMSLegacy {
		return w.linkLegacy()
	}

	return nil
}

// linkLegacy will associate the private key for a system certificate backed by cryptoAPI to
// the copy of the certificate stored in the user store. This makes the key available to legacy
// applications which may require it be specifically present in the users store to be read.
func (w *WinCertStore) linkLegacy() error {
	if w.ProvName != ProviderMSLegacy {
		return fmt.Errorf("cannot link legacy key, Provider mismatch: got %q, want %q", w.ProvName, ProviderMSLegacy)
	}
	logger.Info("Linking legacy key to the user private store.")

	cert, context, err := w.cert(w.issuers, my, certStoreLocalMachine)
	if err != nil {
		return fmt.Errorf("cert lookup returned: %v", err)
	}
	if context == nil {
		return errors.New("cert lookup returned: nil")
	}

	// Lookup the private key for the certificate.
	k, err := w.CertKey(context)
	if err != nil {
		return fmt.Errorf("unable to find legacy private key for %s: %v", cert.SerialNumber, err)
	}
	if k == nil {
		return errors.New("private key lookup returned: nil")
	}
	if k.LegacyContainer == "" {
		return fmt.Errorf("unable to find legacy private key for %s: container was empty", cert.SerialNumber)
	}

	// Generate the path to the expected current user's private key file.
	sid, err := UserSID()
	if err != nil {
		return fmt.Errorf("unable to determine user SID: %v", err)
	}
	_, file := filepath.Split(k.LegacyContainer)
	userContainer := fmt.Sprintf(`%s\Microsoft\Crypto\RSA\%s\%s`, os.Getenv("AppData"), sid, file)

	// Link the private key to the users private key store.
	if err = copyFile(k.LegacyContainer, userContainer); err != nil {
		return err
	}
	logger.Infof("Legacy key %q was located and linked to the user store.", k.LegacyContainer)
	return nil
}

// Remove removes certificates issued by any of w.issuers from the user and/or system cert stores.
// If it is unable to remove any certificates, it returns an error.
func (w *WinCertStore) Remove(removeSystem bool) error {
	for _, issuer := range w.issuers {
		if err := w.remove(issuer, removeSystem); err != nil {
			return err
		}
	}
	return nil
}

// remove removes a certificate issued by w.issuer from the user and/or system cert stores.
func (w *WinCertStore) remove(issuer string, removeSystem bool) error {
	userStore, err := windows.CertOpenStore(
		certStoreProvSystem,
		0,
		0,
		certStoreCurrentUser,
		uintptr(unsafe.Pointer(my)))
	if err != nil {
		return fmt.Errorf("certopenstore for the user store returned: %v", err)
	}
	defer windows.CertCloseStore(userStore, 0)

	userCertContext, err := findCert(
		userStore,
		encodingX509ASN|encodingPKCS7,
		0,
		findIssuerStr,
		wide(issuer),
		nil)
	if err != nil {
		return fmt.Errorf("remove: finding user certificate issued by %s failed: %v", issuer, err)
	}

	if userCertContext != nil {
		if err := removeCert(userCertContext); err != nil {
			return fmt.Errorf("failed to remove user cert: %v", err)
		}
		logger.Info("Cleaned up a user certificate.")
		fmt.Fprintln(os.Stderr, "Cleaned up a user certificate.")
	}

	// if we're only removing the user cert, return early.
	if !removeSystem {
		return nil
	}

	systemStore, err := windows.CertOpenStore(
		certStoreProvSystem,
		0,
		0,
		certStoreLocalMachine,
		uintptr(unsafe.Pointer(my)))
	if err != nil {
		return fmt.Errorf("certopenstore for the system store returned: %v", err)
	}
	defer windows.CertCloseStore(systemStore, 0)

	systemCertContext, err := findCert(
		systemStore,
		encodingX509ASN|encodingPKCS7,
		0,
		findIssuerStr,
		wide(issuer),
		nil)
	if err != nil {
		return fmt.Errorf("remove: finding system certificate issued by %s failed: %v", issuer, err)
	}

	if systemCertContext != nil {
		if err := removeCert(systemCertContext); err != nil {
			return fmt.Errorf("failed to remove system cert: %v", err)
		}
		logger.Info("Cleaned up a system certificate.")
		fmt.Fprintln(os.Stderr, "Cleaned up a system certificate.")
	}

	return nil
}

// removeCert wraps CertDeleteCertificateFromStore. If the call succeeds, nil is returned, otherwise
// the extended error is returned.
func removeCert(certContext *windows.CertContext) error {
	r, _, err := certDeleteCertificateFromStore.Call(uintptr(unsafe.Pointer(certContext)))
	if r != 1 {
		return fmt.Errorf("certdeletecertificatefromstore failed with %X: %v", r, err)
	}
	return nil
}

// Intermediate returns the current intermediate cert associated with this
// WinCertStore or nil if there isn't one.
func (w *WinCertStore) Intermediate() (*x509.Certificate, error) {
	c, _, err := w.cert(w.intermediateIssuers, my, certStoreLocalMachine)
	return c, err
}

// Root returns the certificate issued by the specified issuer from the
// root certificate store 'ROOT/Certificates'.
func (w *WinCertStore) Root(issuer []string) (*x509.Certificate, error) {
	c, _, err := w.cert(issuer, root, certStoreLocalMachine)
	return c, err
}

// Key implements crypto.Signer and crypto.Decrypter for key based operations.
type Key struct {
	handle          uintptr
	pub             crypto.PublicKey
	Container       string
	LegacyContainer string
	AlgorithmGroup  string
}

// Public exports a public key to implement crypto.Signer
func (k *Key) Public() crypto.PublicKey {
	return k.pub
}

// Sign returns the signature of a hash to implement crypto.Signer
func (k *Key) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	hf := opts.HashFunc()
	algID, ok := algIDs[hf]
	if !ok {
		return nil, fmt.Errorf("unsupported hash algorithm %v", hf)
	}

	return sign(k.handle, digest, algID)
}

func sign(kh uintptr, digest []byte, algID *uint16) ([]byte, error) {
	padInfo := paddingInfo{pszAlgID: algID}
	var size uint32
	// Obtain the size of the signature
	r, _, err := nCryptSignHash.Call(
		kh,
		uintptr(unsafe.Pointer(&padInfo)),
		uintptr(unsafe.Pointer(&digest[0])),
		uintptr(len(digest)),
		0,
		0,
		uintptr(unsafe.Pointer(&size)),
		bCryptPadPKCS1)
	if r != 0 {
		return nil, fmt.Errorf("NCryptSignHash returned %X during size check: %v", r, err)
	}

	// Obtain the signature data
	sig := make([]byte, size)
	r, _, err = nCryptSignHash.Call(
		kh,
		uintptr(unsafe.Pointer(&padInfo)),
		uintptr(unsafe.Pointer(&digest[0])),
		uintptr(len(digest)),
		uintptr(unsafe.Pointer(&sig[0])),
		uintptr(size),
		uintptr(unsafe.Pointer(&size)),
		bCryptPadPKCS1)
	if r != 0 {
		return nil, fmt.Errorf("NCryptSignHash returned %X during signing: %v", r, err)
	}

	return sig[:size], nil
}

// DecrypterOpts implements crypto.DecrypterOpts and contains the
// flags required for the NCryptDecrypt system call.
type DecrypterOpts struct {
	// Hashfunc represents the hashing function that was used during
	// encryption and is mapped to the Microsoft equivalent LPCWSTR.
	Hashfunc crypto.Hash
	// Flags represents the dwFlags parameter for NCryptDecrypt
	Flags uint32
}

// oaepPaddingInfo is the BCRYPT_OAEP_PADDING_INFO struct in bcrypt.h.
// https://msdn.microsoft.com/en-us/library/windows/desktop/aa375526(v=vs.85).aspx
type oaepPaddingInfo struct {
	pszAlgID *uint16 // pszAlgId
	pbLabel  *uint16 // pbLabel
	cbLabel  uint32  // cbLabel
}

// Decrypt returns the decrypted contents of the encrypted blob, and implements
// crypto.Decrypter for Key.
func (k *Key) Decrypt(rand io.Reader, blob []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	decrypterOpts, ok := opts.(DecrypterOpts)
	if !ok {
		return nil, errors.New("opts was not certtostore.DecrypterOpts")
	}

	algID, ok := algIDs[decrypterOpts.Hashfunc]
	if !ok {
		return nil, fmt.Errorf("unsupported hash algorithm %v", decrypterOpts.Hashfunc)
	}

	padding := oaepPaddingInfo{
		pszAlgID: algID,
		pbLabel:  wide(""),
		cbLabel:  0,
	}

	return decrypt(k.handle, blob, padding, decrypterOpts.Flags)
}

// decrypt wraps the NCryptDecrypt function and returns the decrypted bytes
// that were previously encrypted by NCryptEncrypt or another compatible
// function such as rsa.EncryptOAEP.
// https://msdn.microsoft.com/en-us/library/windows/desktop/aa376249(v=vs.85).aspx
func decrypt(kh uintptr, blob []byte, padding oaepPaddingInfo, flags uint32) ([]byte, error) {
	var size uint32
	// Obtain the size of the decrypted data
	r, _, err := nCryptDecrypt.Call(
		kh,
		uintptr(unsafe.Pointer(&blob[0])),
		uintptr(len(blob)),
		uintptr(unsafe.Pointer(&padding)),
		0, // Must be null on first run.
		0, // Ignored on first run.
		uintptr(unsafe.Pointer(&size)),
		uintptr(flags))
	if r != 0 {
		return nil, fmt.Errorf("NCryptDecrypt returned %X during size check: %v", r, err)
	}

	// Decrypt the message
	plainText := make([]byte, size)
	r, _, err = nCryptDecrypt.Call(
		kh,
		uintptr(unsafe.Pointer(&blob[0])),
		uintptr(len(blob)),
		uintptr(unsafe.Pointer(&padding)),
		uintptr(unsafe.Pointer(&plainText[0])),
		uintptr(size),
		uintptr(unsafe.Pointer(&size)),
		uintptr(flags))
	if r != 0 {
		return nil, fmt.Errorf("NCryptDecrypt returned %X during decryption: %v", r, err)
	}

	return plainText[:size], nil
}

// SetACL sets the requested permissions on the private key. If a
// cryptoAPI compatible copy of the key is present, the same ACL is set.
func (k *Key) SetACL(access string, sid string, perm string) error {
	if err := setACL(k.Container, access, sid, perm); err != nil {
		return err
	}
	if k.LegacyContainer == "" {
		return nil
	}
	return setACL(k.LegacyContainer, access, sid, perm)
}

// setACL sets permissions for the private key by wrapping the Microsoft
// icacls utility. icacls is used for simplicity working with NTFS ACLs.
func setACL(file, access, sid, perm string) error {
	logger.Infof("running: icacls.exe %s /%s %s:%s", file, access, sid, perm)
	// Parameter validation isn't required, icacls handles this on its own.
	err := exec.Command("icacls.exe", file, "/"+access, sid+":"+perm).Run()
	// Error 1798 can safely be ignored, because it occurs when trying to set an acl
	// for a non-existend sid, which only happens for certain permissions needed on later
	// versions of Windows.
	if err, ok := err.(*exec.ExitError); ok && strings.Contains(err.Error(), "1798") == false {
		logger.Infof("ignoring error while %sing '%s' access to %s for sid: %v", access, perm, file, sid)
		return nil
	} else if err != nil {
		return fmt.Errorf("certstorage.SetFileACL is unable to %s %s access on %s to sid %s, %v", access, perm, file, sid, err)
	}
	return nil
}

// Key opens a handle to an existing private key and returns key.
// Key implements both crypto.Signer and crypto.Decrypter
func (w *WinCertStore) Key() (*Key, error) {
	var kh uintptr
	r, _, err := nCryptOpenKey.Call(
		uintptr(w.Prov),
		uintptr(unsafe.Pointer(&kh)),
		uintptr(unsafe.Pointer(wide(w.container))),
		0,
		nCryptMachineKey)
	if r != 0 {
		return nil, fmt.Errorf("NCryptOpenKey for container %q returned %X: %v", w.container, r, err)
	}

	return keyMetadata(kh, w)
}

// CertKey wraps CryptAcquireCertificatePrivateKey. It obtains the CNG private
// key of a known certificate and returns a pointer to a Key which implements
// both crypto.Signer and crypto.Decrypter.
// https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecertificateprivatekey
func (w *WinCertStore) CertKey(cert *windows.CertContext) (*Key, error) {
	var (
		kh       uintptr
		spec     uint32
		mustFree int
	)
	r, _, err := cryptAcquireCertificatePrivateKey.Call(
		uintptr(unsafe.Pointer(cert)),
		acquireCached|acquireSilent|acquireOnlyNCryptKey,
		0, // Reserved, must be null.
		uintptr(unsafe.Pointer(&kh)),
		uintptr(unsafe.Pointer(&spec)),
		uintptr(unsafe.Pointer(&mustFree)),
	)
	// If the function succeeds, the return value is nonzero (TRUE).
	if r == 0 {
		return nil, fmt.Errorf("cryptAcquireCertificatePrivateKey returned %X: %v", r, err)
	}
	if mustFree != 0 {
		return nil, fmt.Errorf("wrong mustFree [%d != 0]", mustFree)
	}
	if spec != ncryptKeySpec {
		return nil, fmt.Errorf("wrong keySpec [%d != %d]", spec, ncryptKeySpec)
	}

	return keyMetadata(kh, w)
}

// Generate returns a crypto.Signer representing either a TPM-backed or
// software backed key, depending on support from the host OS
// key size is set to the maximum supported by Microsoft Software Key Storage Provider
func (w *WinCertStore) Generate(keySize int) (crypto.Signer, error) {
	logger.Infof("Provider: %s", w.ProvName)
	// The MPCP only supports a max keywidth of 2048, due to the TPM specification.
	// https://www.microsoft.com/en-us/download/details.aspx?id=52487
	// The Microsoft Software Key Storage Provider supports a max keywidth of 16384.
	if keySize > 16384 {
		return nil, fmt.Errorf("unsupported keysize, got: %d, want: < %d", keySize, 16384)
	}

	var kh uintptr
	var length = uint32(keySize)
	// Pass 0 as the fifth parameter because it is not used (legacy)
	// https://msdn.microsoft.com/en-us/library/windows/desktop/aa376247(v=vs.85).aspx
	r, _, err := nCryptCreatePersistedKey.Call(
		uintptr(w.Prov),
		uintptr(unsafe.Pointer(&kh)),
		uintptr(unsafe.Pointer(wide("RSA"))),
		uintptr(unsafe.Pointer(wide(w.container))),
		0,
		nCryptMachineKey|nCryptOverwriteKey)
	if r != 0 {
		return nil, fmt.Errorf("NCryptCreatePersistedKey returned %X: %v", r, err)
	}

	// Microsoft function calls return actionable return codes in r, err is often filled with text, even when successful
	r, _, err = nCryptSetProperty.Call(
		kh,
		uintptr(unsafe.Pointer(wide("Length"))),
		uintptr(unsafe.Pointer(&length)),
		unsafe.Sizeof(length),
		ncryptPersistFlag)
	if r != 0 {
		return nil, fmt.Errorf("NCryptSetProperty (Length) returned %X: %v", r, err)
	}

	var usage uint32
	usage = ncryptAllowDecryptFlag | ncryptAllowSigningFlag
	r, _, err = nCryptSetProperty.Call(
		kh,
		uintptr(unsafe.Pointer(wide("Key Usage"))),
		uintptr(unsafe.Pointer(&usage)),
		unsafe.Sizeof(usage),
		ncryptPersistFlag)
	if r != 0 {
		return nil, fmt.Errorf("NCryptSetProperty (Key Usage) returned %X: %v", r, err)
	}

	// Set the second parameter to 0 because we require no flags
	// https://msdn.microsoft.com/en-us/library/windows/desktop/aa376265(v=vs.85).aspx
	r, _, err = nCryptFinalizeKey.Call(kh, w.keyStorageFlags)
	if r != 0 {
		return nil, fmt.Errorf("NCryptFinalizeKey returned %X: %v", r, err)
	}

	return keyMetadata(kh, w)
}

func keyMetadata(kh uintptr, store *WinCertStore) (*Key, error) {
	// uc is used to populate the unique container name attribute of the private key
	uc, err := getProperty(kh, nCryptUniqueNameProperty)
	if err != nil {
		return nil, fmt.Errorf("unable to determine key unique name: %v", err)
	}

	// Populate key storage locations for software backed keys.
	var lc string
	if store.ProvName != ProviderMSPlatform {
		uc, lc, err = softwareKeyContainers(uc)
		if err != nil {
			return nil, err
		}
	}

	alg, err := getProperty(kh, nCryptAlgorithmGroupProperty)
	if err != nil {
		return nil, fmt.Errorf("unable to determine key algorithm: %v", err)
	}
	var pub crypto.PublicKey
	switch alg {
	case "ECDSA":
		buf, err := export(kh, bCryptECCPublicBlob)
		if err != nil {
			return nil, fmt.Errorf("failed to export ECC public key: %v", err)
		}
		pub, err = unmarshalECC(buf)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal ECC public key: %v", err)
		}
	default:
		buf, err := export(kh, bCryptRSAPublicBlob)
		if err != nil {
			return nil, fmt.Errorf("failed to export %v public key: %v", alg, err)
		}
		pub, err = unmarshalRSA(buf)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal %v public key: %v", alg, err)
		}
	}

	return &Key{handle: kh, pub: pub, Container: uc, LegacyContainer: lc, AlgorithmGroup: alg}, nil
}

func getProperty(kh uintptr, property *uint16) (string, error) {
	var strSize uint32
	r, _, err := nCryptGetProperty.Call(
		kh,
		uintptr(unsafe.Pointer(property)),
		0,
		0,
		uintptr(unsafe.Pointer(&strSize)),
		0,
		0)
	if r != 0 {
		return "", fmt.Errorf("NCryptGetProperty(%v) returned %X during size check: %v", property, r, err)
	}

	buf := make([]byte, strSize)
	r, _, err = nCryptGetProperty.Call(
		kh,
		uintptr(unsafe.Pointer(property)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(strSize),
		uintptr(unsafe.Pointer(&strSize)),
		0,
		0)
	if r != 0 {
		return "", fmt.Errorf("NCryptGetProperty %v returned %X during export: %v", property, r, err)
	}

	uc := strings.Replace(string(buf), string(0x00), "", -1)
	return uc, nil
}

func export(kh uintptr, blobType *uint16) ([]byte, error) {
	var size uint32
	// When obtaining the size of a public key, most parameters are not required
	r, _, err := nCryptExportKey.Call(
		kh,
		0,
		uintptr(unsafe.Pointer(blobType)),
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&size)),
		0)
	if r != 0 {
		return nil, fmt.Errorf("NCryptExportKey returned %X during size check: %v", r, err)
	}

	// Place the exported key in buf now that we know the size required
	buf := make([]byte, size)
	r, _, err = nCryptExportKey.Call(
		kh,
		0,
		uintptr(unsafe.Pointer(blobType)),
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(size),
		uintptr(unsafe.Pointer(&size)),
		0)
	if r != 0 {
		return nil, fmt.Errorf("NCryptExportKey returned %X during export: %v", r, err)
	}
	return buf, nil
}

func unmarshalRSA(buf []byte) (*rsa.PublicKey, error) {
	// BCRYPT_RSA_BLOB from bcrypt.h
	header := struct {
		Magic         uint32
		BitLength     uint32
		PublicExpSize uint32
		ModulusSize   uint32
		UnusedPrime1  uint32
		UnusedPrime2  uint32
	}{}

	r := bytes.NewReader(buf)
	if err := binary.Read(r, binary.LittleEndian, &header); err != nil {
		return nil, err
	}

	if header.Magic != rsa1Magic {
		return nil, fmt.Errorf("invalid header magic %x", header.Magic)
	}

	if header.PublicExpSize > 8 {
		return nil, fmt.Errorf("unsupported public exponent size (%d bits)", header.PublicExpSize*8)
	}

	exp := make([]byte, 8)
	if n, err := r.Read(exp[8-header.PublicExpSize:]); n != int(header.PublicExpSize) || err != nil {
		return nil, fmt.Errorf("failed to read public exponent (%d, %v)", n, err)
	}

	mod := make([]byte, header.ModulusSize)
	if n, err := r.Read(mod); n != int(header.ModulusSize) || err != nil {
		return nil, fmt.Errorf("failed to read modulus (%d, %v)", n, err)
	}

	pub := &rsa.PublicKey{
		N: new(big.Int).SetBytes(mod),
		E: int(binary.BigEndian.Uint64(exp)),
	}
	return pub, nil
}

func unmarshalECC(buf []byte) (*ecdsa.PublicKey, error) {
	// BCRYPT_ECCKEY_BLOB from bcrypt.h
	header := struct {
		Magic uint32
		Key   uint32
	}{}

	r := bytes.NewReader(buf)
	if err := binary.Read(r, binary.LittleEndian, &header); err != nil {
		return nil, err
	}

	curve, ok := curveIDs[header.Magic]
	if !ok {
		return nil, fmt.Errorf("unsupported header magic: %x", header.Magic)
	}

	keyX := make([]byte, header.Key)
	if n, err := r.Read(keyX); n != int(header.Key) || err != nil {
		return nil, fmt.Errorf("failed to read key X (%d, %v)", n, err)
	}

	keyY := make([]byte, header.Key)
	if n, err := r.Read(keyY); n != int(header.Key) || err != nil {
		return nil, fmt.Errorf("failed to read key Y (%d, %v)", n, err)
	}

	pub := &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(keyX),
		Y:     new(big.Int).SetBytes(keyY),
	}
	return pub, nil
}

// Store imports certificates into the Windows certificate store
func (w *WinCertStore) Store(cert *x509.Certificate, intermediate *x509.Certificate) error {
	certContext, err := windows.CertCreateCertificateContext(
		encodingX509ASN|encodingPKCS7,
		&cert.Raw[0],
		uint32(len(cert.Raw)))
	if err != nil {
		return fmt.Errorf("CertCreateCertificateContext returned: %v", err)
	}
	defer windows.CertFreeCertificateContext(certContext)

	// Associate the private key we previously generated
	r, _, err := cryptFindCertificateKeyProvInfo.Call(
		uintptr(unsafe.Pointer(certContext)),
		uintptr(uint32(0)),
		0,
	)
	// Windows calls will fill err with a success message, r is what must be checked instead
	if r == 0 {
		return fmt.Errorf("found a matching private key for this certificate, but association failed: %v", err)
	}

	// Open a handle to the system cert store
	systemStore, err := windows.CertOpenStore(
		certStoreProvSystem,
		0,
		0,
		certStoreLocalMachine,
		uintptr(unsafe.Pointer(my)))
	if err != nil {
		return fmt.Errorf("CertOpenStore for the system store returned: %v", err)
	}
	defer windows.CertCloseStore(systemStore, 0)

	// Add the cert context to the system certificate store
	if err := windows.CertAddCertificateContextToStore(systemStore, certContext, windows.CERT_STORE_ADD_ALWAYS, nil); err != nil {
		return fmt.Errorf("CertAddCertificateContextToStore returned: %v", err)
	}

	// Prep the intermediate cert context
	intContext, err := windows.CertCreateCertificateContext(
		encodingX509ASN|encodingPKCS7,
		&intermediate.Raw[0],
		uint32(len(intermediate.Raw)))
	if err != nil {
		return fmt.Errorf("CertCreateCertificateContext returned: %v", err)
	}
	defer windows.CertFreeCertificateContext(intContext)

	// Open a handle to the intermediate cert store
	caStore, err := windows.CertOpenStore(
		certStoreProvSystem,
		0,
		0,
		certStoreLocalMachine,
		uintptr(unsafe.Pointer(ca)))
	if err != nil {
		return fmt.Errorf("CertOpenStore for the intermediate store returned: %v", err)
	}
	defer windows.CertCloseStore(caStore, 0)

	// Add the intermediate cert context to the store
	if err := windows.CertAddCertificateContextToStore(caStore, intContext, windows.CERT_STORE_ADD_ALWAYS, nil); err != nil {
		return fmt.Errorf("CertAddCertificateContextToStore returned: %v", err)
	}

	return nil
}

// copyFile copies the contents of one file from one location to another
func copyFile(from, to string) error {
	source, err := os.Open(from)
	if err != nil {
		return fmt.Errorf("os.Open(%s) returned: %v", from, err)
	}
	defer source.Close()

	dest, err := os.OpenFile(to, os.O_RDWR|os.O_CREATE, 0666)
	if err != nil {
		return fmt.Errorf("os.OpenFile(%s) returned: %v", to, err)
	}
	defer dest.Close()

	_, err = io.Copy(dest, source)
	if err != nil {
		return fmt.Errorf("io.Copy(%q, %q) returned: %v", to, from, err)
	}

	return nil
}

// softwareKeyContainers returns the file path for a software backed key. If the key
// was finalized with with NCRYPT_WRITE_KEY_TO_LEGACY_STORE_FLAG, it also returns its
// equivalent CryptoAPI key file path. It assumes the key is persisted in the system keystore.
// https://docs.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptfinalizekey.
func softwareKeyContainers(uniqueID string) (string, string, error) {
	var cngRoot = os.Getenv("ProgramData") + `\Microsoft\Crypto\Keys\`
	var capiRoot = os.Getenv("ProgramData") + `\Microsoft\Crypto\RSA\MachineKeys\`

	// Determine the key type, so that we know which container we are
	// working with.
	var keyType, cng, capi string
	if _, err := os.Stat(cngRoot + uniqueID); err == nil {
		keyType = "CNG"
	}
	if _, err := os.Stat(capiRoot + uniqueID); err == nil {
		keyType = "CAPI"
	}

	// Generate the container path for the keyType we already have,
	// and lookup the container path for the keyType we need to infer.
	var err error
	switch keyType {
	case "CNG":
		cng = cngRoot + uniqueID
		capi, err = keyMatch(cng, capiRoot)
		if err != nil {
			return "", "", fmt.Errorf("error locating legacy key: %v", err)
		}
	case "CAPI":
		capi = capiRoot + uniqueID
		cng, err = keyMatch(capi, cngRoot)
		if err != nil {
			return "", "", fmt.Errorf("unable to locate CNG key: %v", err)
		}
		if cng == "" {
			return "", "", errors.New("CNG key was empty")
		}
	default:
		return "", "", fmt.Errorf("unexpected key type %q", keyType)
	}

	return cng, capi, nil
}

// keyMatch takes a known path to a private key and searches for a
// matching key in a provided directory.
func keyMatch(keyPath, dir string) (string, error) {
	key, err := os.Stat(keyPath)
	if err != nil {
		return "", fmt.Errorf("unable to determine key creation date: %v", err)
	}
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		return "", fmt.Errorf("unable to locate search directory: %v", err)
	}
	// A matching key is present in the target directory when it has a modified
	// timestamp within 5 minutes of the known key. Checking the timestamp is
	// necessary to select the right key. Typically, there are several machine
	// keys present, only one of which was created at the same time as the
	// known key.
	for _, f := range files {
		age := int(key.ModTime().Sub(f.ModTime()) / time.Second)
		if age >= -300 && age < 300 {
			return dir + f.Name(), nil
		}
	}
	return "", nil
}
