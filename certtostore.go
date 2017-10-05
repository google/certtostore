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

// Package certtostore handles storage for certificates
package certtostore

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/certtostore/sysinfo"
)

const (
	createMode = os.FileMode(0600)
)

// CertStorage exposes the different backend storage options for certificates
type CertStorage interface {
	// Cert returns the current X509 certificate or nil if no certificate is installed.
	Cert() (*x509.Certificate, error)
	// Intermediate returns the current intermediate X509 certificate or nil if no certificate is installed.
	Intermediate() (*x509.Certificate, error)
	// Generate generates a new private key in the storage and returns a signer that can be used
	// to perform signatures with the new key and read the public portion of the key. CertStorage
	// implementations should strive to ensure a Generate call doesn't actually destroy any current
	// key or cert material and to only install the new key for clients once Store is called.
	Generate(keySize int) (crypto.Signer, error)
	// Store finishes the cert installation started by the last Generate call with the given cert and
	// intermediate.
	Store(cert *x509.Certificate, intermediate *x509.Certificate) error
}

// FileStorage exposes the file storage (on disk) backend type for certificates.
// The certificate id is used as the base of the filename within the basepath.
type FileStorage struct {
	path string
	key  *rsa.PrivateKey
}

// NewFileStorage sets up a new file storage struct for use by StoreCert
func NewFileStorage(basepath string) *FileStorage {
	return &FileStorage{path: basepath}
}

// Cert returns the FileStorage's current cert or nil if there is none.
func (f *FileStorage) Cert() (*x509.Certificate, error) {
	return certFromDisk(filepath.Join(f.path, "cert.crt"))
}

// Intermediate returns the FileStorage's current intermediate cert or nil if there is none.
func (f *FileStorage) Intermediate() (*x509.Certificate, error) {
	return certFromDisk(filepath.Join(f.path, "cacert.crt"))
}

// Generate creates a new RSA private key and returns a signer that can be used to make a CSR for the key.
func (f *FileStorage) Generate(keySize int) (crypto.Signer, error) {
	var err error
	f.key, err = rsa.GenerateKey(rand.Reader, keySize)
	return f.key, err
}

// Store finishes our cert installation by PEM encoding the cert, intermediate, and key and storing them to disk.
func (f *FileStorage) Store(cert *x509.Certificate, intermediate *x509.Certificate) error {
	// Make sure our directory exists
	if err := os.MkdirAll(filepath.Dir(f.path), createMode|0111); err != nil {
		return err
	}

	// Encode our certs and key
	var certBuf, intermediateBuf, keyBuf bytes.Buffer
	if err := pem.Encode(&certBuf, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
		return fmt.Errorf("could not encode cert to PEM: %v", err)
	}
	if err := pem.Encode(&intermediateBuf, &pem.Block{Type: "CERTIFICATE", Bytes: intermediate.Raw}); err != nil {
		return fmt.Errorf("could not encode intermediate to PEM: %v", err)
	}

	// Write the certificates out to files
	if err := ioutil.WriteFile(filepath.Join(f.path, "cert.crt"), certBuf.Bytes(), createMode); err != nil {
		return err
	}
	if err := ioutil.WriteFile(filepath.Join(f.path, "cacert.crt"), intermediateBuf.Bytes(), createMode); err != nil {
		return err
	}

	// Return early if no private key is available
	if f.key == nil {
		return nil
	}
	// Write our private key out to a file
	if err := pem.Encode(&keyBuf, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(f.key)}); err != nil {
		return fmt.Errorf("could not encode key to PEM: %v", err)
	}
	if err := ioutil.WriteFile(filepath.Join(f.path, "cert.key"), keyBuf.Bytes(), createMode); err != nil {
		return err
	}

	return nil
}

// certFromDisk reads a x509.Certificate from a location on disk and
// validates it as a certificate. If the filename doesn't exist it returns
// (nil, nil) to indicate a non-fatal failure to read the cert.
func certFromDisk(filename string) (*x509.Certificate, error) {
	certPEM, err := ioutil.ReadFile(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	xc, err := PEMToX509(certPEM)
	if err != nil {
		return nil, fmt.Errorf("file %q is not recognized as a certificate", filename)
	}
	return xc, nil
}

// SANCheck checks that the subject alternative name matches the hostname
func SANCheck(c *x509.Certificate) error {
	if len(c.DNSNames) < 1 {
		return fmt.Errorf("certificate does not contain a SAN")
	}

	cs, err := sysinfo.CompInfo()
	if err != nil {
		return fmt.Errorf("could not discover computer information: %v", err)
	}

	lhostname := strings.ToLower(cs.DNSHostName) + "." + strings.ToLower(cs.Domain)
	chostname := c.DNSNames[0]
	if lhostname != chostname {
		return fmt.Errorf("certificate SAN [%q] and Hostname [%q] do not match", chostname, lhostname)
	}
	return nil
}

// PEMToX509 takes a raw PEM certificate and decodes it to an x509.Certificate.
func PEMToX509(b []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("unable to parse PEM certificate")
	}

	xc, err := x509.ParseCertificate(block.Bytes)
	return xc, err
}
