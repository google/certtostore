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
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"math/big"
	"testing"
	"time"

	"github.com/google/certtostore/testdata"
)

// TODO(b/142911419): Create OS specific test packages to cover each
// CertStorage implementation independently.

func generateCertificate(caStore CertStorage, opts GenerateOpts) (CertStorage, error) {
	dir, err := ioutil.TempDir("", "certstorage_cert_test")
	if err != nil {
		return nil, fmt.Errorf("ioutil.Tempdir: %v", err)
	}
	leafStore := NewFileStorage(dir)
	// Create a leaf certificate request.
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("create random name: %v", err)
	}
	cn := hex.EncodeToString(b)
	template := x509.Certificate{
		SerialNumber: new(big.Int).SetBytes(b),
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * time.Minute),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		SignatureAlgorithm:    x509.SHA256WithRSA,
	}
	leafSigner, err := leafStore.Generate(opts)
	if err != nil {
		return nil, fmt.Errorf("leafStore.Generate(%v): %v", opts, err)
	}
	// Sign the leaf cert request with the CA certificate.
	caCrt, err := caStore.Cert()
	if err != nil {
		return nil, fmt.Errorf("caStore.Cert: %v", err)
	}
	if caCrt == nil {
		return nil, fmt.Errorf("could not read CA certificate")
	}
	caKey, err := caStore.Key()
	if err != nil {
		return nil, fmt.Errorf("caStore.Key: %v", err)
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, caCrt, leafSigner.Public(), caKey)
	if err != nil {
		return nil, fmt.Errorf("x509.CreateCertificate: %v", err)
	}
	// Add the new leaf certificate to the leaf store.
	leafCrt, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("x509.ParseCertificate: %v", err)
	}
	if err := leafStore.Store(leafCrt, caCrt); err != nil {
		return nil, fmt.Errorf("leafStore.Store: %v", err)
	}
	return leafStore, nil
}

func TestCredential(t *testing.T) {
	for _, testCase := range []struct {
		name string
		opts GenerateOpts
	}{
		{
			name: "rsa-2048",
			opts: GenerateOpts{
				Algorithm: RSA,
				Size:      2048,
			},
		},
		{
			name: "ecdsa-p256",
			opts: GenerateOpts{
				Algorithm: EC,
				Size:      256,
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			ca := NewFileStorage(testdata.CAPath())
			// Use the CA CertStorage to issue a leaf cert.
			leafStore, err := generateCertificate(ca, testCase.opts)
			if err != nil {
				t.Fatalf("error generating certificate: %v", err)
			}
			// Retrieve the leaf cert.
			leafCrt, err := leafStore.Cert()
			if err != nil {
				t.Fatalf("error retrieving certificate: %v", err)
			}
			// Retrieve a certificate and key for the CA.
			caCrt, err := ca.Cert()
			if err != nil {
				t.Fatalf("error retrieving CA certificate: %v", err)
			}
			caKey, err := ca.Key()
			if err != nil {
				t.Fatalf("error retrieving CA credential: %v", err)
			}
			// Exercise CertificateChain.
			chains, err := leafStore.CertificateChain()
			if err != nil {
				t.Fatalf("error retrieving certificate chain: %v", err)
			}
			for ci, chain := range chains {
				for i, cert := range chain {
					t.Logf("%d.%d: %s", ci, i, cert.Subject)
				}
			}
			if len(chains) != 1 {
				t.Fatalf("%d chains found, expected 1", len(chains))
			}
			if len(chains[0]) < 2 {
				t.Fatalf("%d chain entries found, expected at least 2", len(chains[0]))
			}
			if !leafCrt.Equal(chains[0][0]) {
				t.Errorf("certificate chain[0] is not the leaf")
			}
			if !caCrt.Equal(chains[0][1]) {
				t.Errorf("certificate chain[1] is not the ca")
			}
			// Exercise the CA Public key by verifying the leaf cert.
			caPub := caKey.Public()
			if caPub == nil {
				t.Fatal("CA public key not found")
			}
			rsaPub, ok := caPub.(*rsa.PublicKey)
			if !ok {
				t.Fatal("CA public key is not RSA")
			}
			leafHash := sha256.Sum256(leafCrt.RawTBSCertificate)
			if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, leafHash[:], leafCrt.Signature); err != nil {
				t.Fatalf("error verifying certificate signature: %v", err)
			}
		})
	}
}

func verifySig(pub crypto.PublicKey, sig []byte, digest []byte) error {
	if len(digest) == 0 {
		return fmt.Errorf("digest is empty")
	}
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest, sig)
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(pub, digest, sig) {
			return fmt.Errorf("signature verification failed")
		}
		return nil
	default:
		return fmt.Errorf("unsupported public key type: %T", pub)
	}
}

func TestSign(t *testing.T) {
	testmsg := []byte("test")
	for _, testCase := range []struct {
		name string
		hash crypto.Hash
		opts GenerateOpts
	}{
		{
			name: "rsa-2048",
			hash: crypto.SHA256,
			opts: GenerateOpts{
				Algorithm: RSA,
				Size:      2048,
			},
		},
		{
			name: "ecdsa-p256",
			hash: crypto.SHA256,
			opts: GenerateOpts{
				Algorithm: EC,
				Size:      256,
			},
		},
		{
			name: "ecdsa-p384",
			hash: crypto.SHA384,
			opts: GenerateOpts{
				Algorithm: EC,
				Size:      384,
			},
		},
		{
			name: "ecdsa-p521",
			hash: crypto.SHA512,
			opts: GenerateOpts{
				Algorithm: EC,
				Size:      521,
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			ca := NewFileStorage(testdata.CAPath())
			// Use the CA CertStorage to issue a leaf cert.
			leafStore, err := generateCertificate(ca, testCase.opts)
			if err != nil {
				t.Fatalf("error generating certificate: %v", err)
			}
			k, err := leafStore.Key()
			if err != nil {
				t.Fatalf("error retrieving key: %v", err)
			}

			// Hash the test message using the given hash function.
			h := testCase.hash.New()
			if _, err := h.Write(testmsg); err != nil {
				t.Fatalf("error writing data to hash: %v", err)
			}
			digest := h.Sum(nil)

			sig, err := k.Sign(rand.Reader, digest, testCase.hash)
			if err != nil {
				t.Fatalf("error signing: %v", err)
			}
			if len(sig) == 0 {
				t.Fatalf("signature is empty")
			}

			pub := k.Public()
			if pub == nil {
				t.Fatal("public key is nil")
			}
			err = verifySig(pub, sig, digest[:])
			if err != nil {
				t.Fatalf("error verifying signature: %v", err)
			}
		})
	}
}

func TestDecrypt(t *testing.T) {
	ca := NewFileStorage(testdata.CAPath())
	// Decrypt the test message.
	caKey, err := ca.Key()
	if err != nil {
		t.Fatalf("error retrieving CA credential: %v", err)
	}
	msg, err := base64.StdEncoding.DecodeString(testdata.Ciphertext)
	if err != nil {
		t.Fatalf("error loading ciphertext: %v", err)
	}
	plaintext, err := caKey.Decrypt(rand.Reader, msg, nil)
	if err != nil {
		t.Fatalf("error decrypting ciphertext: %v", err)
	}
	if string(plaintext) != testdata.Plaintext {
		t.Fatalf("plaintext '%v' does not match expected '%v'", string(plaintext), testdata.Plaintext)
	}
}

func TestFileStore(t *testing.T) {
	for _, testCase := range []struct {
		name string
		opts GenerateOpts
	}{
		{
			name: "rsa-2048",
			opts: GenerateOpts{
				Algorithm: RSA,
				Size:      2048,
			},
		},
		{
			name: "ecdsa-p256",
			opts: GenerateOpts{
				Algorithm: EC,
				Size:      256,
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			pem, err := testdata.Certificate()
			if err != nil {
				t.Fatalf("testdata.Certificate: %v", err)
			}
			xc, err := PEMToX509(pem)
			if err != nil {
				t.Fatalf("error decoding test certificate: %v", err)
			}

			dir, err := ioutil.TempDir("", "certstorage_test")
			if err != nil {
				t.Fatalf("failed to create temporary dir: %v", err)
			}
			tc := NewFileStorage(dir)
			cert, err := tc.Cert()
			if err != nil {
				t.Errorf("error while reading empty cert: %v", err)
			}
			if cert != nil {
				t.Errorf("expected cert on new file store to be nil, instead %v", cert)
			}

			cert, err = tc.Intermediate()
			if err != nil {
				t.Errorf("error while reading empty intermediate: %v", err)
			}
			if cert != nil {
				t.Errorf("expected intermediate on new file store to be nil, instead %v", cert)
			}

			signer, err := tc.Generate(testCase.opts)
			if err != nil {
				t.Errorf("failed to generate signer: %v", err)
			}
			_, err = x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, signer)
			if err != nil {
				t.Errorf("failed to create signed CSR with signer from Generate: %v", err)
			}

			if err := tc.Store(xc, xc); err != nil {
				t.Errorf("store failed: %v", err)
			}

			cert, err = tc.Cert()
			if err != nil {
				t.Fatalf("error while reading back written cert: %v", err)
			}
			if !cert.Equal(xc) {
				t.Errorf("expected read-back cert to match xc, instead it's %v", cert)
			}

			cert, err = tc.Intermediate()
			if err != nil {
				t.Fatalf("error while reading back written intermediate: %v", err)
			}
			if !cert.Equal(xc) {
				t.Errorf("expected read-back intermediate to match xc, instead it's %v", cert)
			}
		})
	}
}

func TestPEMToX509(t *testing.T) {
	pem, err := testdata.Certificate()
	if err != nil {
		t.Fatalf("testdata.Certificate: %v", err)
	}
	xc, err := PEMToX509(pem)
	if err != nil {
		t.Fatalf("error decoding test certificate: %v", err)
	}

	const issuer = "Dummy OU"
	xCissuer := xc.Issuer.OrganizationalUnit[0]
	if xCissuer != issuer {
		t.Fatalf("unexpected certificate issuer got:%v, want:%v", xCissuer, issuer)
	}
}

func TestValidateGenerateOpts(t *testing.T) {
	for _, tt := range []struct {
		name    string
		opts    GenerateOpts
		wantErr bool
	}{
		{
			name: "valid-rsa",
			opts: GenerateOpts{Algorithm: RSA, Size: 2048},
		},
		{
			name: "valid-ec",
			opts: GenerateOpts{Algorithm: EC, Size: 256},
		},
		{
			name:    "invalid-rsa-size",
			opts:    GenerateOpts{Algorithm: RSA, Size: 1024},
			wantErr: true,
		},
		{
			name:    "invalid-ec-size",
			opts:    GenerateOpts{Algorithm: EC, Size: 128},
			wantErr: true,
		},
		{
			name:    "unsupported-algorithm",
			opts:    GenerateOpts{Algorithm: "DSA", Size: 2048},
			wantErr: true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateGenerateOpts(tt.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateGenerateOpts(%v) error = %v, wantErr %v", tt.opts, err, tt.wantErr)
			}
		})
	}
}
