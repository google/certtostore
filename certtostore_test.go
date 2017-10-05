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
	"crypto/rand"
	"crypto/x509"
	"io/ioutil"
	"testing"

	"github.com/google/certtostore/testdata/certtest"
)

func TestFileStore(t *testing.T) {
	xc, err := PEMToX509([]byte(certtest.CertPEM))
	if err != nil {
		t.Fatalf("error decoding test certificate: %v", err)
	}

	var tc CertStorage
	dir, err := ioutil.TempDir("", "certstorage_test")
	if err != nil {
		t.Fatalf("failed to create temporary dir: %v", err)
	}

	tc = NewFileStorage(dir)
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

	signer, err := tc.Generate(2048)
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
}

func TestFileStoreImplementation(t *testing.T) {
	var fs interface{} = NewFileStorage("/tmp")
	if _, ok := fs.(CertStorage); !ok {
		t.Fatal("FileStorage does not implement CertStorage interface")
	}
}

func TestPEMToX509(t *testing.T) {
	xc, err := PEMToX509([]byte(certtest.CertPEM))
	if err != nil {
		t.Fatalf("error decoding test certificate: %v", err)
	}

	const issuer = "Dummy OU"
	xCissuer := xc.Issuer.OrganizationalUnit[0]
	if xCissuer != issuer {
		t.Fatalf("unexpected certificate issuer got:%v, want:%v", xCissuer, issuer)
	}
}
