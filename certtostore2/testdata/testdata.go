/*
Copyright 2016 Google Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package testdata provides certificate-related data for tests.
package testdata

import (
	"io/ioutil"
	"path"
)

const (
	// Plaintext for Ciphertext.
	Plaintext = "All is discovered, flee at once!\n"
	// Ciphertext is a test sentence encrypted with the CA public key.
	// Generated with:
	// openssl x509 -in testdata/testdata.go -inform pem -pubkey -noout > /tmp/pubkey
	// echo 'All is discovered, flee at once!' |\
	//     openssl pkeyutl -inkey /tmp/pubkey -pubin -encrypt | base64 > /tmp/out
	Ciphertext = `
Oe9eCeqdmcF8skR8iajcBC/OfigMU9W+gGdQqMJPvhqFX95QnIzt9O+Vg5Xfi4IcAXllJpFLj4uY
KFPmZF7gqWLkVzOXA60TjZXrxrWd+M+fCZ/yP1696iYg9eaCPxvTyXQ08EYl5D931Lxrsvr0UF1L
lllelQBg+cjr4V4MT94j3pgisSnv7ThrOq6KBL4h9Gjr6cCib9f3vSYgw7mGRLjB/E5T37pZlnqb
tGAfpvKGpknmhsfxpd6kE59JTiDjdQNkttIgCjTOiF+FB7imJZLMJxJ9OjUirH9au7O5nX71NIc9
sYpt+z4CenWduPWPz54lJCeS9+rKejqAr9Rtxg==`
	// testDataPath where certificate and key files can be found.
	testDataPath = "testdata"
)

// CAPath returns a path to a directory containing a cert/key suitable for FileStorage.
func CAPath() string {
	return path.Join(testDataPath, "ca")
}

// Certificate returns a PEM encoded leaf certificate.
func Certificate() ([]byte, error) {
	return ioutil.ReadFile(path.Join(testDataPath, "test_cert.pem"))
}
