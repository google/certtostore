// Copyright 2022 Google LLC
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
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestGetPropertyStr(t *testing.T) {
	err1 := errors.New("test error")
	tests := []struct {
		desc    string
		out     []byte
		err     error
		want    string
		wantErr error
	}{
		{"with replacements",
			[]byte{104, 0, 101, 108, 0, 108, 111},
			nil,
			"hello",
			nil,
		},
		{"without replacements",
			[]byte{104, 101, 108, 108, 111},
			nil,
			"hello",
			nil,
		},
		{"error",
			[]byte{104, 0, 101, 108, 0, 108, 111},
			err1,
			"",
			err1,
		},
	}
	for _, tt := range tests {
		fnGetProperty = func(kh uintptr, property *uint16) ([]byte, error) {
			return tt.out, tt.err
		}
		out, err := getPropertyStr(0, nil)
		if out != tt.want {
			t.Errorf("%s produced unexpected result: got %s, want %s", tt.desc, out, tt.want)
		}
		if !errors.Is(err, tt.wantErr) {
			t.Errorf("%s produced unexpected error: got %v, want %v", tt.desc, err, tt.wantErr)
		}
	}
}

func TestDefaultWinCertStoreOptions(t *testing.T) {
	provider := ProviderMSSoftware
	container := "TestContainer"
	issuers := []string{"CN=Test CA"}
	intermediateIssuers := []string{"CN=Intermediate CA"}
	legacyKey := true

	opts := DefaultWinCertStoreOptions(provider, container, issuers, intermediateIssuers, legacyKey)

	if opts.Provider != provider {
		t.Errorf("Provider: got %s, want %s", opts.Provider, provider)
	}
	if opts.Container != container {
		t.Errorf("Container: got %s, want %s", opts.Container, container)
	}
	if len(opts.Issuers) != len(issuers) || opts.Issuers[0] != issuers[0] {
		t.Errorf("Issuers: got %v, want %v", opts.Issuers, issuers)
	}
	if len(opts.IntermediateIssuers) != len(intermediateIssuers) || opts.IntermediateIssuers[0] != intermediateIssuers[0] {
		t.Errorf("IntermediateIssuers: got %v, want %v", opts.IntermediateIssuers, intermediateIssuers)
	}
	if opts.LegacyKey != legacyKey {
		t.Errorf("LegacyKey: got %t, want %t", opts.LegacyKey, legacyKey)
	}
	if opts.CurrentUser != false {
		t.Errorf("CurrentUser: got %t, want %t", opts.CurrentUser, false)
	}
	if opts.StoreFlags != 0 {
		t.Errorf("StoreFlags: got %d, want %d", opts.StoreFlags, 0)
	}
}

func TestOpenWinCertStoreWithOptions(t *testing.T) {
	tests := []struct {
		name        string
		opts        WinCertStoreOptions
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid_options_current_user",
			opts: WinCertStoreOptions{
				Provider:            ProviderMSSoftware,
				Container:           "TestContainer",
				Issuers:             []string{"CN=Test CA"},
				IntermediateIssuers: []string{"CN=Intermediate CA"},
				LegacyKey:           false,
				CurrentUser:         true,
				StoreFlags:          0,
			},
			expectError: false,
		},
		{
			name: "valid_options_machine_store",
			opts: WinCertStoreOptions{
				Provider:            ProviderMSSoftware,
				Container:           "TestContainer",
				Issuers:             []string{"CN=Test CA"},
				IntermediateIssuers: []string{"CN=Intermediate CA"},
				LegacyKey:           false,
				CurrentUser:         false,
				StoreFlags:          0,
			},
			expectError: false,
		},
		{
			name: "valid_options_with_readonly_flag",
			opts: WinCertStoreOptions{
				Provider:            ProviderMSSoftware,
				Container:           "TestContainer",
				Issuers:             []string{"CN=Test CA"},
				IntermediateIssuers: []string{"CN=Intermediate CA"},
				LegacyKey:           false,
				CurrentUser:         true,
				StoreFlags:          CertStoreReadOnly,
			},
			expectError: false,
		},
		{
			name: "valid_options_with_multiple_flags",
			opts: WinCertStoreOptions{
				Provider:            ProviderMSSoftware,
				Container:           "TestContainer",
				Issuers:             []string{"CN=Test CA"},
				IntermediateIssuers: []string{"CN=Intermediate CA"},
				LegacyKey:           false,
				CurrentUser:         true,
				StoreFlags:          CertStoreReadOnly | CertStoreSaveToFile,
			},
			expectError: false,
		},
		{
			name: "invalid_provider",
			opts: WinCertStoreOptions{
				Provider:            "NonExistentProvider",
				Container:           "TestContainer",
				Issuers:             []string{"CN=Test CA"},
				IntermediateIssuers: []string{"CN=Intermediate CA"},
				LegacyKey:           false,
				CurrentUser:         true,
				StoreFlags:          0,
			},
			expectError: true,
			errorMsg:    "unable to open crypto provider",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store, err := OpenWinCertStoreWithOptions(tt.opts)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				} else if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error to contain '%s', got: %v", tt.errorMsg, err)
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if store == nil {
				t.Error("Expected non-nil store")
				return
			}

			// Verify the store was configured correctly
			if store.ProvName != tt.opts.Provider {
				t.Errorf("Provider name: got %s, want %s", store.ProvName, tt.opts.Provider)
			}

			if store.container != tt.opts.Container {
				t.Errorf("Container: got %s, want %s", store.container, tt.opts.Container)
			}

			if len(store.issuers) != len(tt.opts.Issuers) {
				t.Errorf("Issuers length: got %d, want %d", len(store.issuers), len(tt.opts.Issuers))
			}

			if len(store.intermediateIssuers) != len(tt.opts.IntermediateIssuers) {
				t.Errorf("IntermediateIssuers length: got %d, want %d", len(store.intermediateIssuers), len(tt.opts.IntermediateIssuers))
			}

			if store.storeFlags != tt.opts.StoreFlags {
				t.Errorf("StoreFlags: got %d, want %d", store.storeFlags, tt.opts.StoreFlags)
			}

			// Test the isReadOnly method
			expectedReadOnly := (tt.opts.StoreFlags & CertStoreReadOnly) != 0
			if store.isReadOnly() != expectedReadOnly {
				t.Errorf("isReadOnly(): got %t, want %t", store.isReadOnly(), expectedReadOnly)
			}

			// Clean up
			if err := store.Close(); err != nil {
				t.Errorf("Error closing store: %v", err)
			}
		})
	}
}

func TestWinCertStore_isReadOnly(t *testing.T) {
	tests := []struct {
		name       string
		storeFlags uint32
		expected   bool
	}{
		{
			name:       "not_readonly",
			storeFlags: 0,
			expected:   false,
		},
		{
			name:       "readonly_only",
			storeFlags: CertStoreReadOnly,
			expected:   true,
		},
		{
			name:       "readonly_with_other_flags",
			storeFlags: CertStoreReadOnly | CertStoreSaveToFile,
			expected:   true,
		},
		{
			name:       "other_flags_without_readonly",
			storeFlags: CertStoreSaveToFile,
			expected:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &WinCertStore{
				storeFlags: tt.storeFlags,
			}

			result := store.isReadOnly()
			if result != tt.expected {
				t.Errorf("isReadOnly(): got %t, want %t", result, tt.expected)
			}
		})
	}
}

func TestWinCertStore_ReadOnlyOperations(t *testing.T) {
	// Create a read-only store for testing
	opts := WinCertStoreOptions{
		Provider:            ProviderMSSoftware,
		Container:           "TestReadOnlyContainer",
		Issuers:             []string{"CN=Test CA"},
		IntermediateIssuers: []string{"CN=Intermediate CA"},
		LegacyKey:           false,
		CurrentUser:         true,
		StoreFlags:          CertStoreReadOnly,
	}

	store, err := OpenWinCertStoreWithOptions(opts)
	if err != nil {
		t.Fatalf("Failed to open read-only store: %v", err)
	}
	defer store.Close()

	// Test that write operations are blocked
	t.Run("Generate_blocked", func(t *testing.T) {
		_, err := store.Generate(GenerateOpts{Algorithm: RSA, Size: 2048})
		if err == nil {
			t.Error("Expected Generate to fail in read-only mode")
		}
		if !strings.Contains(err.Error(), "read-only") {
			t.Errorf("Expected error to mention read-only, got: %v", err)
		}
	})

	t.Run("Store_blocked", func(t *testing.T) {
		// Create a dummy certificate for testing
		cert := &x509.Certificate{}
		err := store.Store(cert, cert)
		if err == nil {
			t.Error("Expected Store to fail in read-only mode")
		}
		if !strings.Contains(err.Error(), "read-only") {
			t.Errorf("Expected error to mention read-only, got: %v", err)
		}
	})

	t.Run("StoreWithDisposition_blocked", func(t *testing.T) {
		// Create a dummy certificate for testing
		cert := &x509.Certificate{}
		err := store.StoreWithDisposition(cert, cert, 1)
		if err == nil {
			t.Error("Expected StoreWithDisposition to fail in read-only mode")
		}
		if !strings.Contains(err.Error(), "read-only") {
			t.Errorf("Expected error to mention read-only, got: %v", err)
		}
	})

	t.Run("Remove_blocked", func(t *testing.T) {
		err := store.Remove(false)
		if err == nil {
			t.Error("Expected Remove to fail in read-only mode")
		}
		if !strings.Contains(err.Error(), "read-only") {
			t.Errorf("Expected error to mention read-only, got: %v", err)
		}
	})

	t.Run("Link_blocked", func(t *testing.T) {
		err := store.Link()
		if err == nil {
			t.Error("Expected Link to fail in read-only mode")
		}
		if !strings.Contains(err.Error(), "read-only") {
			t.Errorf("Expected error to mention read-only, got: %v", err)
		}
	})
}

func TestWinCertStore_StoreDomain(t *testing.T) {
	tests := []struct {
		name        string
		currentUser bool
		storeFlags  uint32
		expected    uint32
	}{
		{
			name:        "machine_store_no_flags",
			currentUser: false,
			storeFlags:  0,
			expected:    certStoreLocalMachine,
		},
		{
			name:        "user_store_no_flags",
			currentUser: true,
			storeFlags:  0,
			expected:    certStoreCurrentUser,
		},
		{
			name:        "machine_store_with_readonly",
			currentUser: false,
			storeFlags:  CertStoreReadOnly,
			expected:    certStoreLocalMachine,
		},
		{
			name:        "user_store_with_multiple_flags",
			currentUser: true,
			storeFlags:  CertStoreReadOnly | CertStoreSaveToFile,
			expected:    certStoreCurrentUser,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &WinCertStore{
				storeFlags: tt.storeFlags,
			}

			// Set the keyAccessFlags based on currentUser
			if !tt.currentUser {
				store.keyAccessFlags = nCryptMachineKey
			}

			result := store.storeDomain()
			if result != tt.expected {
				t.Errorf("storeDomain(): got %d, want %d", result, tt.expected)
			}
		})
	}
}

func TestWinCertStoreOptions_DeepCopy(t *testing.T) {
	// Test that the slices are deep-copied to prevent external modification
	originalIssuers := []string{"CN=Original CA"}
	originalIntermediateIssuers := []string{"CN=Original Intermediate CA"}

	opts := WinCertStoreOptions{
		Provider:            ProviderMSSoftware,
		Container:           "TestContainer",
		Issuers:             originalIssuers,
		IntermediateIssuers: originalIntermediateIssuers,
		LegacyKey:           false,
		CurrentUser:         true,
		StoreFlags:          0,
	}

	store, err := OpenWinCertStoreWithOptions(opts)
	if err != nil {
		t.Fatalf("Failed to open store: %v", err)
	}
	defer store.Close()

	// Modify the original slices
	originalIssuers[0] = "CN=Modified CA"
	originalIntermediateIssuers[0] = "CN=Modified Intermediate CA"

	// Verify that the store's internal slices were not affected
	if store.issuers[0] == "CN=Modified CA" {
		t.Error("Store's issuers slice was not deep-copied")
	}
	if store.intermediateIssuers[0] == "CN=Modified Intermediate CA" {
		t.Error("Store's intermediateIssuers slice was not deep-copied")
	}

	// Verify the correct values are preserved
	if store.issuers[0] != "CN=Original CA" {
		t.Errorf("Expected issuer 'CN=Original CA', got '%s'", store.issuers[0])
	}
	if store.intermediateIssuers[0] != "CN=Original Intermediate CA" {
		t.Errorf("Expected intermediate issuer 'CN=Original Intermediate CA', got '%s'", store.intermediateIssuers[0])
	}
}

func TestWinCertStoreOptions_LegacyKeyConfiguration(t *testing.T) {
	tests := []struct {
		name                 string
		legacyKey            bool
		expectedProvName     string
		expectedStorageFlags uintptr
	}{
		{
			name:                 "legacy_key_enabled",
			legacyKey:            true,
			expectedProvName:     ProviderMSLegacy,
			expectedStorageFlags: ncryptWriteKeyToLegacyStore,
		},
		{
			name:                 "legacy_key_disabled",
			legacyKey:            false,
			expectedProvName:     ProviderMSSoftware,
			expectedStorageFlags: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := WinCertStoreOptions{
				Provider:            ProviderMSSoftware,
				Container:           "TestContainer",
				Issuers:             []string{"CN=Test CA"},
				IntermediateIssuers: []string{"CN=Intermediate CA"},
				LegacyKey:           tt.legacyKey,
				CurrentUser:         true,
				StoreFlags:          0,
			}

			store, err := OpenWinCertStoreWithOptions(opts)
			if err != nil {
				t.Fatalf("Failed to open store: %v", err)
			}
			defer store.Close()

			if store.ProvName != tt.expectedProvName {
				t.Errorf("ProvName: got %s, want %s", store.ProvName, tt.expectedProvName)
			}

			if store.keyStorageFlags != tt.expectedStorageFlags {
				t.Errorf("keyStorageFlags: got %d, want %d", store.keyStorageFlags, tt.expectedStorageFlags)
			}
		})
	}
}

func TestWinCertStoreOptions_KeyAccessFlags(t *testing.T) {
	tests := []struct {
		name                   string
		currentUser            bool
		expectedKeyAccessFlags uintptr
	}{
		{
			name:                   "current_user",
			currentUser:            true,
			expectedKeyAccessFlags: 0, // No machine key flag
		},
		{
			name:                   "machine_store",
			currentUser:            false,
			expectedKeyAccessFlags: nCryptMachineKey,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := WinCertStoreOptions{
				Provider:            ProviderMSSoftware,
				Container:           "TestContainer",
				Issuers:             []string{"CN=Test CA"},
				IntermediateIssuers: []string{"CN=Intermediate CA"},
				LegacyKey:           false,
				CurrentUser:         tt.currentUser,
				StoreFlags:          0,
			}

			store, err := OpenWinCertStoreWithOptions(opts)
			if err != nil {
				t.Fatalf("Failed to open store: %v", err)
			}
			defer store.Close()

			if store.keyAccessFlags != tt.expectedKeyAccessFlags {
				t.Errorf("keyAccessFlags: got %d, want %d", store.keyAccessFlags, tt.expectedKeyAccessFlags)
			}
		})
	}
}

func BenchmarkOpenWinCertStoreWithOptions(b *testing.B) {
	opts := WinCertStoreOptions{
		Provider:            ProviderMSSoftware,
		Container:           "BenchmarkContainer",
		Issuers:             []string{"CN=Benchmark CA"},
		IntermediateIssuers: []string{"CN=Benchmark Intermediate CA"},
		LegacyKey:           false,
		CurrentUser:         true,
		StoreFlags:          0,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		store, err := OpenWinCertStoreWithOptions(opts)
		if err != nil {
			b.Fatalf("Failed to open store: %v", err)
		}
		store.Close()
	}
}

func TestCertByCommonName_NotFound(t *testing.T) {
	// Open a valid store to exercise CertByCommonName.
	opts := WinCertStoreOptions{
		Provider:            ProviderMSSoftware,
		Container:           "TestContainerForCNLookup",
		Issuers:             []string{"CN=Test CA"},
		IntermediateIssuers: []string{"CN=Intermediate CA"},
		LegacyKey:           false,
		CurrentUser:         true,
		StoreFlags:          0,
	}
	store, err := OpenWinCertStoreWithOptions(opts)
	if err != nil {
		t.Fatalf("failed to open store: %v", err)
	}
	defer store.Close()

	// Use a CN that should not exist to trigger the "not found" path.
	const nonexistentCN = "CN=__certtostore_test_common_name_that_should_not_exist__"

	cert, ctx, chains, err := store.CertByCommonName(nonexistentCN)
	if err == nil {
		if ctx != nil {
			FreeCertContext(ctx)
		}
		t.Fatalf("expected error for unknown common name, got none")
	}
	if !strings.Contains(err.Error(), "no certificate found") {
		t.Errorf("unexpected error: %v", err)
	}
	if cert != nil {
		t.Errorf("expected nil certificate, got %#v", cert)
	}
	if ctx != nil {
		FreeCertContext(ctx)
		t.Errorf("expected nil cert context, got non-nil")
	}
	if chains != nil {
		t.Errorf("expected nil chains, got %#v", chains)
	}
}

func TestCertByCommonName(t *testing.T) {
	// Open a valid, writable current-user store.
	opts := WinCertStoreOptions{
		Provider:            ProviderMSSoftware,
		Container:           "TestContainerForCNLookup",
		Issuers:             []string{"CN=Test CA"},
		IntermediateIssuers: []string{"CN=Intermediate CA"},
		LegacyKey:           false,
		CurrentUser:         true,
		StoreFlags:          0,
	}
	store, err := OpenWinCertStoreWithOptions(opts)
	if err != nil {
		t.Fatalf("failed to open store: %v", err)
	}
	defer store.Close()

	// Create a self-signed cert with a unique CN.
	cn := fmt.Sprintf("__certtostore_%d__", time.Now().UnixNano())
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore:             time.Now().Add(-1 * time.Minute),
		NotAfter:              time.Now().Add(5 * time.Minute),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("x509.CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("x509.ParseCertificate: %v", err)
	}

	// Insert the cert directly into the current-user MY store to avoid private key association.
	// Local constants for CertOpenStore.
	const (
		certStoreProvSystem        = 10 // CERT_STORE_PROV_SYSTEM
		certSystemStoreCurrentUser = 1 << 16
		x509ASN                    = 1     // X509_ASN_ENCODING
		pkcs7ASN                   = 65536 // PKCS_7_ASN_ENCODING
	)
	myW, err := windows.UTF16PtrFromString("MY")
	if err != nil {
		t.Fatalf("UTF16PtrFromString: %v", err)
	}
	h, err := windows.CertOpenStore(
		certStoreProvSystem,
		0,
		0,
		certSystemStoreCurrentUser,
		uintptr(unsafe.Pointer(myW)),
	)
	if err != nil {
		t.Fatalf("CertOpenStore: %v", err)
	}
	defer windows.CertCloseStore(h, 0)

	ctx, err := windows.CertCreateCertificateContext(
		x509ASN|pkcs7ASN,
		&cert.Raw[0],
		uint32(len(cert.Raw)),
	)
	if err != nil {
		t.Fatalf("CertCreateCertificateContext: %v", err)
	}
	defer windows.CertFreeCertificateContext(ctx)

	if err := windows.CertAddCertificateContextToStore(h, ctx, windows.CERT_STORE_ADD_ALWAYS, nil); err != nil {
		t.Fatalf("CertAddCertificateContextToStore: %v", err)
	}

	// Query by CN.
	found, foundCtx, chains, err := store.CertByCommonName(cn)
	if err != nil {
		t.Fatalf("CertByCommonName returned error: %v", err)
	}
	if found == nil {
		t.Fatal("expected a certificate, got nil")
	}
	if foundCtx == nil {
		t.Fatal("expected a cert context, got nil")
	}
	// Ensure cleanup: RemoveCertByContext frees foundCtx.
	defer func() {
		if delErr := RemoveCertByContext(foundCtx); delErr != nil {
			t.Fatalf("RemoveCertByContext: %v", delErr)
		}
	}()

	// Validate result.
	if found.Subject.CommonName != cn {
		t.Fatalf("unexpected CommonName: got %q, want %q", found.Subject.CommonName, cn)
	}
	if len(chains) == 0 || len(chains[0]) == 0 {
		t.Fatalf("expected at least one chain with one element, got %+v", chains)
	}
	if !found.Equal(chains[0][0]) {
		t.Errorf("chains[0][0] is not the leaf; got %v, want leaf %v", chains[0][0].Subject, found.Subject)
	}
}
