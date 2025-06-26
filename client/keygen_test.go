package client

import (
	"strings"
	"testing"
)

// Test individual keygen functions without server dependencies

func TestIdentity(t *testing.T) {
	tests := []struct {
		name    string
		uid     string
		did     string
		bid     string
		wantErr bool
	}{
		{
			name:    "basic test",
			uid:     "user123",
			did:     "myapp",
			bid:     "even",
			wantErr: false,
		},
		{
			name:    "email user ID",
			uid:     "alice@example.com",
			did:     "document-app",
			bid:     "odd",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			identity := &Identity{
				UID: tt.uid,
				DID: tt.did,
				BID: tt.bid,
			}

			// Check that all fields are non-empty
			if identity.UID == "" {
				t.Errorf("Identity.UID is empty")
			}
			if identity.DID == "" {
				t.Errorf("Identity.DID is empty")
			}
			if identity.BID == "" {
				t.Errorf("Identity.BID is empty")
			}

			// Test String() method
			str := identity.String()
			if str == "" {
				t.Errorf("Identity.String() returned empty string")
			}
			if !strings.Contains(str, tt.uid) || !strings.Contains(str, tt.did) || !strings.Contains(str, tt.bid) {
				t.Errorf("Identity.String() = %v, should contain UID, DID, and BID", str)
			}
		})
	}
}

func TestPasswordToPin(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantLen  int
	}{
		{
			name:     "simple password",
			password: "test123",
			wantLen:  2, // First 2 bytes of SHA256 hash
		},
		{
			name:     "empty password",
			password: "",
			wantLen:  2,
		},
		{
			name:     "unicode password",
			password: "пароль123",
			wantLen:  2,
		},
		{
			name:     "long password",
			password: "this is a very long password with many characters",
			wantLen:  2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pin := PasswordToPin(tt.password)
			if len(pin) != tt.wantLen {
				t.Errorf("PasswordToPin() length = %d, want %d", len(pin), tt.wantLen)
			}

			// Test consistency - same password should produce same PIN
			pin2 := PasswordToPin(tt.password)
			if string(pin) != string(pin2) {
				t.Errorf("PasswordToPin() not deterministic")
			}
		})
	}
}

func TestGenerateAuthCodes(t *testing.T) {
	tests := []struct {
		name       string
		serverURLs []string
		wantCount  int
	}{
		{
			name:       "single server",
			serverURLs: []string{"https://server1.com"},
			wantCount:  1,
		},
		{
			name:       "multiple servers",
			serverURLs: []string{"https://server1.com", "https://server2.com", "https://server3.com"},
			wantCount:  3,
		},
		{
			name:       "empty servers",
			serverURLs: []string{},
			wantCount:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authCodes := GenerateAuthCodes(tt.serverURLs)

			if authCodes == nil {
				t.Errorf("GenerateAuthCodes() returned nil")
				return
			}

			if len(authCodes.ServerAuthCodes) != tt.wantCount {
				t.Errorf("GenerateAuthCodes() server auth codes count = %d, want %d",
					len(authCodes.ServerAuthCodes), tt.wantCount)
			}

			if authCodes.BaseAuthCode == "" && tt.wantCount > 0 {
				t.Errorf("GenerateAuthCodes() base auth code is empty")
			}

			// Test that each server has an auth code
			for _, url := range tt.serverURLs {
				if _, exists := authCodes.ServerAuthCodes[url]; !exists {
					t.Errorf("GenerateAuthCodes() missing auth code for server %s", url)
				}
			}
		})
	}
}

func TestGenerateEncryptionKeyInputValidation(t *testing.T) {
	tests := []struct {
		name       string
		identity   *Identity
		password   string
		maxGuesses int
		expiration int
		serverURLs []string
		wantError  bool
	}{
		{
			name:       "nil identity",
			identity:   nil,
			password:   "test",
			maxGuesses: 10,
			expiration: 0,
			serverURLs: []string{"http://server1.com"},
			wantError:  true,
		},
		{
			name:       "empty UID",
			identity:   &Identity{UID: "", DID: "app", BID: "even"},
			password:   "test",
			maxGuesses: 10,
			expiration: 0,
			serverURLs: []string{"http://server1.com"},
			wantError:  true,
		},
		{
			name:       "empty DID",
			identity:   &Identity{UID: "user", DID: "", BID: "even"},
			password:   "test",
			maxGuesses: 10,
			expiration: 0,
			serverURLs: []string{"http://server1.com"},
			wantError:  true,
		},
		{
			name:       "empty BID",
			identity:   &Identity{UID: "user", DID: "app", BID: ""},
			password:   "test",
			maxGuesses: 10,
			expiration: 0,
			serverURLs: []string{"http://server1.com"},
			wantError:  true,
		},
		{
			name:       "negative max guesses",
			identity:   &Identity{UID: "user", DID: "app", BID: "even"},
			password:   "test",
			maxGuesses: -1,
			expiration: 0,
			serverURLs: []string{"http://server1.com"},
			wantError:  true,
		},
		{
			name:       "no servers",
			identity:   &Identity{UID: "user", DID: "app", BID: "even"},
			password:   "test",
			maxGuesses: 10,
			expiration: 0,
			serverURLs: []string{},
			wantError:  true,
		},
		{
			name:       "valid inputs (will fail at server connection)",
			identity:   &Identity{UID: "user", DID: "app", BID: "even"},
			password:   "test",
			maxGuesses: 10,
			expiration: 0,
			serverURLs: []string{"http://localhost:9999"}, // non-existent server
			wantError:  true,                              // Should fail at connectivity test
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GenerateEncryptionKey(tt.identity, tt.password,
				tt.maxGuesses, tt.expiration, ConvertURLsToServerInfo(tt.serverURLs))

			if tt.wantError && result.Error == "" {
				t.Errorf("GenerateEncryptionKey() expected error but got none")
			}
			if !tt.wantError && result.Error != "" {
				t.Errorf("GenerateEncryptionKey() unexpected error: %s", result.Error)
			}
		})
	}
}

func TestRecoverEncryptionKeyInputValidation(t *testing.T) {
	tests := []struct {
		name        string
		identity    *Identity
		password    string
		serverInfos []ServerInfo
		threshold   int
		authCodes   *AuthCodes
		wantError   bool
	}{
		{
			name:        "nil identity",
			identity:    nil,
			password:    "test",
			serverInfos: []ServerInfo{{URL: "http://server1.com"}},
			threshold:   1,
			authCodes:   &AuthCodes{},
			wantError:   true,
		},
		{
			name:        "empty UID",
			identity:    &Identity{UID: "", DID: "app", BID: "even"},
			password:    "test",
			serverInfos: []ServerInfo{{URL: "http://server1.com"}},
			threshold:   1,
			authCodes:   &AuthCodes{},
			wantError:   true,
		},
		{
			name:        "empty DID",
			identity:    &Identity{UID: "user", DID: "", BID: "even"},
			password:    "test",
			serverInfos: []ServerInfo{{URL: "http://server1.com"}},
			threshold:   1,
			authCodes:   &AuthCodes{},
			wantError:   true,
		},
		{
			name:        "empty BID",
			identity:    &Identity{UID: "user", DID: "app", BID: ""},
			password:    "test",
			serverInfos: []ServerInfo{{URL: "http://server1.com"}},
			threshold:   1,
			authCodes:   &AuthCodes{},
			wantError:   true,
		},
		{
			name:        "zero threshold",
			identity:    &Identity{UID: "user", DID: "app", BID: "even"},
			password:    "test",
			serverInfos: []ServerInfo{{URL: "http://server1.com"}},
			threshold:   0,
			authCodes:   &AuthCodes{},
			wantError:   true,
		},
		{
			name:        "negative threshold",
			identity:    &Identity{UID: "user", DID: "app", BID: "even"},
			password:    "test",
			serverInfos: []ServerInfo{{URL: "http://server1.com"}},
			threshold:   -1,
			authCodes:   &AuthCodes{},
			wantError:   true,
		},
		{
			name:        "no servers",
			identity:    &Identity{UID: "user", DID: "app", BID: "even"},
			password:    "test",
			serverInfos: []ServerInfo{},
			threshold:   1,
			authCodes:   &AuthCodes{},
			wantError:   true,
		},
		{
			name:        "nil auth codes",
			identity:    &Identity{UID: "user", DID: "app", BID: "even"},
			password:    "test",
			serverInfos: []ServerInfo{{URL: "http://server1.com"}},
			threshold:   1,
			authCodes:   nil,
			wantError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := RecoverEncryptionKeyWithServerInfo(tt.identity, tt.password,
				tt.serverInfos, tt.threshold, tt.authCodes)

			if tt.wantError && result.Error == "" {
				t.Errorf("RecoverEncryptionKeyWithServerInfo() expected error but got none")
			}
			if !tt.wantError && result.Error != "" {
				t.Errorf("RecoverEncryptionKeyWithServerInfo() unexpected error: %s", result.Error)
			}
		})
	}
}

func TestMaxMin(t *testing.T) {
	tests := []struct {
		name    string
		a, b    int
		wantMax int
		wantMin int
	}{
		{
			name:    "positive numbers",
			a:       5,
			b:       3,
			wantMax: 5,
			wantMin: 3,
		},
		{
			name:    "negative numbers",
			a:       -2,
			b:       -5,
			wantMax: -2,
			wantMin: -5,
		},
		{
			name:    "equal numbers",
			a:       7,
			b:       7,
			wantMax: 7,
			wantMin: 7,
		},
		{
			name:    "zero and positive",
			a:       0,
			b:       10,
			wantMax: 10,
			wantMin: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := max(tt.a, tt.b); got != tt.wantMax {
				t.Errorf("max(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.wantMax)
			}
			if got := min(tt.a, tt.b); got != tt.wantMin {
				t.Errorf("min(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.wantMin)
			}
		})
	}
}

// Integration test that requires real servers - keep as a separate test that can be skipped
func TestKeygenRoundTrip(t *testing.T) {
	// Skip if running in CI or if servers not available
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Test the complete keygen round trip using actual functions
	identity := &Identity{
		UID: "test-user-id-fixed",
		DID: "test-app",
		BID: "even",
	}
	password := "test-password-123"
	maxGuesses := 10
	expiration := 0
	serverURLs := []string{
		"http://localhost:9200",
		"http://localhost:9201",
		"http://localhost:9202",
	}

	// Step 1: Generate encryption key
	t.Log("🔐 Generating encryption key...")
	result := GenerateEncryptionKey(identity, password, maxGuesses, expiration, ConvertURLsToServerInfo(serverURLs))
	if result.Error != "" {
		t.Skipf("Key generation failed (servers not available): %s", result.Error)
	}

	t.Logf("✅ Generated key: %x", result.EncryptionKey[:16])
	t.Logf("✅ Used %d servers with threshold %d", len(result.ServerURLs), result.Threshold)

	// Step 2: Recover encryption key
	t.Log("🔓 Recovering encryption key...")
	serverInfos := ConvertURLsToServerInfo(result.ServerURLs)
	recoveryResult := RecoverEncryptionKeyWithServerInfo(identity, password, serverInfos, result.Threshold, result.AuthCodes)
	if recoveryResult.Error != "" {
		t.Fatalf("Key recovery failed: %s", recoveryResult.Error)
	}

	t.Logf("✅ Recovered key: %x", recoveryResult.EncryptionKey[:16])

	// Step 3: Verify keys match
	if len(result.EncryptionKey) != len(recoveryResult.EncryptionKey) {
		t.Errorf("Key lengths don't match: original=%d, recovered=%d", len(result.EncryptionKey), len(recoveryResult.EncryptionKey))
	}

	for i := 0; i < len(result.EncryptionKey) && i < len(recoveryResult.EncryptionKey); i++ {
		if result.EncryptionKey[i] != recoveryResult.EncryptionKey[i] {
			t.Errorf("Keys don't match at byte %d: original=0x%02x, recovered=0x%02x", i, result.EncryptionKey[i], recoveryResult.EncryptionKey[i])
			t.Errorf("Original key:  %x", result.EncryptionKey)
			t.Errorf("Recovered key: %x", recoveryResult.EncryptionKey)
			return
		}
	}

	t.Log("✅ Keygen round trip test passed - keys match!")
}
