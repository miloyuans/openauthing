package password

import "testing"

func TestArgon2IDHashAndVerify(t *testing.T) {
	manager := NewArgon2ID()

	hash, err := manager.Hash("secret123")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	ok, err := manager.Verify("secret123", hash)
	if err != nil {
		t.Fatalf("verify password: %v", err)
	}
	if !ok {
		t.Fatal("expected password verification to succeed")
	}

	ok, err = manager.Verify("wrong-password", hash)
	if err != nil {
		t.Fatalf("verify wrong password: %v", err)
	}
	if ok {
		t.Fatal("expected wrong password verification to fail")
	}
}

func TestArgon2IDVerifyRejectsMalformedHash(t *testing.T) {
	manager := NewArgon2ID()

	ok, err := manager.Verify("secret123", "not-a-valid-hash")
	if err == nil {
		t.Fatal("expected malformed hash error")
	}
	if ok {
		t.Fatal("expected malformed hash verification to fail")
	}
}
