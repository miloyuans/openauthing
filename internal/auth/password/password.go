package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const Algorithm = "argon2id"

var ErrInvalidHash = errors.New("password:invalid_hash")

type Argon2ID struct {
	Memory      uint32
	Time        uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

func NewArgon2ID() *Argon2ID {
	return &Argon2ID{
		Memory:      64 * 1024,
		Time:        3,
		Parallelism: 2,
		SaltLength:  16,
		KeyLength:   32,
	}
}

func (a *Argon2ID) Algorithm() string {
	return Algorithm
}

func (a *Argon2ID) Hash(plain string) (string, error) {
	if strings.TrimSpace(plain) == "" {
		return "", fmt.Errorf("password must not be empty")
	}

	salt := make([]byte, a.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("read random salt: %w", err)
	}

	hash := argon2.IDKey([]byte(plain), salt, a.Time, a.Memory, a.Parallelism, a.KeyLength)
	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		a.Memory,
		a.Time,
		a.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

func (a *Argon2ID) Verify(plain, encoded string) (bool, error) {
	params, salt, expectedHash, err := parseHash(encoded)
	if err != nil {
		return false, err
	}

	actualHash := argon2.IDKey([]byte(plain), salt, params.Time, params.Memory, params.Parallelism, uint32(len(expectedHash)))
	return subtle.ConstantTimeCompare(expectedHash, actualHash) == 1, nil
}

func ValidateEncodedHash(encoded string) error {
	_, _, _, err := parseHash(encoded)
	return err
}

func parseHash(encoded string) (*Argon2ID, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 {
		return nil, nil, nil, ErrInvalidHash
	}

	if parts[1] != Algorithm {
		return nil, nil, nil, ErrInvalidHash
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return nil, nil, nil, ErrInvalidHash
	}

	params := &Argon2ID{}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &params.Memory, &params.Time, &params.Parallelism); err != nil {
		return nil, nil, nil, ErrInvalidHash
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, nil, nil, ErrInvalidHash
	}

	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, nil, nil, ErrInvalidHash
	}

	if len(salt) == 0 || len(hash) == 0 {
		return nil, nil, nil, ErrInvalidHash
	}

	return params, salt, hash, nil
}
