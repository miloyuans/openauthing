package sessionid

import "testing"

func TestGenerateProducesNonEmptyDifferentValues(t *testing.T) {
	first, err := Generate()
	if err != nil {
		t.Fatalf("generate sid: %v", err)
	}
	second, err := Generate()
	if err != nil {
		t.Fatalf("generate second sid: %v", err)
	}

	if first == "" || second == "" {
		t.Fatal("expected non-empty sid values")
	}
	if first == second {
		t.Fatal("expected generated sid values to differ")
	}
}

func TestHashIsDeterministicAndSecretScoped(t *testing.T) {
	hashOne, err := Hash("secret-one", "sid-value")
	if err != nil {
		t.Fatalf("hash sid: %v", err)
	}
	hashTwo, err := Hash("secret-one", "sid-value")
	if err != nil {
		t.Fatalf("hash sid second time: %v", err)
	}
	hashThree, err := Hash("secret-two", "sid-value")
	if err != nil {
		t.Fatalf("hash sid with different secret: %v", err)
	}

	if hashOne != hashTwo {
		t.Fatal("expected deterministic hash output")
	}
	if hashOne == hashThree {
		t.Fatal("expected different secret to produce different hash")
	}
}
