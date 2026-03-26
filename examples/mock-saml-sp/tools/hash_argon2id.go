package main

import (
	"fmt"
	"os"

	authpassword "github.com/miloyuans/openauthing/internal/auth/password"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: go run ./examples/mock-saml-sp/tools/hash_argon2id.go <secret>")
		os.Exit(1)
	}

	encoded, err := authpassword.NewArgon2ID().Hash(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	fmt.Print(encoded)
}
