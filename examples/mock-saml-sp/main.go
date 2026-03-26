package main

import (
	"log"
	"net/http"
)

func main() {
	cfg := loadConfig()
	app := newApp(cfg)

	log.Printf("mock-saml-sp listening on %s", cfg.Addr)
	log.Printf("mock-saml-sp browser URL: %s", cfg.BaseURL)
	log.Printf("mock-saml-sp ACS URL: %s", cfg.ACSURL)
	log.Printf("mock-saml-sp entity ID: %s", cfg.EntityID)
	log.Printf("mock-saml-sp IdP SSO URL: %s", cfg.IDPSSOBrowserURL)

	if err := http.ListenAndServe(cfg.Addr, app.routes()); err != nil {
		log.Fatal(err)
	}
}
