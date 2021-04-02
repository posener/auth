// The example program shows how to use the googleauth package.
//
// Before usage, credentials needs to be created.
// Go to the https://console.cloud.google.com/apis/credentials page and create a "Service Account"
// and an "OAuth 2.0 Client ID".
// The service account json config should be downloaded and passed with the 'service-account' flag.
// The OAuth 2.0 client ID and secret should be passed using the 'client-id' and 'client-secret'
// flags.
// In the client ID configuration, the "Authorized Javascript origins" should contain
// http://localhost:8080 (or another URL address that this server is running at). And the
// "Authorized redirect URIs" should contain the same address with a "/auth" suffix - according to
// where the `auth.RedirectHandler()` is mounted in this code, and see that
// `googleauth.Config.OAuth2.RedirectURL` is configured accordingly.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"

	"github.com/posener/googleauth"
	"golang.org/x/oauth2"
)

var (
	port           = flag.Int("port", 8080, "Server port")
	serviceAccount = flag.String("service-account", "", "Path to a Google Service account config file.")
	clientID       = flag.String("client-id", "", "Google OAuth 2.0 Client ID.")
	clientSecret   = flag.String("client-secret", "", "Google OAuth 2.0 Client secret.")
	allowed        = flag.String("allowed", "", "Allowed user.")
)

func Example() {
	auth, err := googleauth.New(context.Background(), googleauth.Config{
		ServiceAccountPath: *serviceAccount,
		// Client credentials. As configured in
		// from https://console.cloud.google.com/apis/credentials at the "OAuth 2.0 Client IDs"
		// section.
		OAuth2: oauth2.Config{
			// The redirect URL should be configured in the client config in google cloud console.
			RedirectURL:  fmt.Sprintf("http://localhost:%d/auth", *port),
			ClientID:     *clientID,
			ClientSecret: *clientSecret,
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := googleauth.User(r.Context())
		if *allowed != "" && *allowed != user.Email {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		fmt.Fprintf(w, "Hello, %s", user.Name)
	})

	mux := http.NewServeMux()
	mux.Handle("/", auth.Authenticate(handler))
	mux.Handle("/auth", auth.RedirectHandler())

	http.ListenAndServe(fmt.Sprintf(":%d", *port), mux)
}
