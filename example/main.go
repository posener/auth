// The example program shows how to use the googleauth package.
//
// Before usage, credentials needs to be created.
// Go to the https://console.cloud.google.com/apis/credentials page and create an "OAuth 2.0 Client
// ID". The OAuth 2.0 client ID and secret should be passed using the 'client-id' and
// 'client-secret' flags.
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
	port         = flag.Int("port", 8080, "Server port")
	clientID     = flag.String("client-id", "", "Google OAuth 2.0 Client ID.")
	clientSecret = flag.String("client-secret", "", "Google OAuth 2.0 Client secret.")
	authorized   = flag.String("authorized", "", "Authorized user.")
)

func main() {
	flag.Parse()

	// Create auth object.
	auth, err := googleauth.New(context.Background(), googleauth.Config{
		// Client credentials. As configured in
		// from https://console.cloud.google.com/apis/credentials at the "OAuth 2.0 Client IDs"
		// section.
		OAuth2: oauth2.Config{
			// The redirect URL should be configured in the client config in google cloud console.
			RedirectURL:  fmt.Sprintf("http://localhost:%d/auth", *port),
			ClientID:     *clientID,
			ClientSecret: *clientSecret,
		},
		Log: log.Printf,
	})
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.Handle("/", auth.Authenticate(http.HandlerFunc(handler)))
	mux.Handle("/auth", auth.RedirectHandler())

	err = http.ListenAndServe(fmt.Sprintf(":%d", *port), mux)
	if err != nil {
		log.Fatal(err)
	}
}

// handler is an example for http handler that is protected using Google authorization.
func handler(w http.ResponseWriter, r *http.Request) {
	// Get the authenticated user from the request context.
	user := googleauth.User(r.Context())

	if user == nil {
		// No user is logged in. This can only happen when the handler is not wrapped with
		// `auth.Authorize`.
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}

	// The authenticated user can be authorized according to the email, which identifies the
	// account.
	if *authorized != "" && *authorized != user.Email {
		// The logged in user is not allowed for this page.
		http.Error(w, fmt.Sprintf("User %s not allowed", user.Email), http.StatusForbidden)
		return
	}

	// User is allowed, greet them.
	fmt.Fprintf(w, "Hello, %s", user.Name)
}
