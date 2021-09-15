// ackage auth provides painless OAuth2 authentication for http handlers.
//
// After creating an Auth object, the `RedirectHandler` should be mounted to answer the
// cfg.OAuth2.RedirectURL http calls and the `Authenticate` method can be used to enforce
// authentication on http handlers.
// The `User` function can be used to get the logged in user in an authenticated http handler.
//
// See simple usage example in ./example/main.go.
//
//	a, err := auth.New(ctx, auth.Config{ ... })
// 	if err != nil { /* Handle error */ }
//
// 	mux := http.NewServeMux()
// 	mux.Handle("/", a.Authenticate(handler))  // Authenticate a given handler on '/'.
// 	mux.Handle("/auth", a.RedirectHandler())  // Handle OAuth2 redirect.
// 	log.Fatal(http.ListenAndServe(":8080", mux)) // Serve.
//
// Authentication
//
// Authentication is done by wrapping an `http.Handler` that requires only signed in users
// with the `Authenticate` middleware method.
//
// Authorization
//
// Authorization is allowing only specific users to access an `http.Handler`. For example, allowing
// only john@gmail.com, or anyone that signed in using their @example.com. This can be done by
// inspecting the username using the `auth.User(ctx)` method, inside the authenticated `http.Handler`.
// For example, given a function `authorized` that checks if the signed-in user is authorized:
//
//  func handler(w http.ResponseWriter, r *http.Request) {
//  	creds := auth.User(r.Context())
//  	if !authorized(creds) {
//  		// Handle unauthorized users.
//  		http.Error(w, "User not allowed", http.StatusForbidden)
//  		return
//  	}
//  	// Handle authorized users.
//  }
//
//  // authorized is an example function that checks if a user is authorized.
//  func authorized(creds *auth.Creds) bool { return creds.Email == "john@gmail.com" }
//
// Features
//
// - [x] Automatic redirects to OAuth2 flow (login screen) from authorized handlers when user
// is not authenticated.
//
// - [x] Redirect handler automatic redirects to the path that requested to the authentication. Such
// that if user visited /foo and was sent to the OAuth2 login. After successfull login it
// will return to /foo.
//
// - [x] Auth2 id_token is automatically stored in a Cookie. This allows users not to go through
// the authentication phase on every authenticated page, or on different sessions.
package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/idtoken"
)

const (
	afterKey   = "after"
	cookieName = "login"
)

type contextType string

const credsKey contextType = "creds"

var defaultScopes = []string{
	"https://www.googleapis.com/auth/userinfo.email",
	"https://www.googleapis.com/auth/userinfo.profile",
	"openid",
}

// Config is the Google configuration for the authentication.
type Config struct {
	// Config Oauth2 client credentials.
	//
	// If scope is not set, the defaultScopes are used. The scope should not be set for standard
	// usage.
	// If Endpoint is not set, google.Endpoint is used. It should not be set for standard usage.
	//
	// OAuth2 Providers
	//
	// For Google OAuth2 authentication, the client credentials can be generated using Google cloud
	// console at: https://console.cloud.google.com/apis/credentials.
	oauth2.Config

	// Disable authentication.
	Disable bool

	Log    func(string, ...interface{}) `json:"-"`
	Client *http.Client                 `json:"-"`

	// Unsecure uses unsecured cookies (Required for http scheme).
	Unsecure bool
}

// Auth is an authentication handler.
type Auth struct {
	validator *idtoken.Validator
	cfg       Config
}

// Creds is the credentials of the logged in user.
type Creds struct {
	// Email of user. Can be used to identify the user.
	Email string
	// Name of user. User may change the name, therefore this field should not be used for
	// authentication.
	Name string
}

// New returns an authentication handler.
func New(ctx context.Context, cfg Config) (*Auth, error) {
	if cfg.Disable {
		a := &Auth{cfg: cfg}
		a.logf("Authentication is disabled!")
		return a, nil
	}

	if cfg.Client == nil {
		cfg.Client = http.DefaultClient
	}

	tokenValidator, err := idtoken.NewValidator(ctx, idtoken.WithHTTPClient(cfg.Client))
	if err != nil {
		return nil, err
	}

	// Apply default values.
	if cfg.Endpoint.AuthURL == "" || cfg.Endpoint.TokenURL == "" {
		cfg.Endpoint = google.Endpoint
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = defaultScopes
	}

	return &Auth{validator: tokenValidator, cfg: cfg}, nil
}

// RedirectHandler should be mounted on the cfg.OAuth2.RedirectURL path.
func (a *Auth) RedirectHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		token, err := a.cfg.Exchange(r.Context(), code)
		if err != nil {
			a.logf("Authentication failure for code %s: %s", code, err)
			http.Error(w, "Authorization failure", http.StatusUnauthorized)
			return
		}

		_, ok := token.Extra("id_token").(string)
		if !ok {
			a.logf("Invalid ID token %v (%T)", token.Extra("id_token"), token.Extra("id_token"))
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}

		err = a.setCookie(w, fromOauth2(token))
		if err != nil {
			a.logf("Failed setting cookie: %v", err)
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}

		redirectPath := r.URL.Query().Get("state")
		if redirectPath == "" {
			redirectPath = "/"
		}
		http.Redirect(w, r, redirectPath, http.StatusTemporaryRedirect)
	})
}

// LogoutHandler can be mounted on an http endpoint for logging out. It will redirect to
// the given path after user is navigating to the logout path.
func (a *Auth) LogoutHandler(redirectPath string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.clearCookie(w)
		http.Redirect(w, r, redirectPath, http.StatusTemporaryRedirect)
	})
}

// Authenticate wraps a handler and enforces only authenticated users.
func (a *Auth) Authenticate(handler http.Handler) http.Handler {
	if handler == nil {
		panic("auth: nil handler")
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.cfg.Disable {
			handler.ServeHTTP(w, r)
			return
		}

		token, err := a.getCookie(r)
		if token == nil && err == nil {
			// Cookie is missing, invalid. Fetch new token from OAuth2 provider.
			// Redirect user to the OAuth2 consent page to ask for permission for the scopes specified
			// above.
			// Set the scope to the current request URL, it will be used by the redirect handler to
			// redirect back to the url that requested the authentication.
			url := a.cfg.AuthCodeURL(r.RequestURI)
			http.Redirect(w, r, url, http.StatusTemporaryRedirect)
			return
		}
		if err != nil {
			a.clearCookie(w)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			a.logf("Get cookie error: %v", err)
			return
		}

		// Source token, in case the token needs a renewal.
		newOauth2Token, err := a.cfg.TokenSource(r.Context(), token.toOauth2()).Token()
		if err != nil {
			a.clearCookie(w)
			http.Error(w, "Internal error", http.StatusInternalServerError)
			a.logf("Failed token source: %s", err)
			return
		}
		newToken := fromOauth2(newOauth2Token)

		if newToken.IDToken != token.IDToken {
			a.logf("Refreshed token")
			token = newToken
			a.setCookie(w, token)
		}

		// Validate the id_token.
		payload, err := a.validator.Validate(r.Context(), token.IDToken, a.cfg.ClientID)
		if err != nil {
			a.clearCookie(w)
			http.Error(w, "Invalid auth.", http.StatusUnauthorized)
			a.logf("Invalid token, reset cookie: %s", err)
			return
		}
		// User is authenticated.
		// Store email and name in context, and call the inner handler.
		creds := &Creds{
			Email: payload.Claims["email"].(string),
			Name:  payload.Claims["name"].(string),
		}
		r = r.WithContext(context.WithValue(r.Context(), credsKey, creds))
		handler.ServeHTTP(w, r)
	})
}

func (a *Auth) clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:    cookieName,
		Value:   "",
		Expires: time.Now(),
		Secure:  !a.cfg.Unsecure,
	})
}

func (a *Auth) setCookie(w http.ResponseWriter, token *token) error {
	jsonEncoded, err := json.Marshal(token)
	if err != nil {
		return err
	}
	base64Encoded := base64.StdEncoding.EncodeToString(jsonEncoded)
	http.SetCookie(w, &http.Cookie{
		Name:   cookieName,
		Value:  base64Encoded,
		Secure: !a.cfg.Unsecure,
	})
	return nil
}

func (a *Auth) getCookie(r *http.Request) (*token, error) {
	// Get the token from the cookie.
	cookie, err := r.Cookie(cookieName)
	switch {
	case err == http.ErrNoCookie || cookie.Value == "":
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("failed getting cookie: %v", err)
	}

	decoded, err := base64.URLEncoding.DecodeString(cookie.Value)
	if err != nil {
		return nil, fmt.Errorf("failed base64 decoding cookie: %s", err)
	}
	t := &token{}
	err = json.Unmarshal(decoded, t)
	if err != nil {
		return nil, fmt.Errorf("failed json decoding cookie: %s", err)
	}
	return t, nil
}

func (a *Auth) logf(format string, args ...interface{}) {
	if a.cfg.Log == nil {
		return
	}

	a.cfg.Log(format, args...)
}

// User returns the credentials of the logged in user. It returns nil in case that there is no
// user information (This can happen when the http handler is not authenticated).
// It should be used inside an `http.Handler` that was authenticated using
// `Auth.Authenticate(handler)` and receive the request context, as follows:
//
// 	func handler(w http.ResponseWriter, r *http.Request) {
//		creds := auth.User(r.Context())
//  	if !authorized(creds) {
// 			// Handle unauthorized users.
// 			http.Error(w, "User not allowed", http.StatusForbidden)
// 			return
// 		}
// 		// Handle authorized users.
//  }
func User(ctx context.Context) *Creds {
	v := ctx.Value(credsKey)
	if v == nil {
		return nil
	}
	return v.(*Creds)
}

type token struct {
	*oauth2.Token
	// Extras:
	IDToken string `json:"id_token"`
}

func fromOauth2(t *oauth2.Token) *token {
	return &token{
		Token:   t,
		IDToken: t.Extra("id_token").(string),
	}
}

func (t *token) toOauth2() *oauth2.Token {
	return t.Token.WithExtra(map[string]interface{}{"id_token": t.IDToken})
}
