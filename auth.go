// Package googleauth provides painless Google authentication for http handlers.
//
// After creating an Auth object, the `RedirectHandler` should be mounted to answer the
// cfg.OAuth2.RedirectURL http calls and the `Authenticate` method can be used to enforce
// authentication on http handlers.
// The `User` function can be used to get the logged in user in an authenticated http handler.
//
// See simple usage example in ./example/main.go.
//
//	auth, err := googleauth.New(ctx, googleauth.Config{ ... })
// 	if err != nil { /* Handle error */ }
//
// 	mux := http.NewServeMux()
// 	mux.Handle("/", auth.Authenticate(handler))  // Authenticate a given handler on '/'.
// 	mux.Handle("/auth", auth.RedirectHandler())  // Handle OAuth2 redirect.
// 	log.Fatal(http.ListenAndServe(":8080", mux)) // Serve.
package googleauth

import (
	"context"
	"net/http"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/idtoken"
)

const (
	tokenKey   = "id_token"
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
	// OAuth2 Google client credentials. Should be generated using google cloud console at:
	//  https://console.cloud.google.com/apis/credentials.
	// If scope is not set, the defaultScopes are used. The scope should not be set for standard
	// usage.
	// If Endpoint is not set, google.Endpoint is used. It should not be set for standard usage.
	OAuth2 oauth2.Config

	// Disable authentication.
	Disable bool

	Log    func(string, ...interface{}) `json:"-"`
	Client *http.Client                 `json:"-"`
}

// Auth is a Google authentication handler.
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

// New returns Google authentication handler.
func New(ctx context.Context, cfg Config) (*Auth, error) {
	if cfg.Disable {
		a := &Auth{cfg: cfg}
		a.logf("Google authentication is disabled!")
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
	if cfg.OAuth2.Endpoint.AuthURL == "" || cfg.OAuth2.Endpoint.TokenURL == "" {
		cfg.OAuth2.Endpoint = google.Endpoint
	}
	if len(cfg.OAuth2.Scopes) == 0 {
		cfg.OAuth2.Scopes = defaultScopes
	}

	return &Auth{validator: tokenValidator, cfg: cfg}, nil
}

// RedirectHandler should be mounted on the cfg.OAuth2.RedirectURL path.
func (a *Auth) RedirectHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		token, err := a.cfg.OAuth2.Exchange(r.Context(), code)
		if err != nil {
			a.logf("Authentication failure for code %s: %s", code, err)
			http.Error(w, "Authorization failure", http.StatusUnauthorized)
			return
		}

		_, ok := token.Extra(tokenKey).(string)
		if !ok {
			a.logf("Invalid ID token %v (%T)", token.Extra(tokenKey), token.Extra(tokenKey))
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:    cookieName,
			Value:   token.Extra(tokenKey).(string),
			Expires: token.Expiry,
			Secure:  true,
		})

		redirectPath := r.URL.Query().Get("state")
		if redirectPath == "" {
			redirectPath = "/"
		}
		http.Redirect(w, r, redirectPath, http.StatusTemporaryRedirect)
	})
}

// Authenticate wraps a handler and enforces only authenticated users.
func (a *Auth) Authenticate(handler http.Handler) http.Handler {
	if handler == nil {
		panic("googleauth: nil handler")
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.cfg.Disable {
			handler.ServeHTTP(w, r)
			return
		}

		idToken := a.idToken(w, r)
		if idToken == "" {
			return
		}
		// Calidate the id_token.
		payload, err := a.validator.Validate(r.Context(), idToken, a.cfg.OAuth2.ClientID)
		if err != nil {
			// Clear cookie, in case it is invalid.
			http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Expires: time.Now()})
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

// idToken returns the id_token. From cookie, or from Google redirect page in case the cookie is
// missing. If the returned string is empty, the appropriate response was already written and the
// caller should halt the http serving.
func (a *Auth) idToken(w http.ResponseWriter, r *http.Request) string {
	cookie, err := r.Cookie(cookieName)
	switch {
	case err == http.ErrNoCookie || cookie.Value == "" || (!cookie.Expires.IsZero() && cookie.Expires.Before(time.Now())):
		// Cookie is missing, invalid or expired. Fetch new token from Google.
		// Redirect user to Google's consent page to ask for permission
		// for the scopes specified above.
		// Set the scope to the current request URL, it will be used by the redirect handler to
		// redirect back to the url that requested the authentication.
		url := a.cfg.OAuth2.AuthCodeURL(r.RequestURI)
		http.Redirect(w, r, url, http.StatusTemporaryRedirect)
		return ""

	case err != nil:
		a.logf("Failed getting cookie: %s", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return ""
	}
	return cookie.Value
}

func (a *Auth) logf(format string, args ...interface{}) {
	if a.cfg.Log == nil {
		return
	}

	a.cfg.Log(format, args...)
}

// User returns the credentials of the logged in user. It returns nil in case that there is no
// user information (This can happen when the http handler is not authenticated).
func User(ctx context.Context) *Creds {
	v := ctx.Value(credsKey)
	if v == nil {
		return nil
	}
	return v.(*Creds)
}
