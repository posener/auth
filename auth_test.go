package googleauth

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func TestDisable(t *testing.T) {
	t.Parallel()

	a, err := New(context.Background(), Config{Disable: true})
	require.NoError(t, err)
	h := a.Authenticate(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	assert.Equal(t, http.StatusOK, rec.Result().StatusCode)
}

func TestAuthenticate(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.New(rand.NewSource(0)), 1024)
	require.NoError(t, err)
	privateKeyCert := newCert(privateKey, "keyid")

	oauth2Cfg := oauth2.Config{
		ClientID:     "client1",
		ClientSecret: "secret1",
		RedirectURL:  "https://example.com/auth",
		Scopes:       []string{"scope1", "scope2"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://auth.com/auth",
			TokenURL: "https://auth.com/token",
		},
	}

	email := "email@example.com"
	name := "John"

	signedToken := genSignedToken(t, privateKeyCert.KID, privateKey, oauth2Cfg.ClientID, email, name)

	requestPath := "/path"
	responseText := "authenticated!"

	// For redirect requests, this is the expected redirect URL.
	wantRedirectURL := oauth2Cfg.Endpoint.AuthURL +
		fmt.Sprintf("?client_id=%s", oauth2Cfg.ClientID) +
		"&redirect_uri=" + url.QueryEscape(oauth2Cfg.RedirectURL) +
		"&response_type=code" +
		"&scope=scope1+scope2" +
		"&state=" + url.QueryEscape(requestPath)

	tests := []struct {
		name   string
		cookie *http.Cookie
		assert func(*testing.T, *httptest.ResponseRecorder)
	}{
		{
			name: "valid cookie",
			cookie: &http.Cookie{
				Name:  cookieName,
				Value: signedToken,
			},
			assert: func(t *testing.T, rec *httptest.ResponseRecorder) {
				assert.Equal(t, http.StatusOK, rec.Result().StatusCode)
				assert.Equal(t, responseText, rec.Body.String())
			},
		},
		{
			name: "no cookie gets redirect",
			assert: func(t *testing.T, rec *httptest.ResponseRecorder) {
				assert.Equal(t, http.StatusTemporaryRedirect, rec.Result().StatusCode)
				assert.Equal(t, wantRedirectURL, rec.Result().Header.Get("Location"))
			},
		},
		{
			name: "cookie with invalid token is unauthorized",
			cookie: &http.Cookie{
				Name:  cookieName,
				Value: "invalid token",
			},
			assert: func(t *testing.T, rec *httptest.ResponseRecorder) {
				assert.Equal(t, http.StatusUnauthorized, rec.Result().StatusCode)
			},
		},
		{
			name: "empty cookie is redirected",
			cookie: &http.Cookie{
				Name:  cookieName,
				Value: "",
			},
			assert: func(t *testing.T, rec *httptest.ResponseRecorder) {
				assert.Equal(t, http.StatusTemporaryRedirect, rec.Result().StatusCode)
				assert.Equal(t, wantRedirectURL, rec.Result().Header.Get("Location"))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := New(context.Background(), Config{
				OAuth2: oauth2Cfg,
				Log:    t.Logf,
				Client: fakeClient(t, certResp{Keys: []cert{privateKeyCert}}),
			})
			require.NoError(t, err)

			h := a.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, requestPath, r.URL.Path)
				gotCreds := User(r.Context())
				assert.Equal(t, email, gotCreds.Email)
				assert.Equal(t, name, gotCreds.Name)
				w.Write([]byte(responseText))
			}))

			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, requestPath, nil)
			if tt.cookie != nil {
				req.AddCookie(tt.cookie)
			}

			h.ServeHTTP(rec, req)
			tt.assert(t, rec)
		})
	}
}

func TestRedirect(t *testing.T) {
	t.Parallel()

	validCode := "code"
	statePath := "/next"
	token := struct {
		TokenType    string `json:"token_type"`
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
		// Extras:
		IDToken string `json:"id_token"`
	}{
		TokenType:    "bearer",
		AccessToken:  "access",
		RefreshToken: "refresh",
		ExpiresIn:    time.Now().Add(time.Hour).Unix(),
		IDToken:      "id token",
	}

	tests := []struct {
		name   string
		code   string
		assert func(*testing.T, *httptest.ResponseRecorder)
	}{
		{
			name: "valid code",
			code: validCode,
			assert: func(t *testing.T, rec *httptest.ResponseRecorder) {
				assert.Equal(t, http.StatusTemporaryRedirect, rec.Result().StatusCode)
				assert.Equal(t, statePath, rec.Result().Header.Get("Location"))
				require.Equal(t, 1, len(rec.Result().Cookies()))
				gotCookie := rec.Result().Cookies()[0]
				assert.Equal(t, cookieName, gotCookie.Name)
				assert.Equal(t, token.IDToken, gotCookie.Value)
			},
		},
		{
			name: "no code",
			assert: func(t *testing.T, rec *httptest.ResponseRecorder) {
				assert.Equal(t, http.StatusUnauthorized, rec.Result().StatusCode)
			},
		},
		{
			name: "invalid code",
			code: validCode + "not",
			assert: func(t *testing.T, rec *httptest.ResponseRecorder) {
				assert.Equal(t, http.StatusUnauthorized, rec.Result().StatusCode)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create oauth2 server that will be used by the redirect handler to retreive a token.
			oauth2Server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch path := r.URL.Path; path {
				case "/token":
					// Check that the code in the request is the expected code.
					err := r.ParseForm()
					require.NoError(t, err)
					if r.FormValue("code") != validCode {
						// Invalid code. Return non 2xx response.
						w.WriteHeader(http.StatusUnauthorized)
						return
					}

					// In case of valid code, encode the token into the response.
					w.Header().Set("Content-Type", "application/json")
					err = json.NewEncoder(w).Encode(token)
					require.NoError(t, err)
				default:
					t.Fatalf("Unexpected path: %s", path)
				}
			}))
			defer oauth2Server.Close()

			// Create auth2 config, the the test auth2 server.
			oauth2Cfg := oauth2.Config{
				ClientID:     "client1",
				ClientSecret: "secret1",
				Endpoint: oauth2.Endpoint{
					AuthURL:  oauth2Server.URL + "/auth",
					TokenURL: oauth2Server.URL + "/token",
				},
			}

			a, err := New(context.Background(), Config{
				OAuth2: oauth2Cfg,
				Log:    t.Logf,
			})
			require.NoError(t, err)

			// Call the redirect handler with the code and state values.
			v := url.Values{}
			v.Set("code", tt.code)
			v.Set("state", statePath)
			u := url.URL{Path: "/", RawQuery: v.Encode()}
			u.Query().Encode()
			req := httptest.NewRequest(http.MethodGet, u.String(), nil)
			rec := httptest.NewRecorder()

			a.RedirectHandler().ServeHTTP(rec, req)

			tt.assert(t, rec)
		})
	}
}

func genSignedToken(t *testing.T, privateKeyID string, privateKey *rsa.PrivateKey, clientID string, email, name string) string {
	t.Helper()
	userClaims := struct {
		Email string `json:"email"`
		Name  string `json:"name"`
		jwt.StandardClaims
	}{
		Email: email,
		Name:  name,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Local().Add(time.Hour).Unix(),
			Audience:  clientID,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, userClaims)
	token.Header["kid"] = privateKeyID
	signedToken, err := token.SignedString(privateKey)
	require.NoError(t, err)
	return signedToken
}

// certResp is the json structure of the response of Google's cert server, at
// https://www.googleapis.com/oauth2/v3/certs.
type certResp struct {
	Keys []cert `json:"keys"`
}

type cert struct {
	Alg string `json:"alg"`
	KID string `json:"kid"`
	E   string `json:"e"`
	N   string `json:"n"`
}

// newCert creates a cert object of Google's cert server for a given RSA private key and the key ID.
func newCert(key *rsa.PrivateKey, id string) cert {
	return cert{
		Alg: "RSA256",
		KID: id,
		N:   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}
}

// fakeClient returns a client that fakes Google's cert server.
func fakeClient(t *testing.T, resp certResp) *http.Client {
	return &http.Client{Transport: &fakeTransport{t: t, respData: resp}}
}

type fakeTransport struct {
	t        *testing.T
	respData interface{}
}

func (f *fakeTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	switch r.URL.String() {
	case "https://www.googleapis.com/oauth2/v3/certs":
		data := &bytes.Buffer{}
		err := json.NewEncoder(data).Encode(f.respData)
		if err != nil {
			panic(err)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(data)}, nil
	}
	f.t.Fatalf("Unexpected request to %s", r.URL)
	return nil, nil
}
