# auth

[![codecov](https://codecov.io/gh/posener/auth/branch/master/graph/badge.svg)](https://codecov.io/gh/posener/auth)
[![GoDoc](https://img.shields.io/badge/pkg.go.dev-doc-blue)](http://pkg.go.dev/github.com/posener/auth)

ackage auth provides painless OAuth2 authentication for http handlers.

After creating an Auth object, the `RedirectHandler` should be mounted to answer the
cfg.OAuth2.RedirectURL http calls and the `Authenticate` method can be used to enforce
authentication on http handlers.
The `User` function can be used to get the logged in user in an authenticated http handler.

See simple usage example in [./example/main.go](./example/main.go).

```go
a, err := auth.New(ctx, auth.Config{ ... })
if err != nil { /* Handle error */ }

mux := http.NewServeMux()
mux.Handle("/", a.Authenticate(handler))  // Authenticate a given handler on '/'.
mux.Handle("/auth", a.RedirectHandler())  // Handle OAuth2 redirect.
log.Fatal(http.ListenAndServe(":8080", mux)) // Serve.
```

## Authentication

Authentication is done by wrapping an `http.Handler` that requires only signed in users
with the `Authenticate` middleware method.

## Authorization

Authorization is allowing only specific users to access an `http.Handler`. For example, allowing
only john@gmail.com, or anyone that signed in using their @example.com. This can be done by
inspecting the username using the `auth.User(ctx)` method, inside the authenticated `http.Handler`.
For example, given a function `authorized` that checks if the signed-in user is authorized:

```go
func handler(w http.ResponseWriter, r *http.Request) {
	creds := auth.User(r.Context())
	if !authorized(creds) {
		// Handle unauthorized users.
		http.Error(w, "User not allowed", http.StatusForbidden)
		return
	}
	// Handle authorized users.
}

// authorized is an example function that checks if a user is authorized.
func authorized(creds *auth.Creds) bool { return creds.Email == "john@gmail.com" }
```

## Features

- [x] Automatic redirects to OAuth2 flow (login screen) from authorized handlers when user
is not authenticated.

- [x] Redirect handler automatic redirects to the path that requested to the authentication. Such
that if user visited /foo and was sent to the OAuth2 login. After successfull login it
will return to /foo.

- [x] Auth2 id_token is automatically stored in a Cookie. This allows users not to go through
the authentication phase on every authenticated page, or on different sessions.

## Sub Packages

* [example](./example): The example program shows how to use the auth package.

---
Readme created from Go doc with [goreadme](https://github.com/posener/goreadme)
