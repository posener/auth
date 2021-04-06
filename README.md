# googleauth

[![codecov](https://codecov.io/gh/posener/googleauth/branch/master/graph/badge.svg)](https://codecov.io/gh/posener/googleauth)
[![GoDoc](https://img.shields.io/badge/pkg.go.dev-doc-blue)](http://pkg.go.dev/github.com/posener/googleauth)

Package googleauth provides painless Google authentication for http handlers.

After creating an Auth object, the `RedirectHandler` should be mounted to answer the
cfg.OAuth2.RedirectURL http calls and the `Authenticate` method can be used to enforce
authentication on http handlers.
The `User` function can be used to get the logged in user in an authenticated http handler.

See simple usage example in [./example/main.go](./example/main.go).

## Sub Packages

* [example](./example): The example program shows how to use the googleauth package.

---
Readme created from Go doc with [goreadme](https://github.com/posener/goreadme)
