// Copyright 2016 The Gem Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file.

/*
Package jwtmidware JSON WEB TOKEN authentication for Gem Web framework.

This package requires jwt package: https://github.com/dgrijalva/jwt-go.
*/
package jwtmidware

import (
	"net/http"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-gem/gem"
)

// JWT default configuration.
const (
	formKey    = "_jwt"
	contextKey = "json.web.token"
	claimsKey  = "json.web.token.claims"
)

// New returns a JWT instance via the given
// params and default configuration.
func New(signingMethod jwt.SigningMethod, keyFunc jwt.Keyfunc) *JWT {
	return &JWT{
		SigningMethod: signingMethod,
		KeyFunc:       keyFunc,
		FormKey:       formKey,
		ContextKey:    contextKey,
		ClaimsKey:     claimsKey,
	}
}

// JWT is a HTTP middleware that provides JSON WEB Token
// authentication for Gem web framework.
type JWT struct {
	// See jwt.SigningMethod
	SigningMethod jwt.SigningMethod

	// See jwt.Keyfunc
	KeyFunc jwt.Keyfunc

	// FormKey be used to acquire token from query string
	// or post form.
	FormKey string

	// ContextKey be used to ctx.SetUserValue(ContextKey,jwt.Token)
	ContextKey string

	// NewClaims returns a jwt.Claims instance,
	// And then use jwt.ParseWithClaims to parse token and claims.
	// If it is not set, use jwt.Parse instead.
	NewClaims func() jwt.Claims

	// ClaimsKey be used to ctx.SetUserValue(ClaimsKey, jwt.Claims)
	ClaimsKey string
}

// Wrap implements Middleware's interface.
func (m *JWT) Wrap(next gem.Handler) gem.Handler {
	return gem.HandlerFunc(func(ctx *gem.Context) {
		var tokenStr string
		// Retrieve jwt token.
		if tokenStr = retrieveToken(ctx, m.FormKey); tokenStr == "" {
			// Returns Bad Request status code if the token is empty.
			ctx.Response.WriteHeader(http.StatusBadRequest)
			return
		}

		var err error
		var token *jwt.Token
		var claims jwt.Claims
		if m.NewClaims == nil {
			token, err = jwt.Parse(tokenStr, m.KeyFunc)
		} else {
			claims = m.NewClaims()
			token, err = jwt.ParseWithClaims(tokenStr, claims, m.KeyFunc)
			if err == nil {
				err = claims.Valid()
			}
		}

		if err != nil {
			ctx.Logger().Debug(err)
			ctx.Response.WriteHeader(http.StatusUnauthorized)
			return
		}

		ctx.SetUserValue(m.ContextKey, token)
		ctx.SetUserValue(m.ClaimsKey, claims)

		next.Handle(ctx)
	})
}

const (
	strAuthorization = "Authorization"
	strBearer        = "Bearer"
	bearerLen        = len(strBearer)
)

// Retrieve jwt token from the request.
func retrieveToken(ctx *gem.Context, key string) string {
	auth := ctx.Request.Header.Get(strAuthorization)
	if len(auth) > bearerLen+1 && auth[:bearerLen] == strBearer {
		return auth[bearerLen+1:]
	}

	ctx.Request.ParseForm()
	return ctx.Request.Form.Get(key)
}
