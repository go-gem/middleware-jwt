// Copyright 2016 The Gem Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file.

package jwtmidware

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/go-gem/gem"
	"net/http"
	"net/http/httptest"
	"testing"
)

var (
	signKey = []byte("foobar")

	jwtMidware = New(jwt.SigningMethodHS256, func(token *jwt.Token) (interface{}, error) {
		return signKey, nil
	})

	token = jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"name": "foo",
	})
)

func TestJWT(t *testing.T) {
	signedStr, err := token.SignedString(signKey)
	if err != nil {
		t.Fatalf("failed to signing the token: %s", err)
	}

	req := httptest.NewRequest("GET", "/", nil)
	resp := httptest.NewRecorder()
	ctx := &gem.Context{Request: req, Response: resp}
	ctx.SetServer(gem.New(""))

	var pass bool
	handler := jwtMidware.Wrap(gem.HandlerFunc(func(ctx *gem.Context) {
		pass = true
	}))

	// send a request without jwt token.
	handler.Handle(ctx)
	if pass {
		t.Error("expected no pass the handler, but passed")
	}

	// send a request with jwt token(header).
	ctx.Request.Header = http.Header{}
	ctx.Request.Header.Set(strAuthorization, fmt.Sprintf("%s %s", strBearer, signedStr))
	handler.Handle(ctx)
	if !pass {
		t.Error("failed to pass the handler")
	}

	// send a request with jwt token(post form).
	pass = false
	ctx.Request.Header = http.Header{}
	ctx.Request.Form.Set(jwtMidware.FormKey, signedStr)
	handler.Handle(ctx)
	if !pass {
		t.Error("failed to pass the handler")
	}

	jwtMidware.NewClaims = func() jwt.Claims {
		return jwt.MapClaims{}
	}

	ctx = &gem.Context{Request: req, Response: resp}
	ctx.SetServer(gem.New(""))
	handler.Handle(ctx)
	if !pass {
		t.Error("failed to pass the handler")
	}
	// check token.
	if v, ok := ctx.UserValue(jwtMidware.ContextKey).(*jwt.Token); !ok {
		t.Error("invalid token")
	} else if v2, ok := v.Claims.(jwt.MapClaims); !ok || v2["name"] == nil {
		t.Error("invalid claims")
	}
	// check claims.
	if v, ok := ctx.UserValue(jwtMidware.ClaimsKey).(jwt.MapClaims); !ok || v["name"] == nil {
		t.Error("invalid claims")
	}

	// send a request with invalid token.
	pass = false
	ctx.Request.Form.Set(jwtMidware.FormKey, "invalidSignedString")
	handler.Handle(ctx)
	if pass {
		t.Error("expected no pass the handler, but passed")
	}
}
