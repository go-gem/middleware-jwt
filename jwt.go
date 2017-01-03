// Copyright 2016 The Gem Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file.

/*
Package jwtmidware JSON WEB TOKEN authentication for Gem Web framework.

This package requires jwt package: https://github.com/dgrijalva/jwt-go.

Example

	package main

	import (
		"html/template"
		"net/http"
		"sync"

		"github.com/dgrijalva/jwt-go"
		"github.com/go-gem/gem"
		"github.com/go-gem/middleware-jwt"
	)

	var form = `
	    <html>
	    <head>
	    <title>JSON WEB TOKEN</title>
	    </head>
	    <body>
	    <p><a href="/posts" target="_blank">POSTS LIST</a></p>

	    <form id="signinForm" onsubmit="return false;" method="POST" action="/signin" accept-charset="UTF-8">
	    <input type="text" name="username" id="username">
	    <input type="button" value="Sign in!" onclick="signin(this);">
	    </form>

	    <form id="postForm" onsubmit="return false;" method="POST" action="/posts" accept-charset="UTF-8" style="display:none;">
	    <input type="hidden" value="" id="{{.jwtFormKey}}" name="{{.jwtFormKey}}">
	    <input type="text" name="title" id="title" name="title">
	    <input type="button" value="Create Post!" onclick="createPost(this)">
	    </form>
	    <script type="text/javascript">
		var signinForm = document.getElementById("signinForm");
		var postForm = document.getElementById("postForm");
		var username = document.getElementById("username");
		var jwt = document.getElementById("{{.jwtFormKey}}");
		var title = document.getElementById("title");

		function signin(obj) {
			var xhr = new XMLHttpRequest();
			xhr.open("POST", "/signin", true);
			xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
			xhr.onreadystatechange = function () {
				if (xhr.readyState == 4 && xhr.status == 200) {
					var res = xhr.responseText;
					try{
						var json = eval('(' + res + ')');
						jwt.value = json.data.token;
						signinForm.style.display = 'none';
						postForm.style.display = 'block';
					} catch(err) {
						alert(err);
					} finally {

					}
					return;
				}
			};

			xhr.send("name=" + username.value);
		}

		function createPost(obj) {
			var xhr = new XMLHttpRequest();
			xhr.open("POST", "/posts", true);
			xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
			xhr.onreadystatechange = function () {
				if (xhr.readyState == 4 && xhr.status == 200) {
					var res = xhr.responseText;
					try{
						var json = eval('(' + res + ')');
						title.value = "";
						alert(json.msg);
					} catch(err) {
						alert(err);
					} finally {

					}
					return;
				}
			};

			xhr.send("title=" + title.value + '&_jwt=' + jwt.value);
		}

		console.log("signinForm");
	    </script>
	    </body>
	    </html>
	    `

	var (
		t = template.Must(template.New("index.tmpl").Parse(form))

		signMethod = jwt.SigningMethodHS256
		signKey    = []byte("secret-key")
		keyFunc    = func(token *jwt.Token) (interface{}, error) {
			return signKey, nil
		}

		// initial jwt middleware
		jwtMidware = jwtmidware.New(signMethod, keyFunc)
	)

	func main() {
		jwtMidware.NewClaims = func() jwt.Claims {
			return &userClaims{}
		}

		router := gem.NewRouter()
		router.GET("/", index)
		router.POST("/signin", signin)

		// posts handlers.
		router.GET("/posts", postsList)
		router.POST("/posts", postsAdd, &gem.HandlerOption{
			Middlewares: []gem.Middleware{jwtMidware},
		})

		gem.ListenAndServe(":8080", router.Handler())
	}

	func index(ctx *gem.Context) {
		t.ExecuteTemplate(ctx, "index.tmpl", map[string]interface{}{
			"jwtFormKey": jwtMidware.FormKey,
		})
	}

	var tokens []string

	type userClaims struct {
		jwt.StandardClaims
		Name string `json:"name"`
	}

	// signin handler for distributing jwt token.
	func signin(ctx *gem.Context) {
		name := ctx.Request.PostFormValue("name")
		claims := &userClaims{Name: name}

		token := jwt.NewWithClaims(signMethod, claims)
		encodedToken, err := token.SignedString(signKey)

		if err != nil {
			ctx.JSON(http.StatusInternalServerError, newResponse(-1, http.StatusText(http.StatusInternalServerError), nil))
			return
		}

		ctx.JSON(http.StatusOK, newResponse(0, "success", map[string]interface{}{
			"token": encodedToken,
		}))
	}

	type post struct {
		Title  string `json:"title"`
		Author string `json:"author"`
	}

	var (
		mutex = sync.Mutex{}
		posts = []post{
			post{Title: "first post", Author: "anonymity"},
		}
	)

	func postsAdd(ctx *gem.Context) {
		claims, ok := ctx.UserValue(jwtMidware.ClaimsKey).(*userClaims)
		if !ok || claims.Name == "" {
			ctx.JSON(http.StatusUnauthorized, newResponse(-1, http.StatusText(http.StatusUnauthorized), nil))
			return
		}

		mutex.Lock()
		defer mutex.Unlock()
		posts = append(posts, post{
			Title:  ctx.Request.PostFormValue("title"),
			Author: claims.Name,
		})

		ctx.JSON(200, newResponse(0, "success", nil))
	}

	func postsList(ctx *gem.Context) {
		ctx.JSON(200, newResponse(0, "success", map[string]interface{}{"posts": posts}))
	}

	type jsonResponse struct {
		Code int                    `json:"code"`
		Msg  string                 `json:"msg"`
		Data map[string]interface{} `json:"data"`
	}

	func newResponse(code int, msg string, data map[string]interface{}) jsonResponse {
		return jsonResponse{
			Code: code,
			Msg:  msg,
			Data: data,
		}
	}
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
