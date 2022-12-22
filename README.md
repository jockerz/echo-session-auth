<p class="center">
  <a href="https://codecov.io/gh/jockerz/echo-session-auth" target="_blank">
    <img src="https://img.shields.io/codecov/c/github/jockerz/echo-session-auth?color=%2334D058" alt="Coverage">
  </a>
  <a href="https://goreportcard.com/report/github.com/jockerz/echo-session-auth" target="_blank">
    <img src="https://goreportcard.com/badge/github.com/jockerz/echo-session-auth" alt="Report">
  </a>
   <a href="https://github.com/jockerz/echo-session-auth/actions">
    <img src='https://github.com/jockerz/echo-session-auth/actions/workflows/go.yml/badge.svg' alt='Test Status'>
  </a>
</p>


# Echo Session Auth

This module help to use session based authentication for your `echo` web application.

Examples: [link](https://github.com/jockerz/echo-session-auth-example)


## Install

Install required modules
```
# Install `echo`
go get github.com/labstack/echo
go get github.com/jockerz/session-auth-echo
```

## Preparation

### 1. Extending `echo.Context`

To have our session based auth works, `User` field is **required**. 


```go
type CustomContext struct {
    echo.Context
    User interface{}
}
```

### 2. User Struct

Create `User` `struct` for later use.

```go
type User struct {
    ID       int
    Username string
    Password string
}
```

### 3. `GetUser` function

The `GetUser(c echo.Context, UserID inteface{}) error` function to get *User* 
instance and passed it to the `User` field on **extended context** *struct*.


>> Note: Main `GetUser` job is to assign the `User` instance to `CustomContext.User` field.


Usage example
```go
// For demo only
var Users = []*User{
    &User{"First", 1},
    &User{"Second", 2},
}

function GetUser(c echo.Context, UserID interface{}) error {
    // required
	ctx := c.(*CustomContext)

	uid, _ := strconv.Atoi(fmt.Sprintf("%v", UserID))

	for _, user := range Users {
		if user.ID == uid {
            // REQUIRED
			ctx.User = user
			return nil
		}
	}
	return errors.New("user not found")
}
```


## Usage


### 1. Create `sessionauth.SessionAuth` instance.

`main.go`

```go
package main

import (
    ...
    sessionauth "github.com/jockerz/session-auth-echo"
)

var (
    auth *sessionauth.SessionAuth

    // Session auth config
    Config = sessionauth.MakeConfig(
		[]byte("changeme"),      // Secret Key
		"/login",                // UnAuthRedirect
		[]string{"favicon.ico"}, // Excluded path by strings
		[]*regexp.Regexp{},      // Exlcuded path by regex
	)
)

func main() {
    ...
    // Create session auth
	auth, _ = sessionauth.Create(Config, GetUser)
    ...
}
```


### 2. Use the Extended `Context`

>> Ref: [Context](https://echo.labstack.com/guide/context/)

```go
func main() {
    app := echo.New()
    
    app.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			cc := &CustomContext{
				Context: c,
			}
			return next(cc)
		}
	})
    ...
}
```


### 3. Middlewares


#### 1. Session Middleware

After using the extended *echo context*, 
we need the `*echo.Echo` instance to use *session* and *cookie*.
Therefore we load it after our *custom context*.


```go
func main() {
    ...
    // Use session middleware
    app.Use(auth.GetSessionMiddleware())
}
```


#### 2. Session Auth Middleware

*Auth middleware* is required to get `User` for each request session.
Make sure you use this middleware after the *session middleware*.

```go
func main() {
    ...
    // Use session middleware
    app.Use(auth.GetSessionMiddleware())
    // Session auth middleware
    app.Use(auth.AuthMiddlewareFunc)
}
```


### 4. Protecting Routes

Protected route example for authenticated user only

```go
func ProtectedPage(c echo.Context) error {
	ctx := c.(*CustomContext)
    // required
	SessionAuth.LoginRequired(ctx)
    
    ...
}
```

Protected route example for freshly authenticated user only

```go
func FreshOnlyProtectedPage(c echo.Context) error {
	ctx := c.(*CustomContext)
    // required
	SessionAuth.FreshLoginRequired(ctx)
	
    ...
}
```