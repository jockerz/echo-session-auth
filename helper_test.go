package sessionauth_test

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"

	sessionauth "github.com/jockerz/echo-session-auth"
	"github.com/labstack/echo/v4"
)

type (
	CustomContext struct {
		echo.Context
		User interface{}
	}

	User struct {
		ID       uint
		Username string
		Password string
		Name     string
	}

	LoginParam struct {
		Username string `form:"username" validate:"required" json:"username"`
		Password string `form:"password" validate:"required" json:"password"`
		Remember bool   `form:"remember" json:"remember"`
	}
)

var (
	Secret = []byte("secret")
	users  = []*User{
		&User{1, "user1", "pass", "User 1"},
		&User{2, "user2", "pass", "User 2"},
	}

	// Configs
	exc   = []string{"/exc"}
	excRe = []*regexp.Regexp{
		regexp.MustCompile(`/static/*`),
		regexp.MustCompile(`/exc-re*`),
	}
	config            = sessionauth.MakeConfig(Secret, "/login", exc, excRe)
	sa                = CreateSessionAUth()
	configEmptyUnAuth = sessionauth.MakeConfig(Secret, "", exc, excRe)
	saEmptyUnAuth     = CreateSessionAUth(configEmptyUnAuth)
)

func CreateSessionAUth(c ...*sessionauth.Config) *sessionauth.SessionAuth {
	// SessionAuth
	var sa *sessionauth.SessionAuth
	if len(c) > 0 {
		sa, _ = sessionauth.Create(c[0], GetUser)
	} else {
		sa, _ = sessionauth.Create(config, GetUser)
	}
	return sa
}

func GetUser(c echo.Context, UserID interface{}) error {
	ctx := c.(*CustomContext)

	var uid uint
	uid_i, err := strconv.Atoi(fmt.Sprintf("%v", UserID))

	for _, u := range users {
		if err == nil {
			uid = uint(uid_i)
		}

		if err == nil && u.ID == uint(uid) {
			ctx.User = u
			return nil
		}
	}
	return errors.New("user not found")
}

func CreateApp() *echo.Echo {
	// Create Echo
	app := echo.New()
	// app.Static("/static", "static")
	//
	// // Custom context, required
	// app.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
	// 	return func(c echo.Context) error {
	// 		cc := &CustomContext{
	// 			Context: c,
	// 			User:    nil,
	// 		}
	// 		return next(cc)
	// 	}
	// })
	// // session middleware, required
	// app.Use(sa.GetSessionMiddleware())
	// // session authentication middleware, required
	// app.Use(sa.AuthMiddlewareFunc)
	return app
}

// Endpoints

func NoAuthEndpoint(c echo.Context) error {
	ctx := c.(*CustomContext)
	data := map[string]interface{}{
		"user": ctx.User,
	}
	return c.JSON(http.StatusOK, data)
}

func ProtectedEndpoint(c echo.Context) error {
	ctx := c.(*CustomContext)

	sa.LoginRequired(ctx)
	data := map[string]interface{}{
		"user": ctx.User,
	}
	return ctx.JSON(http.StatusOK, data)
}

func ProtectedEndpointFresh(c echo.Context) error {
	ctx := c.(*CustomContext)

	sa.FreshLoginRequired(ctx)
	data := map[string]interface{}{
		"user": ctx.User,
	}
	return ctx.JSON(http.StatusOK, data)
}

func ProtectedEndpoint401(c echo.Context) error {
	ctx := c.(*CustomContext)

	saEmptyUnAuth.LoginRequired(ctx)
	data := map[string]interface{}{
		"user": ctx.User,
	}
	return ctx.JSON(http.StatusOK, data)
}

func ProtectedEndpointFresh401(c echo.Context) error {
	ctx := c.(*CustomContext)

	saEmptyUnAuth.FreshLoginRequired(ctx)
	data := map[string]interface{}{
		"user": ctx.User,
	}
	return ctx.JSON(http.StatusOK, data)
}

func LoginEndpoint(c echo.Context) error {
	ctx := c.(*CustomContext)
	var body LoginParam

	if ctx.User != nil {
		return ctx.Redirect(http.StatusFound, "/")
	}

	if ctx.Bind(&body) != nil {
		for _, u := range users {
			if body.Username == u.Username {
				// sa.Login(ctx, fmt.Sprintf("%v", u.ID), true, body.Remember)
				sa.Login(ctx, fmt.Sprintf("%v", u.ID), true, true)
			}
		}
	}
	data := map[string]interface{}{}
	return c.JSON(http.StatusOK, data)
}
