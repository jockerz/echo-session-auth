package sessionauth_test

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"

	sessionauth "github.com/jockerz/echo-session-auth"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

// Middleware and its settings

// Middleware chains
//
// Flow: Session > Custom context > AuthMiddleware
func middlewareChains(next echo.HandlerFunc, uid ...uint) echo.HandlerFunc {
	h0 := sa.AuthMiddlewareFunc(next)

	h1 := func(c echo.Context) error {
		cc := &CustomContext{
			Context: c,
			User:    nil,
		}

		if len(uid) > 0 {
			// Login before `AuthMiddlewareFunc` called
			// So the auth session is loaded
			u := strconv.FormatUint(uint64(uid[0]), 10)
			sa.Login(cc, u, true, true)
		}
		return h0(cc)
	}

	h := sa.GetSessionMiddleware()(h1)
	return h
}

// Middleware chains with login settings
func middlewareChainsLoginSetting(next echo.HandlerFunc, uid uint, fresh bool, remember bool) echo.HandlerFunc {
	h0 := sa.AuthMiddlewareFunc(next)

	h1 := func(c echo.Context) error {
		cc := &CustomContext{
			Context: c,
			User:    nil,
		}

		// Login before `AuthMiddlewareFunc` called
		// So the auth session is loaded
		u := strconv.FormatUint(uint64(uid), 10)
		sa.Login(cc, u, fresh, remember)
		return h0(cc)
	}

	h := sa.GetSessionMiddleware()(h1)
	return h
}

// Middleware chains with login settings
func middlewareChainsLoginThenLogout(next echo.HandlerFunc, uid uint, logout bool) echo.HandlerFunc {
	h0 := sa.AuthMiddlewareFunc(next)

	h1 := func(c echo.Context) error {
		cc := &CustomContext{
			Context: c,
			User:    nil,
		}

		// Login before `AuthMiddlewareFunc` called
		// So the auth session is loaded
		u := strconv.FormatUint(uint64(uid), 10)
		sa.Login(cc, u, true, true)
		if logout {
			sa.Logout(cc)
		}
		return h0(cc)
	}

	h := sa.GetSessionMiddleware()(h1)
	return h
}

// End of endpoints

func TestCreate(t *testing.T) {
	// create config
	r := []*regexp.Regexp{}
	config := sessionauth.MakeConfig(Secret, "/login", []string{}, r)
	assert.NotEmpty(t, config)

	// create SessionAuth
	sa, err := sessionauth.Create(config, func(c echo.Context, UserId any) error {
		return nil
	})

	if assert.Nil(t, err) {
		assert.NotNil(t, sa.GetUser)
	}
}

func TestGetSessionMiddleware(t *testing.T) {
	// create SessionAuth
	r := []*regexp.Regexp{}
	config := sessionauth.MakeConfig(Secret, "/login", []string{}, r)
	sa, _ := sessionauth.Create(config, func(c echo.Context, UserId any) error {
		return nil
	})

	m := sa.GetSessionMiddleware()
	assert.Equal(t, reflect.ValueOf(m).Type().String(), "echo.MiddlewareFunc")
}

// Test for AuthMiddlewareFunc

func TestAuthMiddlewareFunc_AuthNotRequired(t *testing.T) {
	app := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	ctx := app.NewContext(req, rec)

	// call the endpoint with its middlewares
	mw := middlewareChains(NoAuthEndpoint)
	err := mw(ctx)

	assert.NoError(t, err)
	assert.Equal(t, rec.Code, http.StatusOK)
}

func TestAuthMiddlewareFunc_Error_AuthRequired(t *testing.T) {
	app := CreateApp()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	ctx := app.NewContext(req, rec)

	// call the endpoint with its middlewares
	mw := middlewareChains(ProtectedEndpoint)
	err := mw(ctx)

	assert.NoError(t, err)
	assert.Equal(t, rec.Code, http.StatusFound)
	assert.Equal(t, rec.Header().Values("Location"), []string{"/login?next="})

	s, err := session.Get(sa.Config.AuthSessionName, ctx)
	assert.NoError(t, err)
	assert.Equal(t, s.Values, map[interface{}]interface{}{})
}

func TestAuthMiddlewareFunc_Error_AuthRequired_401(t *testing.T) {
	app := CreateApp()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	ctx := app.NewContext(req, rec)

	// call the endpoint with its middlewares
	mw := middlewareChains(ProtectedEndpoint401)
	mw(ctx)

	assert.Equal(t, rec.Code, http.StatusUnauthorized)
}

func TestAuthMiddlewareFunc_Fail_UserNotFound(t *testing.T) {
	app := CreateApp()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	ctx := app.NewContext(req, rec)

	// Action
	// call the endpoint with its middlewares
	mw := middlewareChains(ProtectedEndpoint, uint(0))
	err := mw(ctx)

	assert.Equal(t, rec.Code, http.StatusFound)
	assert.NoError(t, err)

	sess, err := session.Get(sa.Config.AuthSessionName, ctx)
	assert.NoError(t, err)
	assert.NotEmpty(t, sess, "Should has `AuthSessionName` session")
}

func TestAuthMiddlewareFunc_Success(t *testing.T) {
	app := CreateApp()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	ctx := app.NewContext(req, rec)
	user := users[0]

	// Action
	// call the endpoint with its middlewares
	mw := middlewareChains(ProtectedEndpoint, user.ID)
	err := mw(ctx)

	assert.Equal(t, rec.Code, http.StatusOK)
	assert.NoError(t, err)

	sess, err := session.Get(sa.Config.AuthSessionName, ctx)
	assert.NoError(t, err)
	assert.NotEmpty(t, sess, "Should has `AuthSessionName` session")
}

func TestAuthMiddlewareFunc_Failed_UseRememberCookie_UserNotFound(t *testing.T) {
	app := CreateApp()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	// Remember cookie value
	uid := strconv.FormatUint(uint64(0), 10)
	d := sessionauth.CookieDigest(uid, config.SecretKey)
	// Drop a cookie to recorder
	// https://gist.github.com/jonnyreeves/17f91155a0d4a5d296d6
	http.SetCookie(rec, &http.Cookie{
		Name:  config.CookieName,
		Value: fmt.Sprintf("%v|%v", uid, base64.StdEncoding.EncodeToString(d)),
	})

	// Copy the Cookie over to a new Request
	req.Header = http.Header{"Cookie": rec.HeaderMap["Set-Cookie"]}

	ctx := app.NewContext(req, rec)
	sa.SetCookie(ctx, uid)

	// Action
	// call the endpoint with its middlewares
	mw := middlewareChains(ProtectedEndpoint)
	err := mw(ctx)

	assert.Equal(t, rec.Code, http.StatusFound, "User is invalid")
	assert.NoError(t, err)
	cookie, err := ctx.Cookie("remember_token")

	assert.NoError(t, err)
	assert.NotEmpty(t, cookie)

	sess, _ := session.Get(sa.Config.AuthSessionName, ctx)
	// The only session value is `_fresh = false`
	assert.Equal(t, len(sess.Values), 1, sess.Values)
}

func TestAuthMiddlewareFunc_Success_UseRememberCookie(t *testing.T) {
	app := CreateApp()
	user := users[0]

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	// Remember cookie value
	uid := strconv.FormatUint(uint64(user.ID), 10)
	d := sessionauth.CookieDigest(uid, config.SecretKey)
	// Drop a cookie to recorder
	// https://gist.github.com/jonnyreeves/17f91155a0d4a5d296d6
	http.SetCookie(rec, &http.Cookie{
		Name:  config.CookieName,
		Value: fmt.Sprintf("%v|%v", uid, base64.StdEncoding.EncodeToString(d)),
	})

	// Copy the Cookie over to a new Request
	req.Header = http.Header{"Cookie": rec.HeaderMap["Set-Cookie"]}

	ctx := app.NewContext(req, rec)
	sa.SetCookie(ctx, uid)

	// Action
	// call the endpoint with its middlewares
	mw := middlewareChains(ProtectedEndpoint)
	err := mw(ctx)

	assert.Equal(t, rec.Code, http.StatusOK, "Remember cookie should works")
	assert.NoError(t, err)
	cookie, err := ctx.Cookie("remember_token")

	assert.NoError(t, err)
	assert.NotEmpty(t, cookie)

	sess, _ := session.Get(sa.Config.AuthSessionName, ctx)
	// has session `_fresh = false`
	assert.Equal(t, len(sess.Values), 1, sess.Values)
}

func TestAuthMiddlewareFunc_Success_NoFresh(t *testing.T) {
	app := CreateApp()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	ctx := app.NewContext(req, rec)
	user := users[0]

	// Action
	// call the endpoint with its middlewares
	mw := middlewareChainsLoginSetting(ProtectedEndpoint, user.ID, false, true)
	err := mw(ctx)

	assert.Equal(t, rec.Code, http.StatusOK)
	assert.NoError(t, err)

	sess, err := session.Get(sa.Config.AuthSessionName, ctx)
	assert.NoError(t, err)
	assert.NotEmpty(t, sess, "Should has `AuthSessionName` session")
}

func TestAuthMiddlewareFunc_Failed_NoFresh(t *testing.T) {
	app := CreateApp()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	ctx := app.NewContext(req, rec)
	user := users[0]

	// Action
	// call the endpoint with its middlewares
	mw := middlewareChainsLoginSetting(ProtectedEndpointFresh, user.ID, false, false)
	mw(ctx)

	assert.Equal(t, rec.Code, http.StatusFound)
}

// Test with no `UnAuthRedirect` setting
func TestAuthMiddlewareFunc_Failed_NoFresh_401(t *testing.T) {
	app := CreateApp()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	ctx := app.NewContext(req, rec)
	user := users[0]

	// Action
	// call the endpoint with its middlewares
	mw := middlewareChainsLoginSetting(ProtectedEndpointFresh401, user.ID, false, false)
	mw(ctx)

	assert.Equal(t, rec.Code, http.StatusUnauthorized)
}

func TestAuthMiddlewareFunc_RememberCookie(t *testing.T) {
	app := CreateApp()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	ctx := app.NewContext(req, rec)
	user := users[0]

	// Action
	// call the endpoint with its middlewares
	mw := middlewareChainsLoginSetting(ProtectedEndpointFresh, user.ID, true, false)
	mw(ctx)

	assert.Equal(t, rec.Code, http.StatusOK)
	// TODO: checks for remember cookie on the response
	// Somehow current `rec` result does not have the cookie
}

func Test_Logout(t *testing.T) {
	app := CreateApp()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	ctx := app.NewContext(req, rec)
	user := users[0]

	// Action
	// call the endpoint with its middlewares
	mw := middlewareChainsLoginThenLogout(ProtectedEndpointFresh, user.ID, true)
	mw(ctx)

	assert.Equal(t, rec.Code, http.StatusFound)
	assert.Equal(t, rec.HeaderMap["Location"][0], "/login?next=")

	check_remember_cookie := false
	// Need to have multiple
	check_sess_auth_count := 0
	for _, v := range rec.HeaderMap["Set-Cookie"] {
		if strings.Contains(v, "remember_token=;") {
			check_remember_cookie = true
		} else if strings.Contains(v, fmt.Sprintf("%v", sa.Config.AuthSessionName)) {
			check_sess_auth_count += 1
		}
	}

	assert.True(t, check_remember_cookie)
	assert.True(t, check_sess_auth_count >= 2)
}

func TestPathIsExlcuded(t *testing.T) {
	path := "/exc-re-by-regex"
	app := CreateApp()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	ctx := app.NewContext(req, rec)
	ctx.SetPath(path)

	mw := middlewareChains(NoAuthEndpoint)
	err := mw(ctx)

	assert.NoError(t, err)
	assert.Equal(t, rec.Code, http.StatusOK)
}
