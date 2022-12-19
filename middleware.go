package sessionauth

import (
	"crypto/hmac"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"time"

	"github.com/gorilla/sessions"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
)

const (
	AuthSessionName          = "sessionauth"
	InvalidCookie            = "invalid cookie"
	InvalidCookieIndentifier = "invalid cookie identifier"
)

type (
	ISessionAuth interface {
		// Get Session (extended againts our config) middleware function
		GetSessionMiddleware() echo.MiddlewareFunc

		// Get authentication middleware function
		AuthMiddlewareFunc() echo.HandlerFunc

		// Set authentication session and cookie
		Login(ctx echo.Context, UserId string, fresh bool) error

		// Clean authentication session and cookie
		Logout(ctx echo.Context)

		// Check if path is in excluded pattern list
		PathIsExcluded(path string)
	}

	SessionAuth struct {
		config *Config
		cookie *sessions.CookieStore

		// Get user method
		// error is not nil if user is not found
		GetUser func(c echo.Context, UserId any) error
	}
)

// Create SessionAuth by
func Create(
	config *Config, getUser func(c echo.Context, UserId any) error,
) (SessionAuth, error) {
	sa := SessionAuth{
		config:  config,
		cookie:  sessions.NewCookieStore([]byte(config.SecretKey)),
		GetUser: getUser,
	}

	return sa, nil
}

func (s *SessionAuth) GetSessionMiddleware() echo.MiddlewareFunc {
	return session.Middleware(s.cookie)
}

func (s *SessionAuth) AuthMiddlewareFunc(next echo.HandlerFunc) echo.HandlerFunc {
	return func(ctx echo.Context) error {
		if s.PathIsExcluded(ctx.Path()) {
			// Skip authentication on excluded path
			return next(ctx)
		}

		// Get auth session
		sess, err := session.Get(AuthSessionName, ctx)
		if err != nil {
			ctx.Error(err)
		}

		// Get UserID from auth session
		UserID, ok := sess.Values[s.config.SessionKey]
		if !ok {
			// Get UserID from remember cookie
			UserID, err = s.GetCookie(ctx)
			if err != nil {
				if err.Error() == InvalidCookieIndentifier {
					sess.Values[s.config.SessionRememberCookie] = "clear"
				}
			}

			if UserID != nil {
				// Session is not fresh anymore
				sess.Values[s.config.SessionFresh] = false
			}
		}

		if err == nil {
			// Get user and set user on context properties
			s.GetUser(ctx, UserID)
		}

		// Get remember me cookie operation
		op, isExist := sess.Values[s.config.SessionRememberCookie]
		if isExist {
			if op == "set" {
				// Set remember cookie
				s.SetCookie(ctx, fmt.Sprintf("%v", UserID))
			} else if op == "clear" {
				sess.Values[s.config.SessionRememberCookie] = ""
				s.DeleteCookie(ctx)
			}
		}

		if err := next(ctx); err != nil {
			ctx.Error(err)
		}

		return nil
	}
}

func (s *SessionAuth) PathIsExcluded(path string) bool {
	u, err := url.Parse(path)
	if err != nil {
		panic(err)
	}

	// Path is UnauthRedirect (usually "/login")
	if u.Path == s.config.UnAuthRedirect {
		return true
	}

	// Check path for excluded string match
	for _, v := range s.config.Excluded {
		if v == u.Path {
			return true
		}
	}

	// Check path for excluded regex match
	for _, v := range s.config.ExcludedRegex {
		if v.Match([]byte(u.Path)) {
			return true
		}
	}

	// Checks completes
	return false
}

// Save session cookie options
func (s *SessionAuth) setSessionOption(ctx echo.Context, sess *sessions.Session) {
	sess.Options.Domain = s.config.CookieDomain
	sess.Options.HttpOnly = s.config.CookieHTTPOnly
	sess.Options.Path = s.config.CookiePath
	sess.Options.Secure = s.config.CookieSecure
	sess.Options.SameSite = s.config.CookieSameSite
}

func (s *SessionAuth) SetCookie(ctx echo.Context, UserID string) {
	cookie := new(http.Cookie)

	cookie.Name = s.config.CookieName
	d := CookieDigest(UserID, s.config.SecretKey)
	cookie.Value = fmt.Sprintf("%v|%v", UserID, base64.StdEncoding.EncodeToString(d))

	cookie.Domain = s.config.CookieDomain
	cookie.Expires = time.Now().Add(time.Second * time.Duration(s.config.CookieDuration))
	cookie.Secure = s.config.CookieSecure
	cookie.HttpOnly = s.config.CookieHTTPOnly
	cookie.SameSite = s.config.CookieSameSite
	cookie.Path = s.config.CookiePath

	// Load to current echo.context
	ctx.SetCookie(cookie)
}

func (s *SessionAuth) GetCookie(ctx echo.Context) (interface{}, error) {
	cookie, err := ctx.Cookie(s.config.CookieName)
	if err != nil {
		return nil, err
	}

	splits := strings.Split(cookie.Value, "|")
	if len(splits) != 2 {
		return nil, errors.New(InvalidCookie)
	}

	UserID := splits[0]
	c := splits[1]

	CookieID, err := DecodeCookie(c, s.config.SecretKey)
	if err != nil {
		return nil, err
	}

	v := CookieDigest(UserID, s.config.SecretKey)

	// remember cookie identifier
	if !hmac.Equal(CookieID, v) {
		return nil, errors.New(InvalidCookieIndentifier)
	}

	return UserID, nil
}

func (s *SessionAuth) DeleteCookie(ctx echo.Context) {
	cookie := &http.Cookie{
		Name:     s.config.CookieName,
		Value:    "",
		HttpOnly: s.config.CookieHTTPOnly,
		SameSite: s.config.CookieSameSite,
		Path:     s.config.CookiePath,
		MaxAge:   -1,
	}

	// Load to current echo.context
	ctx.SetCookie(cookie)
}

// Save authenticated user session
// if "remember" is true, save remember_me cookie
// UserID should be represented as string
func (s *SessionAuth) Login(ctx echo.Context, UserId string, fresh bool, remember bool) error {
	sess, err := session.Get(AuthSessionName, ctx)
	if err != nil {
		return err
	}

	s.setSessionOption(ctx, sess)

	h := ctx.Request().Header
	ua := h["User-Agent"]

	sess.Values[s.config.SessionID] = CreateSessionID(ctx.RealIP(), ua)
	sess.Values[s.config.SessionKey] = UserId
	sess.Values[s.config.SessionFresh] = fresh

	if remember {
		sess.Values[s.config.SessionRememberCookie] = "set"
		if s.config.CookieDuration > 0 {
			sess.Values[s.config.SessionRememberDuration] = s.config.CookieDuration
		}
	}

	// if s.config.ProtectionLevel == ProtectionLevelStrong {}
	// Save session and cookie
	sess.Save(ctx.Request(), ctx.Response())
	return nil
}

func (s *SessionAuth) Logout(ctx echo.Context) {
	sess, err := session.Get(AuthSessionName, ctx)
	if err != nil {
		return
	}

	// Auth session with no UserID value
	h := ctx.Request().Header
	ua := h["User-Agent"]
	sess.Values[s.config.SessionID] = CreateSessionID(ctx.RealIP(), ua)
	// sess.Values[s.config.SessionID] = ""
	// To be cleared on `AuthMiddlewareFunc`
	sess.Values[s.config.SessionRememberCookie] = "clear"

	v := reflect.ValueOf(sess.Values)
	v.SetMapIndex(reflect.ValueOf(s.config.SessionKey), reflect.Value{})
	v.SetMapIndex(reflect.ValueOf(s.config.SessionFresh), reflect.Value{})
	v.SetMapIndex(reflect.ValueOf(s.config.SessionID), reflect.Value{})
	v.SetMapIndex(reflect.ValueOf(s.config.SessionRememberDuration), reflect.Value{})

	sess.Save(ctx.Request(), ctx.Response())
	// v.(*session.Session).Save(ctx.Request(), ctx.Response())
}

// Need to be called on restricted endpoints
// that accessed by authenticated user
// Returns redirect to "config.UnauthRedirect" with last path as next URL query
func (s *SessionAuth) LoginRequired(ctx echo.Context) error {
	// UnauthRedirect is not set
	if s.config.UnAuthRedirect == "" {
		return ctx.NoContent(http.StatusUnauthorized)
	}

	r := reflect.Indirect(reflect.ValueOf(ctx))

	// User is invalid
	if r.FieldByName("User").IsNil() {
		// redirect to "UnauthRedirect" URL
		// with previous URL as next URL query
		return ctx.Redirect(http.StatusFound, s.buildNextURL(ctx))
	}
	return nil
}

// Need to be called on restricted endpoints
// that accessed by freshly authenticated user
// Returns redirect to "config.UnauthRedirect" with last path as next URL query
func (s *SessionAuth) FreshLoginRequired(ctx echo.Context) error {
	// UnauthRedirect is not set
	if s.config.UnAuthRedirect == "" {
		return ctx.NoContent(http.StatusUnauthorized)
	}

	r := reflect.Indirect(reflect.ValueOf(ctx))

	sess, err := session.Get(AuthSessionName, ctx)
	if err != nil {
		return err
	}

	fresh, ok := sess.Values[s.config.SessionFresh]

	v := r.FieldByName("User")

	// User is nil or session is not fresh
	if v.IsNil() || !ok || !fresh.(bool) {
		// redirect to "UnauthRedirect" URL
		// with previous URL as next URL query
		return ctx.Redirect(http.StatusFound, s.buildNextURL(ctx))
	}
	return nil
}

// Build next url for "UnauthRedirect" next parameters
func (s *SessionAuth) buildNextURL(ctx echo.Context) string {
	q := url.Values{}
	q.Set("next", ctx.Path())
	return s.config.UnAuthRedirect + "?" + q.Encode()
}
