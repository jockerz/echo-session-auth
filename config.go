package sessionauth

import (
	"bytes"
	"net/http"
	"os"
	"regexp"
)

// TODO: Protection Level
const (
	ProtectionLevelBasic  int = 1
	ProtectionLevelStrong int = 2
)

// Initial configurations
type Config struct {
	// Session auth cookie name
	AuthSessionName string
	// Secret key that would be used for cookie and more
	// Loaded from shell environment `SECRET_KEY`
	SecretKey []byte
	// Redirection path for unauthorized access to protected page
	UnAuthRedirect string
	// Exluded path list. E.g. "/logout", "/register", etc
	Excluded []string
	// Exluded regex path. E.g. "/static/*"
	ExcludedRegex []*regexp.Regexp

	// Choose between `ProtectionLevelBasic` or `ProtectionLevelStrong`
	ProtectionLevel int

	// Cookie

	// cookie name for login with `remember me` flag
	CookieName     string
	CookieDomain   string
	CookiePath     string
	CookieSecure   bool
	CookieHTTPOnly bool
	CookieSameSite http.SameSite
	// Cookie duration in seconds
	CookieDuration int

	// Session

	SessionFresh            string
	SessionID               string
	SessionKey              string
	SessionNext             string
	SessionRememberCookie   string
	SessionRememberDuration string
}

func MakeConfig(SecretKey []byte, UnAuthRedirect string, Excluded []string, ExcludedRegex []*regexp.Regexp) *Config {
	if !bytes.Equal(SecretKey, []byte{}) {
		SecretKey = []byte(os.Getenv("SECRET_KEY"))
	}

	return &Config{
		SecretKey:       SecretKey,
		UnAuthRedirect:  UnAuthRedirect,
		Excluded:        Excluded,
		ExcludedRegex:   ExcludedRegex,
		ProtectionLevel: ProtectionLevelBasic,
		AuthSessionName: "sessionauth",

		CookieName:     "remember_token",
		CookiePath:     "/",
		CookieSecure:   true,
		CookieHTTPOnly: true,
		CookieSameSite: http.SameSiteDefaultMode,
		// Cookie duration (in seconds) by default is 30 days
		CookieDuration: 86400 * 30,

		// Session freshness status
		SessionFresh: "_fresh",
		// Session Identifier
		SessionID: "_id",
		// User ID
		SessionKey: "_user_id",
		// Remember operation
		SessionRememberCookie: "_remember",
		// Remember session duration
		SessionRememberDuration: "_remember_seconds",
	}
}
