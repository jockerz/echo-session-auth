package sessionauth

import (
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

func MakeConfig(UnAuthRedirect string, Excluded []string, ExcludedRegex []*regexp.Regexp) *Config {
	return &Config{
		SecretKey:       []byte(os.Getenv("SECRET_KEY")),
		UnAuthRedirect:  UnAuthRedirect,
		Excluded:        Excluded,
		ExcludedRegex:   ExcludedRegex,
		ProtectionLevel: ProtectionLevelBasic,

		CookieName:     "remember_token",
		CookiePath:     "/",
		CookieSecure:   true,
		CookieHTTPOnly: true,
		CookieSameSite: http.SameSiteDefaultMode,
		// Cookie duration (in seconds) by default is 30 days
		CookieDuration: 86400 * 30,

		SessionFresh: "_fresh",
		// Session Identifier for a User-Agent
		SessionID:               "_id",
		SessionKey:              "_user_id",
		SessionRememberCookie:   "_remember",
		SessionRememberDuration: "_remember_seconds",
	}
}
