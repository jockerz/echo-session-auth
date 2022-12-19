package sessionauth

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
)

// Create auth session
func CreateSessionID(realIP string, userAgent []string) string {
	plain := fmt.Sprintf("%s|%s", realIP, userAgent)

	hash := sha512.New()
	hash.Write([]byte(plain))

	return base64.StdEncoding.EncodeToString(hash.Sum(nil))
}

// Create a endrypted remember cookie
func CookieDigest(payload string, secret []byte) []byte {
	h := hmac.New(sha512.New, secret)
	h.Write([]byte(payload))
	return h.Sum(nil)
}

// Decode remember cookie
func DecodeCookie(cookieValue string, secret []byte) ([]byte, error) {
	s, e := base64.StdEncoding.DecodeString(cookieValue)
	if e != nil {
		return []byte(""), e
	}
	return s, nil
}
