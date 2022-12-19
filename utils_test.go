package sessionauth_test

import (
	"encoding/base64"
	"testing"

	sessionauth "github.com/jockerz/echo-session-auth"
	"github.com/stretchr/testify/assert"
)

func TestCreateSessionID(t *testing.T) {
	sid := sessionauth.CreateSessionID("ip", []string{"User-agent"})
	sid2 := sessionauth.CreateSessionID("ip", []string{"User-agent"})
	sid3 := sessionauth.CreateSessionID("diffip", []string{"User-agent"})
	sid4 := sessionauth.CreateSessionID("ip", []string{"Diff-User-agent"})

	// Same IP and User-agent should have equal Identifier
	assert.Equal(t, sid, sid2)
	assert.NotEqual(t, sid, sid3)
	assert.NotEqual(t, sid, sid4)
}

func TestCookieDigest(t *testing.T) {
	s := sessionauth.CookieDigest("payload", []byte("secret"))
	s2 := sessionauth.CookieDigest("", []byte(""))

	// Should not be empty
	assert.NotEmpty(t, s)
	assert.NotEmpty(t, s2)
}

func TestDecodeCookie(t *testing.T) {
	secret := []byte("secret")
	s := sessionauth.CookieDigest("payload", secret)
	es := base64.StdEncoding.EncodeToString(s)
	d, err := sessionauth.DecodeCookie(es, secret)

	if assert.Nil(t, err) {
		assert.Equal(t, d, s)
	}
}
