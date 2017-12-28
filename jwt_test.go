package jwt

import (
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

type CustomClaims struct {
	jwt.Claims
	ID   string
	Name string
}

var (
	signingKey   = []byte("asecretsignstring")
	c            jwt.Claims
	sig          jose.Signer
	signedString string
)

func init() {
	var err error
	now := time.Now()

	c = jwt.Claims{
		Issuer:    "issuer",
		Subject:   "subject",
		Audience:  jwt.Audience{"a1"},
		NotBefore: jwt.NewNumericDate(now),
		IssuedAt:  jwt.NewNumericDate(now),
		Expiry:    jwt.NewNumericDate(now.Add(1 * time.Hour)),
	}

	sig, err = jose.NewSigner(
		jose.SigningKey{Algorithm: jose.HS256, Key: signingKey},
		(&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		panic(err)
	}

	signedString, err = jwt.Signed(sig).Claims(c).CompactSerialize()
	if err != nil {
		panic(err)
	}
}

func TestJWT_HandleJWT(t *testing.T) {
	j := New(Option{
		SigningKey:    signingKey,
		SigningMethod: jose.HS256,
		Audience:      "a1",
		Issuer:        "issuer",
	})
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/", nil)
	r.Header.Set(HeaderAuthorization, fmt.Sprintf("%s %s", Bearer, signedString))

	assert.NoError(t, j.HandleJWT(w, r))
	value := r.Context().Value("user")
	assert.NotNil(t, value)
	m, ok := value.(*jwt.Claims)
	assert.True(t, ok)
	assert.Equal(t, m.Issuer, "issuer")
	assert.True(t, m.Audience.Contains("a1"))
}

func TestJWT_HandleJWT_CustomClaims(t *testing.T) {
	cc := CustomClaims{c, "ID", "NAME"}
	signedString, err := jwt.Signed(sig).Claims(&cc).CompactSerialize()
	if err != nil {
		panic(err)
	}

	j := New(Option{
		SigningKey:    signingKey,
		SigningMethod: jose.HS256,
		Audience:      "a1",
		Issuer:        "issuer",
		Claims:        &CustomClaims{},
	})
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/", nil)
	r.Header.Set(HeaderAuthorization, fmt.Sprintf("%s %s", Bearer, signedString))

	assert.NoError(t, j.HandleJWT(w, r))
	value := r.Context().Value("user")
	assert.NotNil(t, value)
	m, ok := value.(*CustomClaims)
	assert.True(t, ok)
	assert.Equal(t, m.Issuer, cc.Issuer)
	assert.True(t, m.Audience.Contains("a1"))
	assert.Equal(t, m.Name, cc.Name)
}
