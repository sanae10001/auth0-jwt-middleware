package jwt

import (
	"context"
	"log"
	"net/http"

	"github.com/auth0-community/go-auth0"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

const (
	HeaderAuthorization = "Authorization"
	Bearer              = "bearer"
)

var (
	UserContextKey = ContextKey{Name: "user"}
)

type (
	// A function called before set value into context
	ContextSetValueFunc func(claims interface{}) (interface{}, error)

	// A function called when an error is encountered
	ErrorHandler func(w http.ResponseWriter, r *http.Request, err error)

	SigningKeyGetter func() (interface{}, error)

	ContextKey struct {
		Name string
	}

	Option struct {
		// Required
		SigningMethod jose.SignatureAlgorithm
		// Required if signing method is HS256
		SigningKey interface{}
		// Required if signing method is HS256
		SigningKeyGetter SigningKeyGetter
		// Required if signing method is RS256
		JWKSUri string

		// The audience identifies the recipients that the JWT is intended for.
		// For JWTs issued by Auth0, aud holds the unique identifier of the target API
		// Required
		Audience string

		// The issuer denotes the issuer of the JWT.
		// The value must match the one configured in your API.
		// Required
		Issuer string

		// Claims are extendable claims data defining token content.
		// Optional. Default: jose.jwt.Claims
		Claims interface{}

		// The key name in the context where the user information
		// from the JWT will be stored.
		// Optional. Default: UserContextKey
		ContextKey interface{}

		// When set, all requests with the OPTIONS method will use authentication
		// Optional. Default: false
		EnableAuthOnOptions bool

		// A boolean indicating if the credentials are optional or not
		// Optional. Default: false
		CredentialsOptional bool

		// The function that will be called when there's an error validating the token
		// Optional. Default: OnError
		ErrorHandler ErrorHandler

		// The function that will be called before set value into context.
		// Used to customize the value will be stored into context.
		// Optional. Default: ContextValueSetClaims
		ContextSetValueFunc ContextSetValueFunc
	}

	JWT struct {
		validator *auth0.JWTValidator
		opt       Option
	}
)

func (k *ContextKey) String() string {
	return "jwt-middleware context value " + k.Name
}

func New(opt Option) *JWT {
	j := new(JWT)
	var provider auth0.SecretProvider

	switch opt.SigningMethod {
	case jose.HS256:
		if opt.SigningKey != nil {
			provider = auth0.NewKeyProvider(opt.SigningKey)
		} else if opt.SigningKeyGetter != nil {
			key, err := opt.SigningKeyGetter()
			if err != nil {
				log.Panic(err)
			}
			provider = auth0.NewKeyProvider(key)
		} else {
			log.Panic("must provide SigningKey or SigningKeyGetter when method is HS256")
		}
	case jose.RS256:
		if opt.JWKSUri == "" {
			log.Panic("must provide jwks uri when method is RS256")
		}
		provider = auth0.NewJWKClient(auth0.JWKClientOptions{URI: opt.JWKSUri})
	default:
		log.Panicf("unsupported signing method=%s", opt.SigningMethod)
	}

	if opt.Audience == "" || opt.Issuer == "" {
		log.Panic("must provide audience and issuer")
	}
	j.validator = auth0.NewValidator(auth0.NewConfiguration(
		provider,
		[]string{opt.Audience},
		opt.Issuer,
		opt.SigningMethod,
	))

	if opt.Claims == nil {
		opt.Claims = &jwt.Claims{}
	}

	if opt.ContextKey == nil {
		opt.ContextKey = UserContextKey
	}

	if opt.ErrorHandler == nil {
		opt.ErrorHandler = OnError
	}

	if opt.ContextSetValueFunc == nil {
		opt.ContextSetValueFunc = ContextValueSetClaims
	}

	j.opt = opt
	return j
}

func (j *JWT) HandlerWithNext(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	err := j.HandleJWT(w, r)
	if err != nil {
		j.opt.ErrorHandler(w, r, err)
		return
	}
	if next != nil {
		next(w, r)
	}
}

func (j *JWT) Handler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := j.HandleJWT(w, r)
		if err != nil {
			j.opt.ErrorHandler(w, r, err)
			return
		}

		h.ServeHTTP(w, r)
	})
}

func (j *JWT) HandleJWT(w http.ResponseWriter, r *http.Request) error {
	if !j.opt.EnableAuthOnOptions {
		if r.Method == "OPTIONS" {
			return nil
		}
	}

	token, err := j.validator.ValidateRequest(r)
	if err != nil {
		if err == auth0.ErrTokenNotFound && j.opt.CredentialsOptional {
			return nil
		}
		return err
	}

	err = j.validator.Claims(r, token, j.opt.Claims)
	if err != nil {
		if err == auth0.ErrTokenNotFound && j.opt.CredentialsOptional {
			return nil
		}
		return err
	}

	value, err := j.opt.ContextSetValueFunc(j.opt.Claims)
	if err != nil {
		return err
	}
	newRequest := r.WithContext(context.WithValue(r.Context(), j.opt.ContextKey, value))
	*r = *newRequest
	return nil
}

func OnError(w http.ResponseWriter, r *http.Request, err error) {
	http.Error(w, err.Error(), http.StatusUnauthorized)
}

func ContextValueSetClaims(claims interface{}) (interface{}, error) {
	return claims, nil
}
