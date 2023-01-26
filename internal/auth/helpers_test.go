package auth

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

type TestProvider struct {
	Handler
}

func testProvider(p Provider) (*TestProvider, error) {
	h, err := p.Handler()
	if err != nil {
		return nil, err
	}
	return &TestProvider{h}, nil
}

func (p *TestProvider) withRequest(header ...string) (*httptest.ResponseRecorder, error) {
	req, err := req(header...)
	if err != nil {
		return nil, err
	}

	rr := httptest.NewRecorder()
	p.Handler(handler()).ServeHTTP(rr, req)
	return rr, nil
}

func req(header ...string) (*http.Request, error) {
	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	return req, nil
}

func handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func httpClient(jwks jwk.Set) *http.Client {
	return &http.Client{
		Transport: RoundTripFn(func(req *http.Request) *http.Response {

			publicKeys, err := jwk.PublicSetOf(jwks)
			if err != nil {
				panic(err)
			}

			b, err := json.Marshal(publicKeys)
			if err != nil {
				panic(err)
			}

			return &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(bytes.NewReader(b)),
				Header:     make(http.Header),
			}
		}),
	}
}

type RoundTripFn func(req *http.Request) *http.Response

func (f RoundTripFn) RoundTrip(req *http.Request) (*http.Response, error) { return f(req), nil }

type Token struct {
	jwt.Token
}

func token(iat time.Time, exp time.Duration) *Token {
	jwt.Settings(jwt.WithFlattenAudience(true))
	expiry := iat.Add(exp)
	accessToken := jwt.New()
	accessToken.Set("iat", iat.Unix())
	accessToken.Set("exp", expiry.Unix())
	return &Token{accessToken}
}

func (t *Token) sign(set jwk.Set) (string, error) {
	signer, ok := set.Key(0)
	if !ok {
		return "", fmt.Errorf("could not get signer")
	}

	tok, err := t.Clone()
	if err != nil {
		return "", err
	}
	signedToken, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256, signer))
	if err != nil {
		return "", err
	}
	return string(signedToken), nil
}

func (t *Token) with(key string, value any) *Token {
	t.Set(key, value)
	return t
}

func newJwkSet(kid string) (jwk.Set, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	key, err := jwk.FromRaw(privateKey)
	if err != nil {
		return nil, err
	}

	key.Set(jwk.AlgorithmKey, jwa.ES256)
	key.Set(jwk.KeyTypeKey, jwa.EC)
	key.Set(jwk.KeyIDKey, kid)
	privateKeys := jwk.NewSet()
	privateKeys.AddKey(key)
	return privateKeys, nil
}
