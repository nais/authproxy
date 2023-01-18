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

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

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
			b, err := json.Marshal(jwks)
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

func defaultIapToken(aud string) *Token {
	return &Token{iapToken(time.Now().Add(-20*time.Second), 5*time.Minute, aud)}
}

func iapToken(iat time.Time, exp time.Duration, aud string) *Token {
	jwt.Settings(jwt.WithFlattenAudience(true))
	sub := uuid.New().String()
	expiry := iat.Add(exp)

	accessToken := jwt.New()
	accessToken.Set("sub", sub)
	accessToken.Set("iss", "https://cloud.google.com/iap")
	accessToken.Set("azp", "123")
	accessToken.Set("aud", aud)
	accessToken.Set("hd", "whatevs.com")
	accessToken.Set("email", "user@nais.io")
	accessToken.Set("iat", iat.Unix())
	accessToken.Set("exp", expiry.Unix())
	return &Token{accessToken}
}

type Token struct {
	jwt.Token
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

func (t *Token) with(key, value string) *Token {
	t.Set(key, value)
	return t
}

func newJwkSet(kid string) (jwk.Set, error) {
	key, err := newJwk(kid)
	if err != nil {
		return nil, err
	}
	privateKeys := jwk.NewSet()
	privateKeys.AddKey(key)
	return privateKeys, nil
}

func newJwk(kid string) (jwk.Key, error) {

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
	return key, nil
}
