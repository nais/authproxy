package auth

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	log "github.com/sirupsen/logrus"
)

const AcceptableClockSkew = 5 * time.Second

type JWTAuth struct {
	AuthHeader     string
	RequiredClaims map[string]any
	jwksURL        string
	jwksCache      *jwk.Cache
}

var _ Provider = &JWTAuth{}

func JWT(authHeader, jwksURL string, requiredClaims map[string]any) (*JWTAuth, error) {

	return &JWTAuth{
		jwksURL:        jwksURL,
		AuthHeader:     authHeader,
		RequiredClaims: requiredClaims,
	}, nil
}

func (p *JWTAuth) Handler() (Handler, error) {
	if p.jwksCache == nil {
		c, err := p.cache()
		if err != nil {
			return nil, err
		}
		p.jwksCache = c
	}

	return func(handler http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			header := r.Header.Get(p.AuthHeader)

			token := strings.ReplaceAll(header, "Bearer ", "")
			token = strings.TrimSpace(token)

			if token == "" {
				log.Debugf("no JWT token found in request")
				http.Error(w, fmt.Sprintf("missing token from header %s", p.AuthHeader), http.StatusUnauthorized)
				return
			}
			if err := p.validate(r.Context(), token); err != nil {
				log.Debugf("invalid JWT token: %v", err)
				http.Error(w, "invalid token", http.StatusUnauthorized)
				return
			}

			handler.ServeHTTP(w, r)
		})
	}, nil
}

func (p *JWTAuth) WithJWKSCache(cache *jwk.Cache) *JWTAuth {
	p.jwksCache = cache
	return p
}

func (p *JWTAuth) validate(ctx context.Context, token string) error {

	opts := []jwt.ValidateOption{
		jwt.WithAcceptableSkew(AcceptableClockSkew),
	}
	for k, v := range p.RequiredClaims {
		switch k {
		case "iss":
			opts = append(opts, jwt.WithIssuer(v.(string)))
		case "aud":
			opts = append(opts, jwt.WithAudience(v.(string)))
		default:
			opts = append(opts, jwt.WithClaimValue(k, v))
		}
	}

	t, err := p.parseToken(ctx, token)
	if err != nil {
		return fmt.Errorf("parsing jwt: %w", err)
	}
	return jwt.Validate(t, opts...)
}

func (p *JWTAuth) parseToken(ctx context.Context, raw string) (jwt.Token, error) {
	jwks, err := p.getJWKS(ctx)
	if err != nil {
		return nil, err
	}
	parseOpts := []jwt.ParseOption{
		jwt.WithKeySet(*jwks,
			jws.WithInferAlgorithmFromKey(true),
		),
		jwt.WithAcceptableSkew(AcceptableClockSkew),
	}
	return jwt.ParseString(raw, parseOpts...)
}

func (p *JWTAuth) getJWKS(ctx context.Context) (*jwk.Set, error) {
	set, err := p.jwksCache.Get(ctx, p.jwksURL)
	if err != nil {
		return nil, fmt.Errorf("provider: fetching jwks: %w", err)
	}

	return &set, nil
}

func (p *JWTAuth) cache() (*jwk.Cache, error) {
	ctx := context.Background()
	cache := jwk.NewCache(ctx)

	err := cache.Register(p.jwksURL)
	if err != nil {
		return nil, fmt.Errorf("registering jwks provider uri to cache: %w", err)
	}

	// trigger initial fetch and cache of jwk set
	_, err = cache.Refresh(ctx, p.jwksURL)
	if err != nil {
		return nil, fmt.Errorf("initial fetch of jwks from provider: %w", err)
	}
	return cache, nil
}
