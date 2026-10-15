package auth

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jwx-go/jwkfetch/v4"
	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/lestrrat-go/jwx/v4/jwt"
	log "github.com/sirupsen/logrus"
)

const AcceptableClockSkew = 5 * time.Second

type JWTAuth struct {
	AuthHeader     string
	RequiredClaims map[string]any
	jwksURL        string
	jwksCache      *jwkfetch.Cache
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

func (p *JWTAuth) WithJWKSCache(cache *jwkfetch.Cache) *JWTAuth {
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
		jwt.WithKeySet(jwks,
			jws.WithInferAlgorithmFromKey(true),
		),
		jwt.WithAcceptableSkew(AcceptableClockSkew),
	}
	return jwt.ParseString(raw, parseOpts...)
}

func (p *JWTAuth) getJWKS(ctx context.Context) (jwk.Set, error) {
	set, err := p.jwksCache.Lookup(ctx, p.jwksURL)
	if err != nil {
		return nil, fmt.Errorf("provider: fetching jwks: %w", err)
	}

	return set, nil
}

func (p *JWTAuth) cache() (*jwkfetch.Cache, error) {
	ctx := context.Background()
	cache, err := jwkfetch.NewCache(ctx, httprc.NewClient(),
		jwkfetch.WithHTTPClient(jwkfetch.WrapHTTPClientDefaults(&http.Client{})),
	)
	if err != nil {
		return nil, fmt.Errorf("creating jwks cache: %w", err)
	}

	err = cache.Register(ctx, p.jwksURL, jwkfetch.WithWaitReady(false))
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
