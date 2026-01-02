package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log"
	"net/http"
	"time"

	"ch0wdreN/oauth-example/extension"
	memoryclient "ch0wdreN/oauth-example/store/memory_client"
	"ch0wdreN/oauth-example/store/valkey"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/token/jwt"
)

var (
	secret = []byte("some-cool-secret-that-is-32bytes")
	config = &fosite.Config{
		AccessTokenLifespan: time.Minute * 30,
		GlobalSecret:        secret,
	}
	privateKey = mustGenerateKey()
)

func mustGenerateKey() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return key
}

func main() {
	ctx := context.Background()

	jwtStrategy := compose.NewOAuth2JWTStrategy(
		func(_ context.Context) (interface{}, error) {
			return privateKey, nil
		},
		compose.NewOAuth2HMACStrategy(config),
		config,
	)

	memoryStore := memoryclient.NewMemoryClientStore()
	valkeyConfig, err := valkey.NewValkeyConfig()
	if err != nil {
		log.Fatal(err)
		return
	}
	valkeyClient, err := valkey.NewValkeyClient(ctx, valkeyConfig)
	if err != nil {
		log.Fatal(err)
		return
	}

	valkeyAuthorizeCodeStorage := valkey.NewValkeyAuthorizeCodeStorage(valkeyClient, memoryStore)
	valkeyAccessTokenStorage := valkey.NewValkeyAccessTokenStorage(valkeyClient, memoryStore, config.GetAccessTokenLifespan(ctx))
	valkeyRefreshTokenStorage := valkey.NewValkeyRefreshTokenStorage(valkeyClient, config.GetRefreshTokenLifespan(ctx))
	valkeyTokenRevocationStorage := valkey.NewValkeyTokenRevocationStorage(valkeyClient, valkeyAccessTokenStorage, valkeyRefreshTokenStorage)

	type Store struct {
		*memoryclient.MemoryClientStore
		*valkey.ValkeyAccessTokenStorage
		*valkey.ValkeyAuthorizeCodeStorage
		*valkey.ValkeyRefreshTokenStorage
		*valkey.ValkeyTokenRevocationStorage
	}

	store := &Store{
		MemoryClientStore:            memoryStore,
		ValkeyAccessTokenStorage:     valkeyAccessTokenStorage,
		ValkeyAuthorizeCodeStorage:   valkeyAuthorizeCodeStorage,
		ValkeyRefreshTokenStorage:    valkeyRefreshTokenStorage,
		ValkeyTokenRevocationStorage: valkeyTokenRevocationStorage,
	}

	provider := compose.Compose(
		config,
		store,
		jwtStrategy,
		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2RefreshTokenGrantFactory,
		compose.OAuth2TokenRevocationFactory,

		extension.SecurityTokenObtainHandlerFactory,
		extension.TokenExchangeHandlerFactory,
	)

	http.HandleFunc("/oauth2/authorization", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		ar, err := provider.NewAuthorizeRequest(ctx, r)
		if err != nil {
			log.Printf("Error occurred in NewAuthorizeRequest: %+v", err)
			provider.WriteAuthorizeError(ctx, w, ar, err)
			return
		}

		// Grant all requested scopes
		for _, scope := range ar.GetRequestedScopes() {
			ar.GrantScope(scope)
		}

		mySessionData := &oauth2.JWTSession{
			JWTClaims: &jwt.JWTClaims{
				Issuer:    "https://my-oauth-server.com",
				Subject:   "peter",
				Audience:  []string{ar.GetClient().GetID()},
				ExpiresAt: time.Now().Add(time.Hour),
				IssuedAt:  time.Now(),
			},
			JWTHeader: &jwt.Headers{
				Extra: make(map[string]any),
			},
		}

		response, err := provider.NewAuthorizeResponse(ctx, ar, mySessionData)
		if err != nil {
			log.Printf("Error occurred in NewAuthorizeResponse: %+v", err)
			provider.WriteAuthorizeError(ctx, w, ar, err)
			return
		}

		provider.WriteAuthorizeResponse(ctx, w, ar, response)
	})

	http.HandleFunc("/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		mySessionData := &oauth2.JWTSession{}

		accessRequest, err := provider.NewAccessRequest(ctx, r, mySessionData)
		if err != nil {
			log.Printf("Error occurred in NewAccessRequest: %+v", err)
			provider.WriteAccessError(ctx, w, accessRequest, err)
			return
		}

		response, err := provider.NewAccessResponse(ctx, accessRequest)
		if err != nil {
			log.Printf("Error occurred in NewAccessResponse: %+v", err)
			provider.WriteAccessError(ctx, w, accessRequest, err)
			return
		}

		provider.WriteAccessResponse(ctx, w, accessRequest, response)
	})

	http.HandleFunc("/oauth2/revoke", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		err := provider.NewRevocationRequest(ctx, r)
		if err != nil {
			log.Printf("Error occurred in NewRevocationRequest: %+v", err)
			provider.WriteRevocationResponse(ctx, w, err)
			return
		}

		provider.WriteRevocationResponse(ctx, w, nil)
	})

	fmt.Println("OAuth2 server is running on :8080")
	fmt.Println("  - Authorization endpoint: http://localhost:8080/oauth2/authorization")
	fmt.Println("  - Token endpoint: http://localhost:8080/oauth2/token")
	fmt.Println("  - Revoke endpoint: http://localhost:8080/oauth2/revoke")

	log.Fatal(http.ListenAndServe(":8080", nil))
}
