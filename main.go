package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"time"

	"ch0wdreN/oauth-example/extension"
	memoryclient "ch0wdreN/oauth-example/store/memory_client"
	"ch0wdreN/oauth-example/store/valkey"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/token/jwt"
	kratosclient "github.com/ory/kratos-client-go"
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

func newProvider(ctx context.Context) (fosite.OAuth2Provider, error) {
	jwtStrategy := compose.NewOAuth2JWTStrategy(
		func(_ context.Context) (any, error) {
			return privateKey, nil
		},
		compose.NewOAuth2HMACStrategy(config),
		config,
	)

	memoryStore := memoryclient.NewMemoryClientStore()
	valkeyConfig, err := valkey.NewValkeyConfig()
	if err != nil {
		return nil, err
	}
	valkeyClient, err := valkey.NewValkeyClient(ctx, valkeyConfig)
	if err != nil {
		return nil, err
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

	return compose.Compose(
		config,
		store,
		jwtStrategy,
		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2RefreshTokenGrantFactory,
		compose.OAuth2TokenRevocationFactory,

		extension.SecurityTokenObtainHandlerFactory,
		extension.TokenExchangeHandlerFactory,
	), nil
}

type authorizer struct {
	provider  fosite.OAuth2Provider
	apiClient *kratosclient.APIClient
}

func (a *authorizer) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	cookie := r.Header.Get("Cookie")

	req := a.apiClient.FrontendAPI.ToSession(ctx).Cookie(cookie)
	session, _, err := req.Execute()
	if err != nil {
		slog.ErrorContext(ctx, "error occurred ToSession api call", slog.Any("error", err))
		http.Redirect(w, r, "http://localhost:8080/error.html", http.StatusFound)
		return
	}

	extraAttributes := make(map[string]any)

	if v, ok := session.Identity.Traits.(map[string]string); ok {
		if email, exist := v["email"]; exist {
			extraAttributes["email"] = email
		}
	}

	ar, err := a.provider.NewAuthorizeRequest(ctx, r)
	if err != nil {
		slog.ErrorContext(ctx, "error occurred NewAuthorizeRequest", slog.Any("error", err))
		a.provider.WriteAuthorizeError(ctx, w, ar, err)
		return
	}

	// Grant all requested scopes
	for _, scope := range ar.GetRequestedScopes() {
		ar.GrantScope(scope)
	}

	jwtSession := &oauth2.JWTSession{
		JWTClaims: &jwt.JWTClaims{
			Issuer:    "https://my-oauth-server.com",
			Subject:   session.Identity.Id,
			Audience:  []string{ar.GetClient().GetID()},
			ExpiresAt: time.Now().Add(time.Hour),
			IssuedAt:  time.Now(),
			Extra:     extraAttributes,
		},
		JWTHeader: &jwt.Headers{},
		Subject:   session.Identity.Id,
	}

	response, err := a.provider.NewAuthorizeResponse(ctx, ar, jwtSession)
	if err != nil {
		slog.ErrorContext(ctx, "error occurred NewAuthorizeResponse", slog.Any("error", err))
		a.provider.WriteAuthorizeError(ctx, w, ar, err)
		return
	}

	a.provider.WriteAuthorizeResponse(ctx, w, ar, response)
}

func (a *authorizer) handleToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	session := new(oauth2.JWTSession)

	accessRequest, err := a.provider.NewAccessRequest(ctx, r, session)
	if err != nil {
		log.Printf("Error occurred in NewAccessRequest: %+v", err)
		a.provider.WriteAccessError(ctx, w, accessRequest, err)
		return
	}

	response, err := a.provider.NewAccessResponse(ctx, accessRequest)
	if err != nil {
		log.Printf("Error occurred in NewAccessResponse: %+v", err)
		a.provider.WriteAccessError(ctx, w, accessRequest, err)
		return
	}

	a.provider.WriteAccessResponse(ctx, w, accessRequest, response)
}

func (a *authorizer) handleRevoke(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	err := a.provider.NewRevocationRequest(ctx, r)
	if err != nil {
		log.Printf("Error occurred in NewRevocationRequest: %+v", err)
		a.provider.WriteRevocationResponse(ctx, w, err)
		return
	}

	a.provider.WriteRevocationResponse(ctx, w, nil)
}

func newAuthorizer(provider fosite.OAuth2Provider) *authorizer {
	config := kratosclient.NewConfiguration()
	config.Servers = kratosclient.ServerConfigurations{
		{
			URL: "http://127.0.0.1:4433",
		},
	}
	apiClient := kratosclient.NewAPIClient(config)

	return &authorizer{
		provider:  provider,
		apiClient: apiClient,
	}
}

type app struct {
	*chi.Mux
	authorizer *authorizer
}

func newApp(authorizer *authorizer) *app {
	mux := chi.NewRouter()
	mux.Use(middleware.Logger)
	mux.Use(middleware.Recoverer)
	mux.Use(middleware.RequestID)

	mux.HandleFunc("/oauth2/authorization", authorizer.handleAuthorize)
	mux.HandleFunc("/oauth2/token", authorizer.handleToken)
	mux.HandleFunc("/oauth2/revoke", authorizer.handleRevoke)

	// demo page
	mux.Handle("/*", http.FileServer(http.Dir("static")))

	return &app{
		authorizer: authorizer,
		Mux:        mux,
	}
}

func main() {
	ctx := context.Background()

	provider, err := newProvider(ctx)
	if err != nil {
		slog.ErrorContext(ctx, "failed to create OAuth2Provider", slog.Any("error", err))
		return
	}

	authorizer := newAuthorizer(provider)
	app := newApp(authorizer)

	fmt.Println("OAuth2 server is running on :8080")
	fmt.Println("  - Authorization endpoint: http://localhost:8080/oauth2/authorization")
	fmt.Println("  - Token endpoint: http://localhost:8080/oauth2/token")
	fmt.Println("  - Revoke endpoint: http://localhost:8080/oauth2/revoke")

	log.Fatal(http.ListenAndServe(":8080", app))
}
