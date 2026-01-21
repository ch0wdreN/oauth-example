package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
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
		func(_ context.Context) (any, error) {
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
	type VerifiableAddress struct {
		ID         string     `json:"id"`
		Value      string     `json:"value"`
		Verified   bool       `json:"verified"`
		Via        string     `json:"via"`
		Status     string     `json:"status"`
		VerifiedAt *time.Time `json:"verified_at,omitempty"`
	}
	type KratosIdentity struct {
		ID                  string                 `json:"id"`
		SchemaID            string                 `json:"schema_id"`
		SchemaURL           string                 `json:"schema_url"`
		State               string                 `json:"state"`
		Traits              map[string]interface{} `json:"traits"`
		VerifiableAddresses []VerifiableAddress    `json:"verifiable_addresses,omitempty"`
	}

	type KratosSession struct {
		ID              string         `json:"id"`
		Active          bool           `json:"active"`
		ExpiresAt       time.Time      `json:"expires_at"`
		AuthenticatedAt time.Time      `json:"authenticated_at"`
		IssuedAt        time.Time      `json:"issued_at"`
		Identity        KratosIdentity `json:"identity"`
	}

	http.HandleFunc("/oauth2/authorization", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		cookie, err := r.Cookie("ory_kratos_session")
		if errors.Is(err, http.ErrNoCookie) {
			// not logined
			current := fmt.Sprintf("http://%s%s", r.Host, r.RequestURI)
			redirect := fmt.Sprintf("http://localhost:4433/self-service/login/browser?return_to=%s", url.QueryEscape(current))
			http.Redirect(w, r, redirect, http.StatusFound)
			return
		}
		if err != nil {
			http.Redirect(w, r, "http://localhost:8080/error.html", http.StatusFound)
			return
		}

		// whoami
		req, err := http.NewRequestWithContext(
			ctx,
			http.MethodGet,
			"http://localhost:4433/sessions/whoami",
			nil,
		)
		if err != nil {
			http.Redirect(w, r, "http://localhost:8080/error.html", http.StatusFound)
			return
		}
		req.AddCookie(cookie)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			http.Redirect(w, r, "http://localhost:8080/error.html", http.StatusFound)
			return
		}
		defer resp.Body.Close()

		var kratosSession KratosSession
		if err := json.NewDecoder(resp.Body).Decode(&kratosSession); err != nil {
			http.Redirect(w, r, "http://localhost:8080/error.html", http.StatusFound)
			return
		}

		extraAttributes := make(map[string]any)

		if email, exist := kratosSession.Identity.Traits["email"]; exist {
			extraAttributes["email"] = email
			fmt.Printf("email found: %s\n", email)
		}
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

		session := &oauth2.JWTSession{
			JWTClaims: &jwt.JWTClaims{
				Issuer:    "https://my-oauth-server.com",
				Subject:   kratosSession.Identity.ID,
				Audience:  []string{ar.GetClient().GetID()},
				ExpiresAt: time.Now().Add(time.Hour),
				IssuedAt:  time.Now(),
				Extra:     extraAttributes,
			},
			JWTHeader: &jwt.Headers{},
			Subject:   kratosSession.Identity.ID,
		}

		response, err := provider.NewAuthorizeResponse(ctx, ar, session)
		if err != nil {
			log.Printf("Error occurred in NewAuthorizeResponse: %+v", err)
			provider.WriteAuthorizeError(ctx, w, ar, err)
			return
		}

		provider.WriteAuthorizeResponse(ctx, w, ar, response)
	})

	http.HandleFunc("/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		session := new(oauth2.JWTSession)

		accessRequest, err := provider.NewAccessRequest(ctx, r, session)
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
	http.Handle("/", http.FileServer(http.Dir("./static")))

	fmt.Println("OAuth2 server is running on :8080")
	fmt.Println("  - Authorization endpoint: http://localhost:8080/oauth2/authorization")
	fmt.Println("  - Token endpoint: http://localhost:8080/oauth2/token")
	fmt.Println("  - Revoke endpoint: http://localhost:8080/oauth2/revoke")

	log.Fatal(http.ListenAndServe(":8080", nil))
}
