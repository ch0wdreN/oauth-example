package extension

import (
	"context"
	"encoding/base64"
	"log/slog"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/x/errorsx"
)

type securityTokenObtainHandler struct {
	AccessTokenStrategy oauth2.AccessTokenStrategy
	AccessTokenStorage  oauth2.AccessTokenStorage
	Config              fosite.Configurator
}

func SecurityTokenObtainHandlerFactory(config fosite.Configurator, storage interface{}, strategy interface{}) interface{} {
	return &securityTokenObtainHandler{
		AccessTokenStrategy: strategy.(oauth2.AccessTokenStrategy),
		AccessTokenStorage:  storage.(oauth2.AccessTokenStorage),
		Config:              config,
	}
}

var _ fosite.TokenEndpointHandler = &securityTokenObtainHandler{}

// CanHandleTokenEndpointRequest implements fosite.TokenEndpointHandler.
func (t *securityTokenObtainHandler) CanHandleTokenEndpointRequest(ctx context.Context, requester fosite.AccessRequester) bool {
	return requester.GetGrantTypes().Has("urn:your-company:params:oauth:grant-type:security-token-obtain")
}

// CanSkipClientAuth implements fosite.TokenEndpointHandler.
func (t *securityTokenObtainHandler) CanSkipClientAuth(ctx context.Context, requester fosite.AccessRequester) bool {
	// TODO
	return true
}

// HandleTokenEndpointRequest implements fosite.TokenEndpointHandler.
func (t *securityTokenObtainHandler) HandleTokenEndpointRequest(ctx context.Context, requester fosite.AccessRequester) error {
	slog.Debug("HandleTokenEndpointRequest called for obtain flow")
	form := requester.GetRequestForm()

	accessToken := form.Get("access_token")
	if accessToken == "" {
		return errorsx.WithStack(fosite.ErrInvalidRequest.WithHint("access_token is required"))
	}
	slog.Debug("access_token received", "token_prefix", accessToken[:min(10, len(accessToken))])

	signature := t.AccessTokenStrategy.AccessTokenSignature(ctx, accessToken)
	slog.Debug("Generated signature for access_token", "signature", signature)

	// Create a new session to populate with the stored data
	newSession := &oauth2.JWTSession{}

	originalRequester, err := t.AccessTokenStorage.GetAccessTokenSession(ctx, signature, newSession)
	if err != nil {
		slog.Error("Failed to get access token session", "error", err, "signature", signature)
		return errorsx.WithStack(fosite.ErrInvalidRequest.WithHint("invalid access_token").WithWrap(err).WithDebug(err.Error()))
	}
	slog.Debug("Successfully retrieved original access token session")

	if err := t.AccessTokenStrategy.ValidateAccessToken(ctx, originalRequester, accessToken); err != nil {
		slog.Error("Access token validation failed", "error", err)
		return errorsx.WithStack(fosite.ErrInvalidRequest.WithHint("access_token validation failed").WithWrap(err).WithDebug(err.Error()))
	}
	slog.Debug("Access token validated successfully")

	// Use the retrieved session from the original requester
	if originalSession := originalRequester.GetSession(); originalSession != nil {
		requester.SetSession(originalSession.Clone())
		slog.Debug("Session cloned and set to requester")
	}

	var audience []string
	if originalSession := originalRequester.GetSession(); originalSession != nil {
		if jwtSession, ok := originalSession.(*oauth2.JWTSession); ok {
			if jwtSession.JWTClaims != nil {
				audience = jwtSession.JWTClaims.Audience
				slog.Debug("Extracted audience from JWT claims", "audience", audience)
			}
		}
	}

	if len(audience) > 0 {
		for _, aud := range audience {
			requester.GrantAudience(aud)
		}
		slog.Debug("Granted audience to requester", "audience", audience)
	}

	return nil
}

// PopulateTokenEndpointResponse implements fosite.TokenEndpointHandler.
func (t *securityTokenObtainHandler) PopulateTokenEndpointResponse(ctx context.Context, requester fosite.AccessRequester, responder fosite.AccessResponder) error {
	if !t.CanHandleTokenEndpointRequest(ctx, requester) {
		return errorsx.WithStack(fosite.ErrUnknownRequest)
	}

	slog.Debug("PopulateTokenEndpointResponse called for obtain flow")
	form := requester.GetRequestForm()

	// 引き継ぎ先のクライアントを取得
	requestedAudience := form.Get("requested_audience")
	if requestedAudience == "" {
		slog.Error("requested_audience is missing")
		return errorsx.WithStack(fosite.ErrInvalidRequest.WithHint("requested_audience is required"))
	}
	slog.Debug("requested_audience received", "audience", requestedAudience)
	// TODO: 引き継ぎが許可されているか検証

	// TODO: セキュリティトークンの発行
	securityToken := base64.RawURLEncoding.EncodeToString([]byte(requestedAudience))
	responder.SetAccessToken(securityToken)
	responder.SetTokenType("urn:your-company:params:oauth:token-type:security-token")
	slog.Debug("Security token generated", "token", securityToken)

	return nil
}
