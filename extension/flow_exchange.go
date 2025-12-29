package extension

import (
	"context"
	"encoding/base64"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/x/errorsx"
)

type tokenExchangeTokenRevocationStorage interface {
	oauth2.TokenRevocationStorage
}

type tokenExchangeHandler struct {
	AccessTokenStrategy    oauth2.AccessTokenStrategy
	AccessTokenStorage     oauth2.AccessTokenStorage
	RefreshTokenStrategy   oauth2.RefreshTokenStrategy
	TokenRevocationStorage tokenExchangeTokenRevocationStorage
	Config                 fosite.Configurator
	ClientManager          fosite.ClientManager
}

var _ fosite.TokenEndpointHandler = &tokenExchangeHandler{}

// TokenExchangeHandlerFactory implements compose.Factory.
func TokenExchangeHandlerFactory(config fosite.Configurator, storage interface{}, strategy interface{}) interface{} {
	return &tokenExchangeHandler{
		AccessTokenStrategy:    strategy.(oauth2.AccessTokenStrategy),
		AccessTokenStorage:     storage.(oauth2.AccessTokenStorage),
		RefreshTokenStrategy:   strategy.(oauth2.RefreshTokenStrategy),
		TokenRevocationStorage: storage.(tokenExchangeTokenRevocationStorage),
		Config:                 config,
		ClientManager:          storage.(fosite.ClientManager),
	}
}

// CanHandleTokenEndpointRequest implements fosite.TokenEndpointHandler.
func (t *tokenExchangeHandler) CanHandleTokenEndpointRequest(ctx context.Context, requester fosite.AccessRequester) bool {
	return requester.GetGrantTypes().Has("urn:ietf:params:oauth:grant-type:token-exchange")
}

// CanSkipClientAuth implements fosite.TokenEndpointHandler.
func (t *tokenExchangeHandler) CanSkipClientAuth(ctx context.Context, requester fosite.AccessRequester) bool {
	// TODO
	return true
}

// HandleTokenEndpointRequest implements fosite.TokenEndpointHandler.
func (t *tokenExchangeHandler) HandleTokenEndpointRequest(ctx context.Context, requester fosite.AccessRequester) error {
	form := requester.GetRequestForm()

	subjectToken := form.Get("subject_token")
	if subjectToken == "" {
		return errorsx.WithStack(fosite.ErrInvalidRequest.WithHint("subject_token is required"))
	}

	subjectTokenType := form.Get("subject_token_type")
	if subjectTokenType == "" {
		return errorsx.WithStack(fosite.ErrInvalidRequest.WithHint("subject_token_type is required"))
	}

	switch subjectTokenType {
	case "urn:ietf:params:oauth:token-type:access_token",
		"urn:ietf:params:oauth:token-type:refresh_token",
		"urn:ietf:params:oauth:token-type:id_token",
		"urn:ietf:params:oauth:token-type:saml1",
		"urn:ietf:params:oauth:token-type:saml2",
		"urn:ietf:params:oauth:token-type:jwt",
		"urn:your-company:params:oauth:token-type:security-token":
		// TODO
	default:
		return errorsx.WithStack(fosite.ErrInvalidRequest.WithHint("unsupported subject_token_type"))
	}

	requestedTokenType := form.Get("requested_token_type")
	if requestedTokenType != "" {
		switch requestedTokenType {
		case "urn:ietf:params:oauth:token-type:access_token",
			"urn:ietf:params:oauth:token-type:refresh_token":
			// TODO
		default:
			return errorsx.WithStack(fosite.ErrInvalidRequest.WithHint("unsupported requested_token_type"))
		}
	}

	audience := form.Get("audience")
	if len(audience) > 0 {
		// TODO: audienceの検証ロジックを実装
	}

	requestedScope := form.Get("scope")
	if requestedScope != "" {
		// TODO: スコープの検証ロジックを実装
	}

	// TODO: subject_tokenの検証

	return nil
}

// PopulateTokenEndpointResponse implements fosite.TokenEndpointHandler.
func (t *tokenExchangeHandler) PopulateTokenEndpointResponse(ctx context.Context, requester fosite.AccessRequester, responder fosite.AccessResponder) error {
	if !t.CanHandleTokenEndpointRequest(ctx, requester) {
		return errorsx.WithStack(fosite.ErrUnknownRequest)
	}

	form := requester.GetRequestForm()

	// Step 1: Decode subject_token (base64) to get audience
	subjectToken := form.Get("subject_token")
	if subjectToken == "" {
		return errorsx.WithStack(fosite.ErrInvalidRequest.WithHint("subject_token is required"))
	}

	// Decode base64 subject_token to get audience
	decodedBytes, err := base64.RawURLEncoding.DecodeString(subjectToken)
	if err != nil {
		return errorsx.WithStack(
			fosite.ErrInvalidRequest.
				WithHint("subject_token must be a valid base64 encoded string").
				WithWrap(err).
				WithDebug(err.Error()),
		)
	}

	tokenAudience := string(decodedBytes)

	// Step 2: Get and validate the request audience parameter
	requestedAudience := form.Get("audience")
	if requestedAudience == "" {
		return errorsx.WithStack(fosite.ErrInvalidRequest.WithHint("audience is required for token exchange"))
	}

	// Step 3: Verify audience matching (完全一致を要求)
	if tokenAudience != requestedAudience {
		return errorsx.WithStack(
			fosite.ErrAccessDenied.
				WithHint("subject_token audience does not match requested audience"),
		)
	}

	// Step 4: Resolve target client from storage using audience as client ID
	targetClient, err := t.ClientManager.GetClient(ctx, requestedAudience)
	if err != nil {
		return errorsx.WithStack(
			fosite.ErrInvalidRequest.
				WithHint("Unable to find client for requested audience").
				WithWrap(err).
				WithDebug(err.Error()),
		)
	}

	if targetClient == nil {
		return errorsx.WithStack(
			fosite.ErrInvalidRequest.WithHint("Client not found for requested audience"),
		)
	}

	// Step 5: Create new session for target client
	newSession := requester.GetSession().Clone()

	// Step 6: Create new requester for target client
	newRequester := fosite.NewAccessRequest(newSession)
	newRequester.SetRequestedScopes(requester.GetRequestedScopes())
	newRequester.SetRequestedAudience([]string{requestedAudience})

	// CRITICAL: Set target client (Service B) here
	// This is the key difference - we use targetClient instead of requester.GetClient()
	newRequester.Client = targetClient

	// Step 7: Grant scopes and audience
	for _, scope := range requester.GetGrantedScopes() {
		newRequester.GrantScope(scope)
	}
	newRequester.GrantAudience(requestedAudience)

	// 新しいaccess tokenを生成
	accessToken, accessSignature, err := t.AccessTokenStrategy.GenerateAccessToken(ctx, newRequester)
	if err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	// 新しいrefresh tokenを生成
	refreshToken, refreshSignature, err := t.RefreshTokenStrategy.GenerateRefreshToken(ctx, newRequester)
	if err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	// (sub, audience)で既存のrefresh tokenをローテーション
	// if err := t.TokenRevocationStorage.RotateRefreshTokenBySubjectAndAudience(ctx, sub, audience, refreshSignature, newRequester.Sanitize([]string{})); err != nil {
	// 	return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	// }

	// access tokenセッションを保存
	if err := t.AccessTokenStorage.CreateAccessTokenSession(ctx, accessSignature, newRequester.Sanitize([]string{})); err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	// refresh tokenセッションを保存
	if err := t.TokenRevocationStorage.CreateRefreshTokenSession(ctx, refreshSignature, accessSignature, newRequester.Sanitize([]string{})); err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	// レスポンスを設定
	responder.SetAccessToken(accessToken)
	responder.SetTokenType("Bearer")
	responder.SetExpiresIn(t.Config.GetAccessTokenLifespan(ctx))
	responder.SetExtra("refresh_token", refreshToken)
	responder.SetExtra("issued_token_type", "urn:ietf:params:oauth:token-type:access_token")

	return nil
}
