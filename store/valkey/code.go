package valkey

import (
	"context"
	"fmt"
	"log/slog"

	json "github.com/goccy/go-json"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/valkey-io/valkey-go"
)

type ValkeyAuthorizeCodeStorage struct {
	client *ValkeyClient
	fosite.ClientManager
}

var _ oauth2.AuthorizeCodeStorage = &ValkeyAuthorizeCodeStorage{}

func NewValkeyAuthorizeCodeStorage(client *ValkeyClient, clientManager fosite.ClientManager) *ValkeyAuthorizeCodeStorage {
	return &ValkeyAuthorizeCodeStorage{
		client:        client,
		ClientManager: clientManager,
	}
}

// CreateAuthorizeCodeSession implements oauth2.AuthorizeCodeStorage.
func (v *ValkeyAuthorizeCodeStorage) CreateAuthorizeCodeSession(ctx context.Context, code string, request fosite.Requester) (err error) {
	req := fosite.Request{
		ID:                request.GetID(),
		RequestedAt:       request.GetRequestedAt(),
		RequestedScope:    request.GetRequestedScopes(),
		GrantedScope:      request.GetGrantedScopes(),
		Form:              request.GetRequestForm(),
		RequestedAudience: request.GetRequestedAudience(),
		GrantedAudience:   request.GetGrantedAudience(),
	}
	data, err := json.Marshal(req)
	if err != nil {
		return err
	}

	key := authorizeCodeKey(code)
	cmd := v.client.B().Set().Key(key).Value(string(data)).Build()

	if err := v.client.Do(ctx, cmd).Error(); err != nil {
		return err
	}

	var session oauth2.JWTSession
	if v, ok := request.GetSession().(*oauth2.JWTSession); ok {
		session = *v
	} else {
		return fmt.Errorf("failed to convert session")
	}

	data, err = json.Marshal(session)
	if err != nil {
		return fmt.Errorf("failed to marshal session: %w", err)
	}

	key = authorizeCodeSessionKey(code)
	cmd = v.client.B().Set().Key(key).Value(string(data)).Build()

	if err := v.client.Do(ctx, cmd).Error(); err != nil {
		return err
	}

	clientIDKey := authorizeCodeClientKey(code)
	cmd = v.client.B().Set().Key(clientIDKey).Value(request.GetClient().GetID()).Build()

	if err := v.client.Do(ctx, cmd).Error(); err != nil {
		return err
	}

	return nil
}

// GetAuthorizeCodeSession implements oauth2.AuthorizeCodeStorage.
func (v *ValkeyAuthorizeCodeStorage) GetAuthorizeCodeSession(ctx context.Context, code string, session fosite.Session) (request fosite.Requester, err error) {
	key := authorizeCodeKey(code)
	cmd := v.client.B().Get().Key(key).Build()

	result, err := v.client.Do(ctx, cmd).AsReader()
	if valkey.IsValkeyNil(err) {
		return nil, fosite.ErrInvalidatedAuthorizeCode
	}
	if err != nil {
		slog.ErrorContext(ctx, "error occurred", "error", err.Error())
		return nil, err
	}

	var req fosite.Request
	if err := json.NewDecoder(result).Decode(&req); err != nil {
		slog.ErrorContext(ctx, "error occurred", "error", err.Error())
		return nil, err
	}

	key = authorizeCodeSessionKey(code)
	cmd = v.client.B().Get().Key(key).Build()

	result, err = v.client.Do(ctx, cmd).AsReader()
	if valkey.IsValkeyNil(err) {
		return nil, fosite.ErrNotFound
	}
	if err != nil {
		// Check if key not found
		return nil, fmt.Errorf("failed to get access token: %w", err)
	}

	if err := json.NewDecoder(result).Decode(session); err != nil {
		return nil, fmt.Errorf("failed to unmarshal request: %w", err)
	}

	req.SetSession(session)

	var clientID string
	key = authorizeCodeClientKey(code)
	cmd = v.client.B().Get().Key(key).Build()
	clientResult, err := v.client.Do(ctx, cmd).AsBytes()
	if valkey.IsValkeyNil(err) {
		return nil, fosite.ErrInvalidatedAuthorizeCode
	}
	if err != nil {
		slog.ErrorContext(ctx, "error occurred", "error", err.Error())
		return nil, err
	}
	clientID = string(clientResult)

	client, err := v.GetClient(ctx, clientID)
	if err != nil {
		slog.ErrorContext(ctx, "error occurred", "error", err.Error())
		return nil, err
	}
	req.Client = client

	return &req, nil
}

// InvalidateAuthorizeCodeSession implements oauth2.AuthorizeCodeStorage.
func (v *ValkeyAuthorizeCodeStorage) InvalidateAuthorizeCodeSession(ctx context.Context, code string) (err error) {
	key := authorizeCodeKey(code)
	cmd := v.client.B().Del().Key(key).Build()

	if err := v.client.Do(ctx, cmd).Error(); err != nil {
		return err
	}

	return nil
}
