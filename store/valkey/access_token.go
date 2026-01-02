package valkey

import (
	"context"
	"fmt"
	"time"

	json "github.com/goccy/go-json"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/valkey-io/valkey-go"
)

type ValkeyAccessTokenStorage struct {
	client *ValkeyClient
	fosite.ClientManager
	accessTokenLifespan time.Duration
}

var _ oauth2.AccessTokenStorage = &ValkeyAccessTokenStorage{}

// NewValkeyAccessTokenStorage creates a new ValkeyAccessTokenStorage
func NewValkeyAccessTokenStorage(client *ValkeyClient, clientManager fosite.ClientManager, accessTokenLifespan time.Duration) *ValkeyAccessTokenStorage {
	return &ValkeyAccessTokenStorage{
		client:              client,
		ClientManager:       clientManager,
		accessTokenLifespan: accessTokenLifespan,
	}
}

// CreateAccessTokenSession implements oauth2.AccessTokenStorage.
func (v *ValkeyAccessTokenStorage) CreateAccessTokenSession(ctx context.Context, signature string, request fosite.Requester) (err error) {
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
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	key := accessTokenKey(signature)
	cmd := v.client.B().Set().Key(key).Value(string(data)).Ex(v.accessTokenLifespan).Build()

	if err := v.client.Do(ctx, cmd).Error(); err != nil {
		return fmt.Errorf("failed to set access token: %w", err)
	}

	clientKey := accessTokenClientKey(signature)
	cmd = v.client.B().Set().Key(clientKey).Value(request.GetClient().GetID()).Ex(v.accessTokenLifespan).Build()

	if err := v.client.Do(ctx, cmd).Error(); err != nil {
		return fmt.Errorf("failed to set access token client ID: %w", err)
	}

	// Create secondary index: requestID -> signature
	requestID := request.GetID()
	indexKey := accessTokenRequestIDKey(requestID)
	indexCmd := v.client.B().Set().Key(indexKey).Value(signature).Ex(v.accessTokenLifespan).Build()

	if err := v.client.Do(ctx, indexCmd).Error(); err != nil {
		return fmt.Errorf("failed to set access token requestID index: %w", err)
	}

	return nil
}

// DeleteAccessTokenSession implements oauth2.AccessTokenStorage.
func (v *ValkeyAccessTokenStorage) DeleteAccessTokenSession(ctx context.Context, signature string) (err error) {
	key := accessTokenKey(signature)
	cmd := v.client.B().Del().Key(key).Build()

	if err := v.client.Do(ctx, cmd).Error(); err != nil {
		return fmt.Errorf("failed to delete access token: %w", err)
	}

	return nil
}

// GetAccessTokenSession implements oauth2.AccessTokenStorage.
func (v *ValkeyAccessTokenStorage) GetAccessTokenSession(ctx context.Context, signature string, session fosite.Session) (request fosite.Requester, err error) {
	key := accessTokenKey(signature)
	cmd := v.client.B().Get().Key(key).Build()

	result, err := v.client.Do(ctx, cmd).AsReader()
	if valkey.IsValkeyNil(err) {
		return nil, fosite.ErrNotFound
	}
	if err != nil {
		// Check if key not found
		return nil, fmt.Errorf("failed to get access token: %w", err)
	}

	var req fosite.Request
	if err := json.NewDecoder(result).Decode(&req); err != nil {
		return nil, fmt.Errorf("failed to unmarshal request: %w", err)
	}

	// Restore session if provided
	if session != nil {
		req.Session = session
	}

	clientKey := accessTokenClientKey(signature)
	cmd = v.client.B().Get().Key(clientKey).Build()
	clientResult, err := v.client.Do(ctx, cmd).AsBytes()
	if valkey.IsValkeyNil(err) {
		return nil, fosite.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get access token client ID: %w", err)
	}
	clientID := string(clientResult)

	client, err := v.GetClient(ctx, clientID)
	if err != nil {
		return nil, err
	}

	req.Client = client

	return &req, nil
}
