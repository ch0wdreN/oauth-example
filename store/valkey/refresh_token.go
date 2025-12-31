package valkey

import (
	"context"
	"time"

	json "github.com/goccy/go-json"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
)

type ValkeyRefreshTokenStorage struct {
	client               *ValkeyClient
	refreshTokenLifespan time.Duration
}

var _ oauth2.RefreshTokenStorage = &ValkeyRefreshTokenStorage{}

func NewValkeyRefreshTokenStorage(client *ValkeyClient, refreshTokenLifespan time.Duration) *ValkeyRefreshTokenStorage {
	return &ValkeyRefreshTokenStorage{
		client:               client,
		refreshTokenLifespan: refreshTokenLifespan,
	}
}

type storeRefreshToken struct {
	active               bool
	accessTokenSignature string
	fosite.Requester
}

// CreateRefreshTokenSession implements oauth2.RefreshTokenStorage.
func (v *ValkeyRefreshTokenStorage) CreateRefreshTokenSession(ctx context.Context, signature string, accessSignature string, request fosite.Requester) (err error) {
	data, err := json.Marshal(&storeRefreshToken{
		active:               true,
		accessTokenSignature: accessSignature,
		Requester:            request,
	})
	if err != nil {
		return err
	}

	key := refreshTokenKey(signature)
	cmd := v.client.B().Set().Key(key).Value(string(data)).Ex(v.refreshTokenLifespan).Build()

	if err := v.client.Do(ctx, cmd).Error(); err != nil {
		return err
	}

	// Create secondary index: requestID -> signature
	requestID := request.GetID()
	indexKey := refreshTokenRequestIDKey(requestID)
	indexCmd := v.client.B().Set().Key(indexKey).Value(signature).Ex(v.refreshTokenLifespan).Build()

	if err := v.client.Do(ctx, indexCmd).Error(); err != nil {
		return err
	}

	return nil
}

// DeleteRefreshTokenSession implements oauth2.RefreshTokenStorage.
func (v *ValkeyRefreshTokenStorage) DeleteRefreshTokenSession(ctx context.Context, signature string) (err error) {
	key := refreshTokenKey(signature)
	cmd := v.client.B().Del().Key(key).Build()

	if err := v.client.Do(ctx, cmd).Error(); err != nil {
		return err
	}

	return nil
}

// GetRefreshTokenSession implements oauth2.RefreshTokenStorage.
func (v *ValkeyRefreshTokenStorage) GetRefreshTokenSession(ctx context.Context, signature string, session fosite.Session) (request fosite.Requester, err error) {
	key := refreshTokenKey(signature)
	cmd := v.client.B().Get().Key(key).Build()

	result, err := v.client.Do(ctx, cmd).AsReader()
	if err != nil {
		return nil, err
	}

	var stored storeRefreshToken
	if err := json.NewDecoder(result).Decode(&stored); err != nil {
		return nil, err
	}

	if !stored.active {
		return nil, fosite.ErrNotFound
	}

	return stored.Requester, nil
}

// RotateRefreshToken implements oauth2.RefreshTokenStorage.
func (v *ValkeyRefreshTokenStorage) RotateRefreshToken(ctx context.Context, requestID string, refreshTokenSignature string) (err error) {
	// first, we need to get the existing refresh token
	key := refreshTokenKey(refreshTokenSignature)
	cmd := v.client.B().Get().Key(key).Build()

	result, err := v.client.Do(ctx, cmd).AsReader()
	if err != nil {
		return err
	}

	var stored storeRefreshToken
	if err := json.NewDecoder(result).Decode(&stored); err != nil {
		return err
	}

	// mark it as inactive
	stored.active = false

	data, err := json.Marshal(&stored)
	if err != nil {
		return err
	}

	// save it back
	cmd = v.client.B().Set().Key(key).Value(string(data)).Ex(v.refreshTokenLifespan).Build()

	if err := v.client.Do(ctx, cmd).Error(); err != nil {
		return err
	}

	// second, we need to delete the associated access token
	accessTokenKey := accessTokenKey(stored.accessTokenSignature)
	delCmd := v.client.B().Del().Key(accessTokenKey).Build()

	if err := v.client.Do(ctx, delCmd).Error(); err != nil {
		return err
	}

	return nil
}
