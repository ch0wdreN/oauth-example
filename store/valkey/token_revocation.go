package valkey

import (
	"context"

	json "github.com/goccy/go-json"
	"github.com/ory/fosite/handler/oauth2"
)

type ValkeyTokenRevocationStorage struct {
	client *ValkeyClient
	oauth2.AccessTokenStorage
	oauth2.RefreshTokenStorage
}

func NewValkeyTokenRevocationStorage(client *ValkeyClient, accessTokenStorage oauth2.AccessTokenStorage, refreshTokenStorage oauth2.RefreshTokenStorage) *ValkeyTokenRevocationStorage {
	return &ValkeyTokenRevocationStorage{
		client:              client,
		AccessTokenStorage:  accessTokenStorage,
		RefreshTokenStorage: refreshTokenStorage,
	}
}

var _ oauth2.TokenRevocationStorage = &ValkeyTokenRevocationStorage{}

// RevokeAccessToken implements oauth2.TokenRevocationStorage.
func (v *ValkeyTokenRevocationStorage) RevokeAccessToken(ctx context.Context, requestID string) error {
	// Lookup signature from requestID index
	indexKey := accessTokenRequestIDKey(requestID)
	cmd := v.client.B().Get().Key(indexKey).Build()

	signature, err := v.client.Do(ctx, cmd).ToString()
	if err != nil {
		// If the index doesn't exist, the token was already revoked or never existed
		// This is not an error condition for revocation
		return nil
	}

	// Delete the actual token using the existing method
	return v.AccessTokenStorage.DeleteAccessTokenSession(ctx, signature)
}

// RevokeRefreshToken implements oauth2.TokenRevocationStorage.
func (v *ValkeyTokenRevocationStorage) RevokeRefreshToken(ctx context.Context, requestID string) error {
	// Lookup signature from requestID index
	indexKey := refreshTokenRequestIDKey(requestID)
	cmd := v.client.B().Get().Key(indexKey).Build()

	signature, err := v.client.Do(ctx, cmd).ToString()
	if err != nil {
		// If the index doesn't exist, the token was already revoked or never existed
		// This is not an error condition for revocation
		return nil
	}

	// Get the existing refresh token
	key := refreshTokenKey(signature)
	getCmd := v.client.B().Get().Key(key).Build()

	result, err := v.client.Do(ctx, getCmd).AsReader()
	if err != nil {
		// Token doesn't exist, already expired or revoked
		return nil
	}

	var stored storeRefreshToken
	if err := json.NewDecoder(result).Decode(&stored); err != nil {
		return err
	}

	// Mark as inactive
	stored.active = false

	data, err := json.Marshal(&stored)
	if err != nil {
		return err
	}

	// Save back with the same TTL
	// Note: We get the remaining TTL to preserve it
	ttlCmd := v.client.B().Ttl().Key(key).Build()
	ttl, err := v.client.Do(ctx, ttlCmd).AsInt64()
	if err != nil || ttl <= 0 {
		// If TTL check fails or token expired, just return
		return nil
	}

	setCmd := v.client.B().Set().Key(key).Value(string(data)).ExSeconds(ttl).Build()
	if err := v.client.Do(ctx, setCmd).Error(); err != nil {
		return err
	}

	return nil
}
