package memoryclient

import (
	"context"
	"sync"
	"time"

	"github.com/ory/fosite"
)

type MemoryClientStore struct {
	clients     map[string]fosite.Client
	clientMutex sync.RWMutex
}

var _ fosite.ClientManager = &MemoryClientStore{}

func NewMemoryClientStore() *MemoryClientStore {
	return &MemoryClientStore{
		clients: map[string]fosite.Client{
			"service-a": &fosite.DefaultClient{
				ID:            "service-a",
				Secret:        []byte("$2a$10$IxMdI6d.LIRZPpSfEwNoeu4rY3FhDREsxFJXikcgdRRAStxUlsuEO"),
				RedirectURIs:  []string{"http://localhost:3000/callback", "http://localhost:8080/"},
				GrantTypes:    fosite.Arguments{"authorization_code", "refresh_token", "urn:your-company:params:oauth:grant-type:security-token-obtain"},
				ResponseTypes: fosite.Arguments{"code", "token"},
				Scopes:        []string{"fosite", "read", "write", "offline"},
			},
			"service-b": &fosite.DefaultClient{
				ID:            "service-b",
				Secret:        []byte("$2a$10$IxMdI6d.LIRZPpSfEwNoeu4rY3FhDREsxFJXikcgdRRAStxUlsuEO"),
				RedirectURIs:  []string{"http://localhost:3001/callback"},
				GrantTypes:    fosite.Arguments{"authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:token-exchange"},
				ResponseTypes: fosite.Arguments{"code", "token"},
				Scopes:        []string{"fosite", "read", "write", "offline"},
			},
		},
		clientMutex: sync.RWMutex{},
	}
}

// ClientAssertionJWTValid implements fosite.ClientManager.
func (m *MemoryClientStore) ClientAssertionJWTValid(ctx context.Context, jti string) error {
	// TODO
	return nil
}

// GetClient implements fosite.ClientManager.
func (m *MemoryClientStore) GetClient(_ context.Context, id string) (fosite.Client, error) {
	m.clientMutex.RLock()
	defer m.clientMutex.RUnlock()

	client, ok := m.clients[id]
	if !ok {
		return nil, fosite.ErrNotFound
	}

	return client, nil
}

// SetClientAssertionJWT implements fosite.ClientManager.
func (m *MemoryClientStore) SetClientAssertionJWT(_ context.Context, jti string, exp time.Time) error {
	// TODO
	return nil
}
