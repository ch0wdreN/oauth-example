package valkey

import (
	"context"
	"fmt"

	"github.com/caarlos0/env/v11"
	"github.com/valkey-io/valkey-go"
)

type ValkeyClient struct {
	valkey.Client
}

type ValkeyConfig struct {
	Address  string `env:"VALKEY_ADDRESS,required"`
	Username string `env:"VALKEY_USERNAME"`
	Password string `env:"VALKEY_PASSWORD"`
	DB       int    `env:"VALKEY_DB" envDefault:"0"`
}

func NewValkeyConfig() (*ValkeyConfig, error) {
	cfg := &ValkeyConfig{}
	if err := env.Parse(cfg); err != nil {
		return nil, fmt.Errorf("failed to parse env config: %w", err)
	}
	return cfg, nil
}

// NewValkeyClient creates a new Valkey-based storage
func NewValkeyClient(ctx context.Context, cfg *ValkeyConfig) (*ValkeyClient, error) {
	client, err := valkey.NewClient(valkey.ClientOption{
		InitAddress: []string{cfg.Address},
		Username:    cfg.Username,
		Password:    cfg.Password,
		SelectDB:    cfg.DB,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create valkey client: %w", err)
	}

	// Test connection
	if err := client.Do(ctx, client.B().Ping().Build()).Error(); err != nil {
		client.Close()
		return nil, fmt.Errorf("failed to connect to valkey: %w", err)
	}

	return &ValkeyClient{
		client,
	}, nil
}

func (s *ValkeyClient) Close() {
	s.Close()
}
