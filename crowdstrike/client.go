package crowdstrike

import (
	"context"
	"fmt"
	"os"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/turbot/steampipe-plugin-sdk/v3/plugin"
)

func getCrowdStrikeClient(ctx context.Context, d *plugin.QueryData) (*client.CrowdStrikeAPISpecification, error) {
	// Try to load client from cache
	if cachedData, ok := d.ConnectionManager.Cache.Get("crowdstrike"); ok {
		return cachedData.(*client.CrowdStrikeAPISpecification), nil
	}

	config := GetConfig(d.Connection)

	// Get client ID
	clientId := os.Getenv("FALCON_CLIENT_ID")
	if config.ClientId != nil {
		clientId = *config.ClientId
	}

	if len(clientId) == 0 {
		return nil, fmt.Errorf("client ID must be configured")
	}

	// Get client secret
	clientSecret := os.Getenv("FALCON_CLIENT_SECRET")
	if config.ClientSecret != nil {
		clientSecret = *config.ClientSecret
	}

	if len(clientSecret) == 0 {
		return nil, fmt.Errorf("client secret must be configured")
	}

	// Get cloud abbreviation
	clientCloud := os.Getenv("FALCON_CLOUD")
	if config.ClientCloud != nil {
		clientCloud = *config.ClientCloud
	}

	if len(clientCloud) == 0 {
		return nil, fmt.Errorf("client cloud must be configured")
	}

	// create the falcon client
	client, err := falcon.NewClient(&falcon.ApiConfig{
		ClientId:     clientId,
		ClientSecret: clientSecret,
		Cloud:        falcon.Cloud(clientCloud),
		Context:      context.Background(),
	})

	if err != nil {
		return nil, fmt.Errorf("error creating crowdstrike client: %s", err.Error())
	}

	// save client in cache
	d.ConnectionManager.Cache.Set("crowdstrike", client)

	return client, nil
}
