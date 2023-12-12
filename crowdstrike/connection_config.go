package crowdstrike

import (
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
)

type CrowdStrikeConfig struct {
	ClientCloud  *string `hcl:"client_cloud"`
	ClientId     *string `hcl:"client_id"`
	ClientSecret *string `hcl:"client_secret"`
}

func ConfigInstance() interface{} {
	return &CrowdStrikeConfig{}
}

func GetConfig(connection *plugin.Connection) CrowdStrikeConfig {
	if connection == nil || connection.Config == nil {
		return CrowdStrikeConfig{}
	}

	config, _ := connection.Config.(CrowdStrikeConfig)
	return config
}
