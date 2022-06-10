package crowdstrike

import (
	"github.com/turbot/steampipe-plugin-sdk/v3/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v3/plugin/schema"
)

type CrowdStrikeConfig struct {
	ClientCloud  *string `cty:"client_cloud"`
	ClientId     *string `cty:"client_id"`
	ClientSecret *string `cty:"client_secret"`
}

var ConfigSchema = map[string]*schema.Attribute{
	"client_cloud": {
		Type: schema.TypeString,
	},
	"client_id": {
		Type: schema.TypeString,
	},
	"client_secret": {
		Type: schema.TypeString,
	},
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
