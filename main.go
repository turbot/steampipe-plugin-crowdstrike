package main

import (
	"steampipe-plugin-crowdstrike/crowdstrike"

	"github.com/turbot/steampipe-plugin-sdk/v3/plugin"
)

func main() {
	plugin.Serve(&plugin.ServeOpts{PluginFunc: crowdstrike.Plugin})
}
