package crowdstrike

import (
	"context"

	"github.com/turbot/steampipe-plugin-sdk/v4/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v4/plugin/transform"
)

func Plugin(ctx context.Context) *plugin.Plugin {
	p := &plugin.Plugin{
		Name: "steampipe-plugin-crowdstrike",
		ConnectionConfigSchema: &plugin.ConnectionConfigSchema{
			NewInstance: ConfigInstance,
			Schema:      ConfigSchema,
		},
		DefaultTransform: transform.FromGo().NullIfZero(),
		TableMap: map[string]*plugin.Table{
			"crowdstrike_detection":               tableCrowdStrikeDetection(ctx),
			"crowdstrike_host":                    tableCrowdStrikeHost(ctx),
			"crowdstrike_intel_actor":             tableCrowdStrikeIntelActor(ctx),
			"crowdstrike_spotlight_vulnerability": tableCrowdStrikeSpotlightVulnerability(ctx),
			"crowdstrike_user":                    tableCrowdStrikeUser(ctx),
			"crowdstrike_zta_assessment":          tableCrowdStrikeZtaAssessment(ctx),
			"crowdstrike_zta_compliance":          tableCrowdStrikeZtaCompliance(ctx),
		},
	}

	return p
}
