package crowdstrike

import (
	"context"

	"github.com/turbot/steampipe-plugin-sdk/v3/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v3/plugin/transform"
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
			"crowdstrike_host":            tableCrowdStrikeHost(ctx),
			"crowdstrike_zta_assessment":  tableCrowdStrikeZtaAssessment(ctx),
			"crowdstrike_zta_compliance":  tableCrowdStrikeZtaCompliance(ctx),
			"crowdstrike_intel_indicator": tableCrowdStrikeIntelIndicator(ctx),
			"crowdstrike_detect":          tableCrowdStrikeDetects(ctx),
		},
	}

	return p
}
