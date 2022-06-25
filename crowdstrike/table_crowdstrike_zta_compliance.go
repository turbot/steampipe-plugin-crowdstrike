package crowdstrike

import (
	"context"

	"github.com/crowdstrike/gofalcon/falcon/client/zero_trust_assessment"
	"github.com/turbot/steampipe-plugin-sdk/v3/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v3/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v3/plugin/transform"
)

func tableCrowdStrikeZtaCompliance(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "crowdstrike_zta_compliance",
		Description: "TODO.",
		List: &plugin.ListConfig{
			Hydrate: listCrowdStrikeZtaCompliance,
		},
		Columns: []*plugin.Column{
			{Name: "cid", Description: "The Customer ID.", Type: proto.ColumnType_STRING},
			{Name: "average_overall_score", Description: "TODO", Type: proto.ColumnType_DOUBLE},
			{Name: "num_aids", Description: "Number of ZeroTrust assessments", Type: proto.ColumnType_INT},
			{Name: "platforms", Description: "TODO", Type: proto.ColumnType_JSON},
			// Steampipe standard columns
			{Name: "title", Description: "Title of the resource.", Type: proto.ColumnType_STRING, Transform: transform.FromField("Cid")},
		},
	}
}

func listCrowdStrikeZtaCompliance(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {
	client, err := getCrowdStrikeClient(ctx, d)
	if err != nil {
		plugin.Logger(ctx).Error("crowdstrike_host.listCrowdStrikeZtaCompliance", "connection_error", err)
		return nil, err
	}

	if err := getLimiter(ctx, d).Wait(ctx); err != nil {
		return nil, err
	}
	response, err := client.ZeroTrustAssessment.GetComplianceV1(
		zero_trust_assessment.NewGetComplianceV1Params().
			WithContext(ctx).WithDefaults(),
	)
	if err != nil {
		plugin.Logger(ctx).Error("crowdstrike_host.listCrowdStrikeZtaCompliance", "query_error", err)
		return nil, err
	}

	domainSignalProps := response.Payload.Resources
	if len(domainSignalProps) == 0 {
		return nil, nil
	}

	for _, dsp := range domainSignalProps {
		d.StreamListItem(ctx, dsp)
		if d.QueryStatus.RowsRemaining(ctx) < 1 {
			return nil, nil
		}
	}

	return nil, nil
}
