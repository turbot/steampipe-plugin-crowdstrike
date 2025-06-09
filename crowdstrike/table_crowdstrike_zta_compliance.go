package crowdstrike

import (
	"context"

	"github.com/crowdstrike/gofalcon/falcon/client/zero_trust_assessment"
	"github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"
)

func tableCrowdStrikeZtaCompliance(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "crowdstrike_zta_compliance",
		Description: "Zero Trust Compliance.",
		List: &plugin.ListConfig{
			Hydrate: listCrowdStrikeZtaCompliance,
		},
		Columns: []*plugin.Column{
			{Name: "cid", Description: "The Customer ID.", Type: proto.ColumnType_STRING},
			{Name: "average_overall_score", Description: "Average overall score of this compliance.", Type: proto.ColumnType_DOUBLE},
			{Name: "num_aids", Description: "Number of Zero Trust assessments.", Type: proto.ColumnType_INT},
			{Name: "platforms", Description: "Zero Trust compliance information by platform.", Type: proto.ColumnType_JSON},
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

	input := &zero_trust_assessment.GetAuditV1Params{
		Context: ctx,
	}
	response, err := client.ZeroTrustAssessment.GetAuditV1(input)
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
		if d.RowsRemaining(ctx) < 1 {
			return nil, nil
		}
	}

	return nil, nil
}
