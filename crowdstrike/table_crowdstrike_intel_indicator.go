package crowdstrike

import (
	"context"
	"time"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client/intel"
	"github.com/sethvargo/go-retry"
	"github.com/turbot/steampipe-plugin-sdk/v3/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v3/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v3/plugin/transform"
)

func tableCrowdStrikeIntelIndicator(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "crowdstrike_intel_indicator",
		Description: "TODO.",
		List: &plugin.ListConfig{
			Hydrate: listCrowdStrikeIntelIndicator,
		},
		Columns: []*plugin.Column{
			{Name: "id", Description: "TODO", Type: proto.ColumnType_STRING},
			{Name: "marker", Description: "TODO", Type: proto.ColumnType_STRING},
			{Name: "actors", Description: "TODO", Type: proto.ColumnType_JSON},
			{Name: "deleted", Description: "TODO", Type: proto.ColumnType_BOOL},
			{Name: "domain_types", Description: "TODO", Type: proto.ColumnType_JSON},
			{Name: "indicator", Description: "TODO", Type: proto.ColumnType_STRING},
			{Name: "ip_address_types", Description: "TODO", Type: proto.ColumnType_JSON},
			{Name: "kill_chains", Description: "TODO", Type: proto.ColumnType_JSON},
			{Name: "labels", Description: "TODO", Type: proto.ColumnType_JSON},
			{Name: "last_updated", Description: "TODO", Type: proto.ColumnType_INT},
			{Name: "malicious_confidence", Description: "TODO", Type: proto.ColumnType_STRING},
			{Name: "malware_families", Description: "TODO", Type: proto.ColumnType_JSON},
			{Name: "published_date", Description: "TODO", Type: proto.ColumnType_INT},
			{Name: "relations", Description: "TODO", Type: proto.ColumnType_JSON},
			{Name: "reports", Description: "TODO", Type: proto.ColumnType_JSON},
			{Name: "targets", Description: "TODO", Type: proto.ColumnType_JSON},
			{Name: "threat_types", Description: "TODO", Type: proto.ColumnType_JSON},
			{Name: "type", Description: "TODO", Type: proto.ColumnType_STRING},
			{Name: "vulnerabilities", Description: "TODO", Type: proto.ColumnType_JSON},

			// Steampipe standard columns
			{Name: "title", Description: "Title of the resource.", Type: proto.ColumnType_STRING, Transform: transform.FromField("Indicator")},
		},
	}
}

func listCrowdStrikeIntelIndicator(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {
	client, err := getCrowdStrikeClient(ctx, d)
	if err != nil {
		plugin.Logger(ctx).Error("crowdstrike_host.listCrowdStrikeIntelIndicator", "connection_error", err)
		return nil, err
	}

	limit := int64(500)

	for response := (*intel.QueryIntelIndicatorEntitiesOK)(nil); response.HasNextPage(); {

		err := retry.Constant(ctx, 500*time.Millisecond, func(ctx context.Context) error {
			response, err = client.Intel.QueryIntelIndicatorEntities(&intel.QueryIntelIndicatorEntitiesParams{
				Context: ctx,
				Filter:  nil,
				Sort:    nil,
				Limit:   &limit,
			},
				response.Paginate(),
			)
			if response != nil && response.XRateLimitRemaining == 0 {
				return retry.RetryableError(ErrRateLimitExceeded)
			}
			if err != nil {
				plugin.Logger(ctx).Error("crowdstrike_host.listCrowdStrikeIntelIndicator", "query_error", err)
				return err
			}
			if err := falcon.AssertNoError(response.Payload.Errors); err != nil {
				return err
			}
			if response == nil || response.Payload == nil {
				return nil
			}
			indicators := response.Payload.Resources
			for _, indicator := range indicators {
				d.StreamListItem(ctx, indicator)
				if d.QueryStatus.RowsRemaining(ctx) < 1 {
					return nil
				}
			}
			return nil
		})

		if err != nil {
			return nil, err
		}

	}

	return nil, nil
}
