package crowdstrike

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/firewall_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/turbot/steampipe-plugin-sdk/v3/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v3/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v3/plugin/transform"
)

func tableCrowdStrikeFirewallPolicy(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "crowdstrike_firewall_policy",
		Description: "TODO.",
		List: &plugin.ListConfig{
			Hydrate: listCrowdStrikeFirewallPolicies,
		},
		Columns: []*plugin.Column{
			{Name: "id", Description: "TODO", Type: proto.ColumnType_STRING},
			// Steampipe standard columns
			{Name: "title", Description: "Title of the resource.", Type: proto.ColumnType_STRING, Transform: transform.FromField("Cid")},
		},
	}
}

func listCrowdStrikeFirewallPolicies(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {
	client, err := getCrowdStrikeClient(ctx, d)
	if err != nil {
		plugin.Logger(ctx).Error("crowdstrike_host.listCrowdStrikeFirewallPolicies", "connection_error", err)
		return nil, err
	}

	limit := int64(10)
	// Reduce the basic request limit down if the user has only requested a small number of rows
	if d.QueryContext.Limit != nil && *d.QueryContext.Limit < limit {
		limit = *d.QueryContext.Limit
	}

	offset := (*int64)(nil)
	filter, err := QualToFQL(ctx, d, "*")
	if err != nil {
		return nil, err
	}

	for {
		response, err := client.FirewallPolicies.QueryFirewallPolicies(
			&firewall_policies.QueryFirewallPoliciesParams{
				Context: ctx,
				Offset:  offset,
				Limit:   &limit,
				Filter:  filter,
			},
		)

		if err != nil {
			return nil, err
		}
		if err = falcon.AssertNoError(response.Payload.Errors); err != nil {
			return nil, err
		}

		fwPolicyBatch := response.Payload.Resources
		if len(fwPolicyBatch) == 0 {
			break
		}

		if details, err := getFirewallPolicyDetailsByIds(ctx, client, fwPolicyBatch); err != nil {
			for _, detail := range details {
				d.StreamListItem(ctx, detail)
				if d.QueryStatus.RowsRemaining(ctx) < 1 {
					return nil, nil
				}
			}
		}

		if response.Payload.Meta == nil && response.Payload.Meta.Pagination == nil && response.Payload.Meta.Pagination.Limit == nil {
			return nil, fmt.Errorf("Cannot paginate Firewall Policies, pagination information missing")
		}
		if *response.Payload.Meta.Pagination.Limit > int32(len(fwPolicyBatch)) {
			// We have got less items than what was the limit. Meaning, this is last batch, continuation is futile.
			break
		} else {
			o := int64(*response.Payload.Meta.Pagination.Offset)
			offset = &o
		}
	}

	return nil, nil
}

func getFirewallPolicyDetailsByIds(ctx context.Context, client *client.CrowdStrikeAPISpecification, ids []string) ([]*models.ResponsesFirewallPolicyV1, error) {
	plugin.Logger(ctx).Trace("fetching details for ", ids)
	response, err := client.FirewallPolicies.GetFirewallPolicies(
		firewall_policies.NewGetFirewallPoliciesParamsWithContext(ctx).WithIds(ids),
	)
	if err != nil {
		return nil, err
	}
	if err = falcon.AssertNoError(response.Payload.Errors); err != nil {
		return nil, err
	}
	return response.Payload.Resources, nil
}
