package crowdstrike

import (
	"context"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/intel"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/turbot/steampipe-plugin-sdk/v3/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v3/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v3/plugin/transform"
	"golang.org/x/time/rate"
)

func tableCrowdStrikeIntelActor(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "crowdstrike_intel_actor",
		Description: "TODO.",
		Get: &plugin.GetConfig{
			KeyColumns: plugin.SingleColumn("id"),
			Hydrate:    getCrowdStrikeIntelActor,
		},
		List: &plugin.ListConfig{
			Hydrate: listCrowdStrikeIntelActor,
		},
		Columns: []*plugin.Column{
			{Name: "active", Description: "TODO", Type: proto.ColumnType_BOOL},
			{Name: "actor_type", Description: "TODO", Type: proto.ColumnType_STRING},
			{Name: "capability", Description: "TODO", Type: proto.ColumnType_JSON},
			{Name: "created_date", Description: "TODO", Type: proto.ColumnType_INT},
			{Name: "description", Description: "TODO", Type: proto.ColumnType_STRING},
			{Name: "ecrime_kill_chain", Description: "TODO", Type: proto.ColumnType_JSON},
			{Name: "entitlements", Description: "TODO", Type: proto.ColumnType_JSON},
			{Name: "first_activity_date", Description: "TODO", Type: proto.ColumnType_INT},
			{Name: "group", Description: "TODO", Type: proto.ColumnType_JSON},
			{Name: "id", Description: "TODO", Type: proto.ColumnType_INT},
			{Name: "image", Description: "TODO", Type: proto.ColumnType_JSON},
			{Name: "kill_chain", Description: "TODO", Type: proto.ColumnType_JSON},
			{Name: "known_as", Description: "TODO", Type: proto.ColumnType_STRING},
			{Name: "last_activity_date", Description: "TODO", Type: proto.ColumnType_INT},
			{Name: "last_modified_date", Description: "TODO", Type: proto.ColumnType_INT},
			{Name: "motivations", Description: "TODO", Type: proto.ColumnType_JSON},
			{Name: "name", Description: "TODO", Type: proto.ColumnType_STRING},
			{Name: "notify_users", Description: "TODO", Type: proto.ColumnType_BOOL},
			{Name: "origins", Description: "TODO", Type: proto.ColumnType_JSON},
			{Name: "region", Description: "TODO", Type: proto.ColumnType_JSON},
			{Name: "rich_text_description", Description: "TODO", Type: proto.ColumnType_STRING},
			{Name: "short_description", Description: "TODO", Type: proto.ColumnType_STRING},
			{Name: "slug", Description: "TODO", Type: proto.ColumnType_STRING},
			{Name: "target_countries", Description: "TODO", Type: proto.ColumnType_JSON},
			{Name: "target_industries", Description: "TODO", Type: proto.ColumnType_JSON},
			{Name: "thumbnail", Description: "TODO", Type: proto.ColumnType_JSON},
			{Name: "url", Description: "TODO", Type: proto.ColumnType_STRING},

			// Steampipe standard columns
			{Name: "title", Description: "Title of the resource.", Type: proto.ColumnType_STRING, Transform: transform.FromField("Indicator")},
		},
	}
}

func listCrowdStrikeIntelActor(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {
	client, err := getCrowdStrikeClient(ctx, d)
	if err != nil {
		plugin.Logger(ctx).Error("crowdstrike_intel_actor.listCrowdStrikeIntelActor", "connection_error", err)
		return nil, err
	}

	limit := int64(500)
	filter, err := QualToFQL(ctx, d, QualToFqlNoKeyignore)
	if err != nil {
		return nil, err
	}

	for offset := int64(0); ; {
		f := &filter
		if len(filter) == 0 {
			f = nil
		}

		if err := getRateLimiter(ctx, d).Wait(ctx); err != nil {
			return nil, err
		}

		response, err := client.Intel.QueryIntelActorIds(
			intel.NewQueryIntelActorIdsParamsWithContext(ctx).
				WithOffset(&offset).
				WithLimit(&limit).
				WithFilter(f),
		)

		if err != nil {
			plugin.Logger(ctx).Error("crowdstrike_intel_actor.listCrowdStrikeIntelActor", "query_error", err)
			return nil, err
		}
		if err := falcon.AssertNoError(response.Payload.Errors); err != nil {
			plugin.Logger(ctx).Error("crowdstrike_intel_actor.listCrowdStrikeIntelActor", "assert_error", err)
			return nil, err
		}

		actorIdBatch := response.Payload.Resources
		actors, err := getIntelActorByIds(ctx, client, getRateLimiter(ctx, d), actorIdBatch)
		for _, actor := range actors {
			d.StreamListItem(ctx, actor)
			if d.QueryStatus.RowsRemaining(ctx) < 1 {
				return nil, nil
			}
		}
		offset = offset + int64(len(actorIdBatch))
		if offset >= *response.Payload.Meta.Pagination.Total {
			break
		}
	}

	return nil, nil
}

func getCrowdStrikeIntelActor(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {
	client, err := getCrowdStrikeClient(ctx, d)
	if err != nil {
		plugin.Logger(ctx).Error("crowdstrike_intel_actor.getCrowdStrikeIntelActor", "connection_error", err)
		return nil, err
	}

	detectId := d.KeyColumnQuals["id"].GetStringValue()

	detect, err := getIntelActorByIds(ctx, client, getRateLimiter(ctx, d), []string{detectId})

	if err != nil {
		plugin.Logger(ctx).Error("crowdstrike_intel_actor.getCrowdStrikeIntelActor", "getIntelIndicatorByIds error", err)
		return nil, err
	}

	return detect[0], nil
}

func getIntelActorByIds(ctx context.Context, client *client.CrowdStrikeAPISpecification, limiter *rate.Limiter, ids []string) ([]*models.DomainActorDocument, error) {
	if len(ids) == 0 {
		return []*models.DomainActorDocument{}, nil
	}

	if err := limiter.Wait(ctx); err != nil {
		return nil, err
	}

	response, err := client.Intel.GetIntelActorEntities(
		intel.NewGetIntelActorEntitiesParamsWithContext(ctx).WithIds(ids),
	)

	if err != nil {
		plugin.Logger(ctx).Error("crowdstrike_intel_actor.getIntelIndicatorByIds", "GetDetectSummaries", err)
		return nil, err
	}
	if err = falcon.AssertNoError(response.Payload.Errors); err != nil {
		plugin.Logger(ctx).Error("crowdstrike_intel_actor.getIntelIndicatorByIds", "GetDetectSummaries", err)
		return nil, err
	}

	return response.Payload.Resources, nil
}
