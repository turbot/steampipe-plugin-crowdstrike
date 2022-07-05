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
)

func tableCrowdStrikeIntelActor(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "crowdstrike_intel_actor",
		Description: "A threat actor, also known as a malicious actor, is any person or organization that intentionally causes harm in the digital sphere.",
		Get: &plugin.GetConfig{
			KeyColumns: plugin.SingleColumn("id"),
			Hydrate:    getCrowdStrikeIntelActor,
		},
		List: &plugin.ListConfig{
			Hydrate: listCrowdStrikeIntelActor,
			KeyColumns: []*plugin.KeyColumn{
				{
					Name:      "slug",
					Require:   plugin.Optional,
					Operators: []string{"="},
				},
				{
					Name:      "active",
					Require:   plugin.Optional,
					Operators: []string{"="},
				},
				{
					Name:      "actor_type",
					Require:   plugin.Optional,
					Operators: []string{"="},
				},
				{
					Name:      "created_date",
					Require:   plugin.Optional,
					Operators: []string{">", ">=", "=", "<", "<="},
				},
				{
					Name:      "first_activity_date",
					Require:   plugin.Optional,
					Operators: []string{">", ">=", "=", "<", "<="},
				},
				{
					Name:      "last_activity_date",
					Require:   plugin.Optional,
					Operators: []string{">", ">=", "=", "<", "<="},
				},
				{
					Name:      "last_modified_date",
					Require:   plugin.Optional,
					Operators: []string{">", ">=", "=", "<", "<="},
				},
			},
		},
		Columns: []*plugin.Column{
			{Name: "active", Description: "If this actor is still active.", Type: proto.ColumnType_BOOL},
			{Name: "actor_type", Description: "The type of actor.", Type: proto.ColumnType_STRING},
			{Name: "capability", Description: "The actor's capability.", Type: proto.ColumnType_JSON},
			{Name: "created_date", Description: "The creation date.", Type: proto.ColumnType_TIMESTAMP, Transform: transform.FromField("CreatedDate").Transform(int642TimestampTransformer)},
			{Name: "description", Description: "A description of the actor.", Type: proto.ColumnType_STRING},
			{Name: "ecrime_kill_chain", Description: "eCrime kill chain fields.", Type: proto.ColumnType_JSON},
			{Name: "entitlements", Description: "Entitlements of the actor.", Type: proto.ColumnType_JSON},
			{Name: "first_activity_date", Description: "Date when first activity was detected.", Type: proto.ColumnType_TIMESTAMP, Transform: transform.FromField("FirstActivityDate").Transform(int642TimestampTransformer)},
			{Name: "group", Description: "The actor's group.", Type: proto.ColumnType_JSON},
			{Name: "id", Description: "The actor's ID.", Type: proto.ColumnType_INT},
			{Name: "image", Description: "URL to the image of the Actor.", Type: proto.ColumnType_JSON},
			{Name: "kill_chain", Description: "Kill chain fields.", Type: proto.ColumnType_JSON},
			{Name: "known_as", Description: "The actor's alias.", Type: proto.ColumnType_STRING},
			{Name: "last_activity_date", Description: "Date of last activity.", Type: proto.ColumnType_TIMESTAMP, Transform: transform.FromField("LastActivityDate").Transform(int642TimestampTransformer)},
			{Name: "last_modified_date", Description: "Date when this actor was last modified.", Type: proto.ColumnType_TIMESTAMP, Transform: transform.FromField("LastModifiedDate").Transform(int642TimestampTransformer)},
			{Name: "motivations", Description: "The actor's motivations.", Type: proto.ColumnType_JSON},
			{Name: "name", Description: "The actor's name.", Type: proto.ColumnType_STRING},
			{Name: "notify_users", Description: "True if users have been notified.", Type: proto.ColumnType_BOOL},
			{Name: "origins", Description: "The actor's country of origin.", Type: proto.ColumnType_JSON},
			{Name: "region", Description: "The actor's region.", Type: proto.ColumnType_JSON},
			{Name: "rich_text_description", Description: "A rich text description of the actor.", Type: proto.ColumnType_STRING},
			{Name: "short_description", Description: "A short description of the actor.", Type: proto.ColumnType_STRING},
			{Name: "slug", Description: "A slug for the actor.", Type: proto.ColumnType_STRING},
			{Name: "target_countries", Description: "The actor's targeted countries.", Type: proto.ColumnType_JSON},
			{Name: "target_industries", Description: "The actor's targeted industries.", Type: proto.ColumnType_JSON},
			{Name: "thumbnail", Description: "URL to an image for this actor.", Type: proto.ColumnType_JSON},
			{Name: "url", Description: "The URL to the falcon portal for this actor.", Type: proto.ColumnType_STRING},

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
	// Reduce the basic request limit down if the user has only requested a small number of rows
	if d.QueryContext.Limit != nil && *d.QueryContext.Limit < limit {
		limit = *d.QueryContext.Limit
	}

	filter, err := QualToFQL(ctx, d, QualToFqlNoKeyignore)
	if err != nil {
		return nil, err
	}

	for offset := int64(0); ; {
		f := &filter
		if len(filter) == 0 {
			f = nil
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
		actors, err := getIntelActorByIds(ctx, client, actorIdBatch)
		if err != nil {
			return nil, err
		}
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

	detect, err := getIntelActorByIds(ctx, client, []string{detectId})

	if err != nil {
		plugin.Logger(ctx).Error("crowdstrike_intel_actor.getCrowdStrikeIntelActor", "getIntelIndicatorByIds error", err)
		return nil, err
	}

	return detect[0], nil
}

func getIntelActorByIds(ctx context.Context, client *client.CrowdStrikeAPISpecification, ids []string) ([]*models.DomainActorDocument, error) {
	if len(ids) == 0 {
		return []*models.DomainActorDocument{}, nil
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
