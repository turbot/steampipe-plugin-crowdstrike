package crowdstrike

import (
	"context"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client/detects"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/turbot/steampipe-plugin-sdk/v3/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v3/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v3/plugin/transform"
)

//// TABLE DEFINITION

func tableCrowdStrikeDetects(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "crowdstrike_detect",
		Description: "TODO.",
		List: &plugin.ListConfig{
			Hydrate: listCrowdStrikeDetects,
		},
		Columns: []*plugin.Column{
			{Name: "adversary_ids", Description: "TODO", Type: proto.ColumnType_JSON, Hydrate: getCrowdStrikeDetect, Transform: transform.FromJSONTag()},
			{Name: "assigned_to_name", Description: "TODO", Type: proto.ColumnType_STRING, Hydrate: getCrowdStrikeDetect},
			{Name: "assigned_to_uid", Description: "TODO", Type: proto.ColumnType_STRING, Hydrate: getCrowdStrikeDetect, Transform: transform.FromJSONTag()},
			{Name: "behaviors", Description: "TODO", Type: proto.ColumnType_JSON, Hydrate: getCrowdStrikeDetect},
			{Name: "behaviors_processed", Description: "TODO", Type: proto.ColumnType_JSON, Hydrate: getCrowdStrikeDetect},
			{Name: "cid", Description: "TODO", Type: proto.ColumnType_STRING, Hydrate: getCrowdStrikeDetect},
			{Name: "created_timestamp", Description: "TODO", Type: proto.ColumnType_TIMESTAMP, Hydrate: getCrowdStrikeDetect, Transform: transform.From(func(ctx context.Context, td *transform.TransformData) (interface{}, error) {
				breach := td.HydrateItem.(*models.DomainAPIDetectionDocument)
				return transformStrFmtDateTime(ctx, *breach.CreatedTimestamp)
			})},
			{Name: "detection_id", Description: "TODO", Type: proto.ColumnType_STRING, Hydrate: getCrowdStrikeDetect},
			{Name: "device", Description: "TODO", Type: proto.ColumnType_JSON, Hydrate: getCrowdStrikeDetect},
			{Name: "email_sent", Description: "TODO", Type: proto.ColumnType_BOOL, Hydrate: getCrowdStrikeDetect},
			{Name: "first_behavior", Description: "TODO", Type: proto.ColumnType_TIMESTAMP, Hydrate: getCrowdStrikeDetect, Transform: transform.From(func(ctx context.Context, td *transform.TransformData) (interface{}, error) {
				breach := td.HydrateItem.(*models.DomainAPIDetectionDocument)
				return transformStrFmtDateTime(ctx, *breach.FirstBehavior)
			})},
			{Name: "hostinfo", Description: "TODO", Type: proto.ColumnType_JSON, Hydrate: getCrowdStrikeDetect},
			{Name: "last_behavior", Description: "TODO", Type: proto.ColumnType_TIMESTAMP, Hydrate: getCrowdStrikeDetect, Transform: transform.From(func(ctx context.Context, td *transform.TransformData) (interface{}, error) {
				breach := td.HydrateItem.(*models.DomainAPIDetectionDocument)
				return transformStrFmtDateTime(ctx, *breach.LastBehavior)
			})},
			{Name: "max_confidence", Description: "TODO", Type: proto.ColumnType_INT, Hydrate: getCrowdStrikeDetect},
			{Name: "max_severity", Description: "TODO", Type: proto.ColumnType_INT, Hydrate: getCrowdStrikeDetect},
			{Name: "max_severity_displayname", Description: "TODO", Type: proto.ColumnType_STRING, Hydrate: getCrowdStrikeDetect},
			{Name: "overwatch_notes", Description: "TODO", Type: proto.ColumnType_STRING, Hydrate: getCrowdStrikeDetect},
			{Name: "quarantined_files", Description: "TODO", Type: proto.ColumnType_JSON, Hydrate: getCrowdStrikeDetect},
			{Name: "seconds_to_resolved", Description: "TODO", Type: proto.ColumnType_INT, Hydrate: getCrowdStrikeDetect},
			{Name: "seconds_to_triaged", Description: "TODO", Type: proto.ColumnType_INT, Hydrate: getCrowdStrikeDetect},
			{Name: "show_in_ui", Description: "TODO", Type: proto.ColumnType_BOOL, Hydrate: getCrowdStrikeDetect},
			{Name: "status", Description: "TODO", Type: proto.ColumnType_STRING, Hydrate: getCrowdStrikeDetect},

			// Steampipe standard columns
			{Name: "title", Description: "Title of the resource.", Type: proto.ColumnType_STRING, Hydrate: getCrowdStrikeDetect, Transform: transform.FromField("AssignedToName")},
		},
	}
}

type detectStruct struct {
	DetectId string
}

//// LIST FUNCTION

func listCrowdStrikeDetects(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {
	client, err := getCrowdStrikeClient(ctx, d)
	if err != nil {
		plugin.Logger(ctx).Error("crowdstrike_host.listCrowdStrikeDetects", "connection_error", err)
		return nil, err
	}

	limit := int64(500)

	for offset := int64(0); ; {
		response, err := client.Detects.QueryDetects(&detects.QueryDetectsParams{
			Filter:  nil,
			Offset:  &offset,
			Limit:   &limit,
			Context: ctx,
		})
		if err != nil {
			plugin.Logger(ctx).Error("crowdstrike_host.listCrowdStrikeDetects", "query_error", err)
			return nil, err
		}
		if err = falcon.AssertNoError(response.Payload.Errors); err != nil {
			plugin.Logger(ctx).Error("crowdstrike_host.listCrowdStrikeDetects", "assert_error", err)
			return nil, err
		}

		detects := response.Payload.Resources
		if len(detects) == 0 {
			break
		}
		for _, detectId := range detects {
			d.StreamListItem(ctx, detectStruct{
				DetectId: detectId,
			})
			if d.QueryStatus.RowsRemaining(ctx) < 1 {
				return nil, nil
			}
		}
		offset = offset + int64(len(detects))
		if offset >= *response.Payload.Meta.Pagination.Total {
			break
		}
	}

	return nil, nil
}

func getCrowdStrikeDetect(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {
	client, err := getCrowdStrikeClient(ctx, d)
	if err != nil {
		plugin.Logger(ctx).Error("crowdstrike_host.getCrowdStrikeDetect", "connection_error", err)
		return nil, err
	}

	var detectId string

	if h.Item != nil {
		result := h.Item.(detectStruct)
		detectId = result.DetectId
	} else {
		detectId = d.KeyColumnQuals["detect_id"].GetStringValue()
	}

	response, err := client.Detects.GetDetectSummaries(&detects.GetDetectSummariesParams{
		Body: &models.MsaIdsRequest{
			Ids: []string{detectId},
		},
		Context: ctx,
	})

	if err != nil {
		plugin.Logger(ctx).Error("crowdstrike_host.getCrowdStrikeDetect", "GetDetectSummaries error", err)
		return nil, err
	}

	return response.Payload.Resources[0], nil
}
