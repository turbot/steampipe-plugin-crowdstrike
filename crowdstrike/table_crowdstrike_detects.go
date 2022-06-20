package crowdstrike

import (
	"context"
	"errors"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
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
		Description: "Detections are events identified by Falcon sensors on the hosts in your environment.",
		List: &plugin.ListConfig{
			Hydrate: listCrowdStrikeDetects,
		},
		Columns: []*plugin.Column{
			{Name: "adversary_ids", Description: "If behaviors or indicators in a detection are attributed to an adversary that is tracked by CrowdStrike Falcon Intelligence, those adversaries will have an ID associated with them. These IDs are found in a detection's metadata which can be viewed using the Detection Details API.", Type: proto.ColumnType_JSON, Hydrate: getCrowdStrikeDetect, Transform: transform.FromJSONTag()},
			{Name: "assigned_to_name", Description: "The human-readable name of the user to whom the detection is currently assigned.", Type: proto.ColumnType_STRING, Hydrate: getCrowdStrikeDetect},

			{Name: "assigned_to_uid", Description: "TODO", Type: proto.ColumnType_STRING, Hydrate: getCrowdStrikeDetect, Transform: transform.FromJSONTag()},
			{Name: "behaviors", Description: "TODO", Type: proto.ColumnType_JSON, Hydrate: getCrowdStrikeDetect},
			{Name: "behaviors_processed", Description: "TODO", Type: proto.ColumnType_JSON, Hydrate: getCrowdStrikeDetect},

			{Name: "cid", Description: "Your organization's customer ID (CID).", Type: proto.ColumnType_STRING, Hydrate: getCrowdStrikeDetect},

			{Name: "created_timestamp", Description: "TODO", Type: proto.ColumnType_TIMESTAMP, Hydrate: getCrowdStrikeDetect, Transform: transform.From(func(ctx context.Context, td *transform.TransformData) (interface{}, error) {
				breach := td.HydrateItem.(*models.DomainAPIDetectionDocument)
				return transformStrFmtDateTime(ctx, *breach.CreatedTimestamp)
			})},

			{Name: "detection_id", Description: "The ID of the detection. This ID can be used in conjunction with other APIs, such as the Detection Details API, or the Resolve Detection API.", Type: proto.ColumnType_STRING, Hydrate: getCrowdStrikeDetect},

			{Name: "device", Description: "TODO", Type: proto.ColumnType_JSON, Hydrate: getCrowdStrikeDetect},
			{Name: "email_sent", Description: "TODO", Type: proto.ColumnType_BOOL, Hydrate: getCrowdStrikeDetect},

			{Name: "first_behavior", Description: "When a detection has more than one associated behavior, this field captures the timestamp of the first behavior.", Type: proto.ColumnType_TIMESTAMP, Hydrate: getCrowdStrikeDetect, Transform: transform.From(func(ctx context.Context, td *transform.TransformData) (interface{}, error) {
				breach := td.HydrateItem.(*models.DomainAPIDetectionDocument)
				return transformStrFmtDateTime(ctx, *breach.FirstBehavior)
			})},

			{Name: "hostinfo", Description: "TODO", Type: proto.ColumnType_JSON, Hydrate: getCrowdStrikeDetect},

			{Name: "last_behavior", Description: "	When a detection has more than one associated behavior, this field captures the timestamp of the last behavior.", Type: proto.ColumnType_TIMESTAMP, Hydrate: getCrowdStrikeDetect, Transform: transform.From(func(ctx context.Context, td *transform.TransformData) (interface{}, error) {
				breach := td.HydrateItem.(*models.DomainAPIDetectionDocument)
				return transformStrFmtDateTime(ctx, *breach.LastBehavior)
			})},
			{Name: "max_confidence", Description: "When a detection has more than one associated behavior with varying confidence levels, this field captures the highest confidence value of all behaviors. Value can be any integer between 1-100.", Type: proto.ColumnType_INT, Hydrate: getCrowdStrikeDetect},
			{Name: "max_severity", Description: "When a detection has more than one associated behavior with varying severity levels, this field captures the highest severity value of all behaviors. Value can be any integer between 1-100.", Type: proto.ColumnType_INT, Hydrate: getCrowdStrikeDetect},
			{Name: "max_severity_displayname", Description: "The name used in the UI to determine the severity of the detection. Values include Critical, High, Medium, and Low", Type: proto.ColumnType_STRING, Hydrate: getCrowdStrikeDetect},

			{Name: "overwatch_notes", Description: "TODO", Type: proto.ColumnType_STRING, Hydrate: getCrowdStrikeDetect},
			{Name: "quarantined_files", Description: "TODO", Type: proto.ColumnType_JSON, Hydrate: getCrowdStrikeDetect},

			{Name: "seconds_to_resolved", Description: "Time that it took to move a detection from newand one of the resolved states (true_positive, false_positive, and ignored).", Type: proto.ColumnType_INT, Hydrate: getCrowdStrikeDetect},
			{Name: "seconds_to_triaged", Description: "Time that it took to move a detection from new to in_progress.", Type: proto.ColumnType_INT, Hydrate: getCrowdStrikeDetect},

			{Name: "show_in_ui", Description: "TODO", Type: proto.ColumnType_BOOL, Hydrate: getCrowdStrikeDetect},

			{Name: "status", Description: "The current status of the detection. Values include new, in_progress, true_positive, false_positive, and ignored.", Type: proto.ColumnType_STRING, Hydrate: getCrowdStrikeDetect},

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

		detectIdBatch := response.Payload.Resources
		if len(detectIdBatch) == 0 {
			break
		}

		detects, err := getDetectsByIds(ctx, client, detectIdBatch)
		if err != nil {
			return nil, err
		}

		for _, detect := range detects {
			d.StreamListItem(ctx, detect)
			if d.QueryStatus.RowsRemaining(ctx) < 1 {
				return nil, nil
			}
		}

		offset = offset + int64(len(detectIdBatch))
		if offset >= *response.Payload.Meta.Pagination.Total {
			break
		}
	}

	return nil, nil
}

func getCrowdStrikeDetect(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {
	client, err := getCrowdStrikeClient(ctx, d)
	if err != nil {
		plugin.Logger(ctx).Error("crowdstrike_detects.getCrowdStrikeDetect", "connection_error", err)
		return nil, err
	}

	detectId := d.KeyColumnQuals["detect_id"].GetStringValue()

	detect, err := getDetectsByIds(ctx, client, []string{detectId})

	if err != nil {
		plugin.Logger(ctx).Error("crowdstrike_detects.getCrowdStrikeDetect", "GetDetectSummaries error", err)
		return nil, err
	}

	return detect[0], nil
}

func getDetectsByIds(ctx context.Context, client *client.CrowdStrikeAPISpecification, ids []string) ([]*models.DomainAPIDetectionDocument, error) {
	response, err := client.Detects.GetDetectSummaries(
		detects.NewGetDetectSummariesParamsWithContext(ctx).WithBody(&models.MsaIdsRequest{
			Ids: ids,
		}),
	)
	if err != nil {
		plugin.Logger(ctx).Error("crowdstrike_detects.getDetectsByIds", "GetDetectSummaries", err)
		return nil, errors.New(falcon.ErrorExplain(err))
	}
	if err = falcon.AssertNoError(response.Payload.Errors); err != nil {
		plugin.Logger(ctx).Error("crowdstrike_detects.getDetectsByIds", "GetDetectSummaries", err)
		return nil, err
	}

	return response.Payload.Resources, nil
}
