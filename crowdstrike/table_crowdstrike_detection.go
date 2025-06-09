package crowdstrike

import (
	"context"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/alerts"
	"github.com/crowdstrike/gofalcon/falcon/client/detects"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"
)

//// TABLE DEFINITION

func tableCrowdStrikeDetection(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "crowdstrike_detection",
		Description: "Detections are events identified by Falcon sensors on the hosts in your environment.",
		List: &plugin.ListConfig{
			Hydrate: listCrowdStrikeDetections,
			KeyColumns: []*plugin.KeyColumn{
				{
					Name:      "created_timestamp",
					Require:   plugin.Optional,
					Operators: []string{">", ">=", "=", "<", "<="},
				},
				{
					Name:      "first_behavior",
					Require:   plugin.Optional,
					Operators: []string{">", ">=", "=", "<", "<="},
				},
				{
					Name:      "last_behavior",
					Require:   plugin.Optional,
					Operators: []string{">", ">=", "=", "<", "<="},
				},
				{
					Name:      "status",
					Require:   plugin.Optional,
					Operators: []string{"="},
				},
				{
					Name:      "detection_id",
					Require:   plugin.Optional,
					Operators: []string{"="},
				},
				{
					Name:      "max_severity",
					Require:   plugin.Optional,
					Operators: []string{">", ">=", "=", "<", "<="},
				},
				{
					Name:      "max_confidence",
					Require:   plugin.Optional,
					Operators: []string{">", ">=", "=", "<", "<="},
				},
			},
		},
		Get: &plugin.GetConfig{
			KeyColumns: plugin.SingleColumn("detection_id"),
			Hydrate:    getCrowdStrikeDetection,
		},
		Columns: []*plugin.Column{
			{Name: "adversary_ids", Description: "If behaviors or indicators in a detection are attributed to an adversary that is tracked by CrowdStrike Falcon Intelligence, those adversaries will have an ID associated with them. These IDs are found in a detection's metadata which can be viewed using the Detection Details API.", Type: proto.ColumnType_JSON, Transform: transform.FromJSONTag()},
			{Name: "assigned_to_name", Description: "The human-readable name of the user to whom the detection is currently assigned.", Type: proto.ColumnType_STRING},
			{Name: "assigned_to_uid", Description: "The UID of the user to whom the detection is currently assigned.", Type: proto.ColumnType_STRING, Transform: transform.FromJSONTag()},
			{Name: "behaviors", Description: "Behavorial details of the detection.", Type: proto.ColumnType_JSON},
			{Name: "behaviors_processed", Description: "The processed behaviors.", Type: proto.ColumnType_JSON},
			{Name: "cid", Description: "Your organization's customer ID (CID).", Type: proto.ColumnType_STRING},
			{Name: "created_timestamp", Description: "Timestamp when this detection was first created.", Type: proto.ColumnType_TIMESTAMP, Transform: transform.FromField("CreatedTimestamp").Transform(strfmtDatetimeTransformer)},
			{Name: "detection_id", Description: "The ID of the detection. This ID can be used in conjunction with other APIs, such as the Detection Details API, or the Resolve Detection API.", Type: proto.ColumnType_STRING},
			{Name: "device", Description: "The device where this was detected.", Type: proto.ColumnType_JSON},
			{Name: "email_sent", Description: "Whether email was sent when this was detected.", Type: proto.ColumnType_BOOL},
			{Name: "first_behavior", Description: "When a detection has more than one associated behavior, this field captures the timestamp of the first behavior.", Type: proto.ColumnType_TIMESTAMP, Transform: transform.FromField("FirstBehavior").Transform(strfmtDatetimeTransformer)},
			{Name: "host_info", Transform: transform.FromField("Hostinfo"), Description: "Information about the host where this was detected.", Type: proto.ColumnType_JSON},
			{Name: "last_behavior", Description: "When a detection has more than one associated behavior, this field captures the timestamp of the last behavior.", Type: proto.ColumnType_TIMESTAMP, Transform: transform.FromField("LastBehavior").Transform(strfmtDatetimeTransformer)},
			{Name: "max_confidence", Description: "When a detection has more than one associated behavior with varying confidence levels, this field captures the highest confidence value of all behaviors. Value can be any integer between 1-100.", Type: proto.ColumnType_INT},
			{Name: "max_severity", Description: "When a detection has more than one associated behavior with varying severity levels, this field captures the highest severity value of all behaviors. Value can be any integer between 1-100.", Type: proto.ColumnType_INT},
			{Name: "max_severity_display_name", Transform: transform.FromField("MaxSeverityDisplayname"), Description: "The name used in the UI to determine the severity of the detection. Values include Critical, High, Medium, and Low", Type: proto.ColumnType_STRING},
			{Name: "overwatch_notes", Description: "Notes from Falcon Overwatch.", Type: proto.ColumnType_STRING},
			{Name: "quarantined_files", Description: "Files that have been quarantined.", Type: proto.ColumnType_JSON},
			{Name: "seconds_to_resolved", Description: "Time that it took to move a detection from new to one of the resolved states (true_positive, false_positive, and ignored).", Type: proto.ColumnType_INT},
			{Name: "seconds_to_triaged", Description: "Time that it took to move a detection from new to in_progress.", Type: proto.ColumnType_INT},
			{Name: "show_in_ui", Description: "Whether this is shown in the User Interface.", Type: proto.ColumnType_BOOL},
			{Name: "status", Description: "The current status of the detection. Values include new, in_progress, true_positive, false_positive, and ignored.", Type: proto.ColumnType_STRING},
			// Steampipe standard columns
			{Name: "title", Description: "Title of the resource.", Type: proto.ColumnType_STRING, Transform: transform.FromField("AssignedToName")},
		},
	}
}

//// LIST FUNCTION

func listCrowdStrikeDetections(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {

	client, err := getCrowdStrikeClient(ctx, d)
	if err != nil {
		plugin.Logger(ctx).Error("crowdstrike_host.listCrowdStrikeDetections", "connection_error", err)
		return nil, err
	}

	limit := int64(500)
	// Reduce the basic request limit down if the user has only requested a small number of rows
	if d.QueryContext.Limit != nil && *d.QueryContext.Limit < limit {
		limit = *d.QueryContext.Limit
	}
	filter, err := QualToFQL(ctx, d, QualToFqlNoKeyignore, "")
	if err != nil {
		return nil, err
	}

	for offset := int64(0); ; {
		f := &filter
		if len(filter) == 0 {
			f = nil
		}

		response, err := client.Detects.QueryDetects(&detects.QueryDetectsParams{
			Filter:  f,
			Offset:  &offset,
			Limit:   &limit,
			Context: ctx,
		})

		if err != nil {
			plugin.Logger(ctx).Error("crowdstrike_host.listCrowdStrikeDetections", "query_error", err)
			return nil, err
		}
		if err = falcon.AssertNoError(response.Payload.Errors); err != nil {
			plugin.Logger(ctx).Error("crowdstrike_host.listCrowdStrikeDetections", "assert_error", err)
			return nil, err
		}

		// Batch size
		batchSize := 999
		detectIdBatch := response.Payload.Resources

		for i := 0; i < len(detectIdBatch); i += batchSize {
			// Get the end index for the batch
			end := i + batchSize
			if end > len(detectIdBatch) {
				end = len(detectIdBatch) // Ensure we don't go out of bounds
			}

			// Extract the batch
			batchIds := detectIdBatch[i:end]

			plugin.Logger(ctx).Trace("detect batch length", len(batchIds))
			batchDetects, err := getDetectsByIds(ctx, client, batchIds)
			if err != nil {
				return nil, err
			}

			for _, detect := range batchDetects {
				d.StreamListItem(ctx, detect)
				if d.RowsRemaining(ctx) < 1 {
					return nil, nil
				}
			}

		}
		offset = offset + int64(len(detectIdBatch))
		if offset >= *response.Payload.Meta.Pagination.Total {
			break
		}
	}

	return nil, nil
}

func getCrowdStrikeDetection(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {
	client, err := getCrowdStrikeClient(ctx, d)
	if err != nil {
		plugin.Logger(ctx).Error("crowdstrike_detects.getCrowdStrikeDetection", "connection_error", err)
		return nil, err
	}

	detectId := d.EqualsQuals["detection_id"].GetStringValue()

	detect, err := getDetectsByIds(ctx, client, []string{detectId})

	if err != nil {
		plugin.Logger(ctx).Error("crowdstrike_detects.getCrowdStrikeDetection", "GetDetectSummaries error", err)
		return nil, err
	}

	return detect[0], nil
}

func getDetectsByIds(ctx context.Context, client *client.CrowdStrikeAPISpecification, ids []string) ([]*models.DetectsAlert, error) {
	if len(ids) == 0 {
		return []*models.DetectsAlert{}, nil
	}

	response, err := client.Alerts.PostEntitiesAlertsV1(&alerts.PostEntitiesAlertsV1Params{
		Body: &models.DetectsapiPostEntitiesAlertsV1Request{
			Ids: ids,
		},
	})

	if err != nil {
		plugin.Logger(ctx).Error("crowdstrike_detects.getDetectsByIds", "GetDetectSummaries", err)
		return nil, err
	}
	if err = falcon.AssertNoError(response.Payload.Errors); err != nil {
		plugin.Logger(ctx).Error("crowdstrike_detects.getDetectsByIds", "GetDetectSummaries", err)
		return nil, err
	}

	return response.Payload.Resources, nil
}
