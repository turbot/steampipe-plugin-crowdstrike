package crowdstrike

import (
	"context"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/alerts"
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
				{Name: "created_timestamp", Require: plugin.Optional, Operators: []string{">", ">=", "=", "<", "<="}},
				{Name: "status", Require: plugin.Optional, Operators: []string{"="}},
				{Name: "id", Require: plugin.Optional, Operators: []string{"="}},
			},
		},
		Get: &plugin.GetConfig{
			KeyColumns: plugin.SingleColumn("id"),
			Hydrate:    getCrowdStrikeDetection,
		},
		Columns: []*plugin.Column{
			{Name: "agent_id", Description: "Device or sensor ID for which the Alert was generated.", Type: proto.ColumnType_STRING, Transform: transform.FromField("AgentID")},
			{Name: "aggregate_id", Description: "Common linkage between multiple Alerts that belong to the same detection bouquet.", Type: proto.ColumnType_STRING, Transform: transform.FromField("AggregateID")},
			{Name: "assigned_to_name", Description: "Name of the person this Alert is assigned to.", Type: proto.ColumnType_STRING, Transform: transform.FromField("AssignedToName")},
			{Name: "assigned_to_uid", Description: "UserID to which this Alert is assigned to.", Type: proto.ColumnType_STRING, Transform: transform.FromField("AssignedToUID")},
			{Name: "assigned_to_uuid", Description: "UUID to which this Alert is assigned to.", Type: proto.ColumnType_STRING, Transform: transform.FromField("AssignedToUUID")},
			{Name: "cid", Description: "Unique ID of CrowdStrike customers.", Type: proto.ColumnType_STRING, Transform: transform.FromField("Cid")},
			{Name: "composite_id", Description: "An opaque internal identifier that can uniquely identify an Alert.", Type: proto.ColumnType_STRING, Transform: transform.FromField("CompositeID")},
			{Name: "confidence", Description: "Confidence is a 1-100 integer value denoting the confidence that, when this Alert fires, it is indicative of malicious activity.", Type: proto.ColumnType_INT, Transform: transform.FromField("Confidence")},
			{Name: "created_timestamp", Description: "Indicates when the Alert was first written to backend store.", Type: proto.ColumnType_TIMESTAMP, Transform: transform.FromField("CreatedTimestamp").Transform(strfmtDatetimeTransformer)},
			{Name: "description", Description: "Short, customer-visible summary of the detected activity.", Type: proto.ColumnType_STRING, Transform: transform.FromField("Description")},
			{Name: "device", Description: "Device struct for the alert.", Type: proto.ColumnType_JSON, Transform: transform.FromField("Device")},
			{Name: "display_name", Description: "Customer visible name for the Alert's pattern.", Type: proto.ColumnType_STRING, Transform: transform.FromField("DisplayName")},
			{Name: "email_sent", Description: "Boolean to know if we sent email regarding this Alert.", Type: proto.ColumnType_BOOL, Transform: transform.FromField("EmailSent")},
			{Name: "external", Description: "Boolean indicating if this Alert is internal or external.", Type: proto.ColumnType_BOOL, Transform: transform.FromField("External")},
			{Name: "id", Description: "Vertex key which triggers the formation of the Alert.", Type: proto.ColumnType_STRING, Transform: transform.FromField("ID")},
			{Name: "mitre_attack", Description: "References to MITRE ATT&CK.", Type: proto.ColumnType_JSON, Transform: transform.FromField("MitreAttack")},
			{Name: "name", Description: "Pattern Name coming either from Taxonomy or directly from the ingested Alert.", Type: proto.ColumnType_STRING, Transform: transform.FromField("Name")},
			{Name: "objective", Description: "End goal that an attack adversary intends to achieve according to MITRE.", Type: proto.ColumnType_STRING, Transform: transform.FromField("Objective")},
			{Name: "pattern_id", Description: "Taxonomy patternID for this Alert.", Type: proto.ColumnType_INT, Transform: transform.FromField("PatternID")},
			{Name: "platform", Description: "Platform that this Alert was triggered on.", Type: proto.ColumnType_STRING, Transform: transform.FromField("Platform")},
			{Name: "product", Description: "Product specifies the SKU that this Alert belongs to.", Type: proto.ColumnType_STRING, Transform: transform.FromField("Product")},
			{Name: "quarantined_files", Description: "Quarantined files.", Type: proto.ColumnType_JSON, Transform: transform.FromField("QuarantinedFiles")},
			{Name: "resolution", Description: "Alert resolution.", Type: proto.ColumnType_STRING, Transform: transform.FromField("Resolution")},
			{Name: "scenario", Description: "Scenario for UI alerts.", Type: proto.ColumnType_STRING, Transform: transform.FromField("Scenario")},
			{Name: "seconds_to_resolved", Description: "Seconds To Resolved represents the seconds elapsed since this alert has been resolved.", Type: proto.ColumnType_INT, Transform: transform.FromField("SecondsToResolved")},
			{Name: "seconds_to_triaged", Description: "Seconds To Triage represents the seconds elapsed since this alert has been triaged.", Type: proto.ColumnType_INT, Transform: transform.FromField("SecondsToTriaged")},
			{Name: "severity", Description: "Severity is a 1-100 integer value, but unlike confidence severity impacts how a Alert is displayed in the UI.", Type: proto.ColumnType_INT, Transform: transform.FromField("Severity")},
			{Name: "severity_name", Description: "Severity name is a UI friendly bucketing of the severity integer.", Type: proto.ColumnType_STRING, Transform: transform.FromField("SeverityName")},
			{Name: "show_in_ui", Description: "Boolean indicating if this Alert will be shown in the UI or if it's hidden.", Type: proto.ColumnType_BOOL, Transform: transform.FromField("ShowInUI")},
			{Name: "source_products", Description: "Source Products are products that produced events which contributed to this alert.", Type: proto.ColumnType_JSON, Transform: transform.FromField("SourceProducts")},
			{Name: "source_vendors", Description: "Source Vendors are vendors that produced events which contributed to this alert.", Type: proto.ColumnType_JSON, Transform: transform.FromField("SourceVendors")},
			{Name: "status", Description: "Could be one of the following - New, closed, in_progress, reopened.", Type: proto.ColumnType_STRING, Transform: transform.FromField("Status")},
			{Name: "tactic", Description: "MITRE ATT&CK tactic.", Type: proto.ColumnType_STRING, Transform: transform.FromField("Tactic")},
			{Name: "tactic_id", Description: "Unique ID for the tactic seen in the Alert.", Type: proto.ColumnType_STRING, Transform: transform.FromField("TacticID")},
			{Name: "tags", Description: "Tags are string values associated with the alert.", Type: proto.ColumnType_JSON, Transform: transform.FromField("Tags")},
			{Name: "technique", Description: "MITRE ATT&CK technique.", Type: proto.ColumnType_STRING, Transform: transform.FromField("Technique")},
			{Name: "technique_id", Description: "Unique ID for the technique seen in the Alert.", Type: proto.ColumnType_STRING, Transform: transform.FromField("TechniqueID")},
			{Name: "timestamp", Description: "Stored value coming in directly from the ingested event or set by cloud in the absence of it.", Type: proto.ColumnType_TIMESTAMP, Transform: transform.FromField("Timestamp").Transform(strfmtDatetimeTransformer)},
			{Name: "type", Description: "Type of definition Detections Extensibility use.", Type: proto.ColumnType_STRING, Transform: transform.FromField("Type")},
			{Name: "updated_timestamp", Description: "Indicates when the Alert was last modified.", Type: proto.ColumnType_TIMESTAMP, Transform: transform.FromField("UpdatedTimestamp").Transform(strfmtDatetimeTransformer)},
			// Steampipe standard columns
			{Name: "title", Description: "Title of the resource.", Type: proto.ColumnType_STRING, Transform: transform.FromField("DisplayName")},
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

		response, err := client.Alerts.QueryV2(&alerts.QueryV2Params{
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

		detectIdBatch := response.Payload.Resources
		plugin.Logger(ctx).Trace("detect batch length", len(detectIdBatch))
		detects, err := getDetectsByIds(ctx, client, detectIdBatch)
		if err != nil {
			return nil, err
		}

		for _, detect := range detects {
			d.StreamListItem(ctx, detect)
			if d.RowsRemaining(ctx) < 1 {
				return nil, nil
			}
		}

		if err != nil {
			return nil, err
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

	detectId := d.EqualsQuals["id"].GetStringValue()

	detect, err := getDetectsByIds(ctx, client, []string{detectId})

	if err != nil {
		plugin.Logger(ctx).Error("crowdstrike_detects.getCrowdStrikeDetection", "PostEntitiesAlertsV1 error", err)
		return nil, err
	}

	if len(detect) == 0 {
		return nil, nil
	}

	return detect[0], nil
}

func getDetectsByIds(ctx context.Context, client *client.CrowdStrikeAPISpecification, ids []string) ([]*models.DetectsAlert, error) {
	if len(ids) == 0 {
		return []*models.DetectsAlert{}, nil
	}

	response, err := client.Alerts.PostEntitiesAlertsV1(
		alerts.NewPostEntitiesAlertsV1ParamsWithContext(ctx).WithBody(&models.DetectsapiPostEntitiesAlertsV1Request{
			Ids: ids,
		}),
	)

	if err != nil {
		plugin.Logger(ctx).Error("crowdstrike_detects.getDetectsByIds", "PostEntitiesAlertsV1", err)
		return nil, err
	}
	if err = falcon.AssertNoError(response.Payload.Errors); err != nil {
		plugin.Logger(ctx).Error("crowdstrike_detects.getDetectsByIds", "PostEntitiesAlertsV1", err)
		return nil, err
	}

	return response.Payload.Resources, nil
}
