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

func tableCrowdStrikeAlert(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "crowdstrike_alert",
		Description: "Alerts are events identified by Falcon sensors on the hosts in your environment. This table uses the new Alerts API (replacing the deprecated Detects API).",
		List: &plugin.ListConfig{
			Hydrate: listCrowdStrikeAlerts,
			KeyColumns: []*plugin.KeyColumn{
				{
					Name:      "created_timestamp",
					Require:   plugin.Optional,
					Operators: []string{">", ">=", "=", "<", "<="},
				},
				{
					Name:      "status",
					Require:   plugin.Optional,
					Operators: []string{"="},
				},
				{
					Name:      "composite_id",
					Require:   plugin.Optional,
					Operators: []string{"="},
				},
				{
					Name:      "aggregate_id",
					Require:   plugin.Optional,
					Operators: []string{"="},
				},
				{
					Name:      "filter",
					Require:   plugin.Optional,
					Operators: []string{"="},
				},
				{
					Name:      "severity",
					Require:   plugin.Optional,
					Operators: []string{">", ">=", "=", "<", "<="},
				},
				{
					Name:      "confidence",
					Require:   plugin.Optional,
					Operators: []string{">", ">=", "=", "<", "<="},
				},
			},
		},
		Get: &plugin.GetConfig{
			KeyColumns: plugin.SingleColumn("composite_id"),
			Hydrate:    getCrowdStrikeAlert,
		},
		Columns: []*plugin.Column{
			{Name: "composite_id", Description: "The unique identifier for this alert.", Type: proto.ColumnType_STRING, Transform: transform.FromField("CompositeID")},
			{Name: "aggregate_id", Description: "References a logical grouping of alerts. It represents the Agent ID & Process Tree ID, similar to the legacy detection_id.", Type: proto.ColumnType_STRING, Transform: transform.FromField("AggregateID")},
			{Name: "agent_id", Description: "Device or sensor ID for which the Alert was generated.", Type: proto.ColumnType_STRING, Transform: transform.FromField("AgentID")},
			{Name: "assigned_to_name", Description: "The human-readable name of the user to whom the alert is currently assigned.", Type: proto.ColumnType_STRING, Transform: transform.FromField("AssignedToName")},
			{Name: "assigned_to_uid", Description: "The UID of the user to whom the alert is currently assigned.", Type: proto.ColumnType_STRING, Transform: transform.FromField("AssignedToUID")},
			{Name: "assigned_to_uuid", Description: "The UUID of the user to whom the alert is currently assigned.", Type: proto.ColumnType_STRING, Transform: transform.FromField("AssignedToUUID")},
			{Name: "filter", Description: "The filter expression to filter the alerts.", Type: proto.ColumnType_STRING, Transform: transform.FromQual("filter")},
			{Name: "cid", Description: "Your organization's customer ID (CID).", Type: proto.ColumnType_STRING, Transform: transform.FromField("Cid")},
			{Name: "created_timestamp", Description: "Timestamp when this alert was first created.", Type: proto.ColumnType_TIMESTAMP, Transform: transform.FromField("CreatedTimestamp").Transform(strfmtDatetimeTransformer)},
			{Name: "updated_timestamp", Description: "Timestamp when this alert was last modified.", Type: proto.ColumnType_TIMESTAMP, Transform: transform.FromField("UpdatedTimestamp").Transform(strfmtDatetimeTransformer)},
			{Name: "crawled_timestamp", Description: "Timestamp when ThreatGraph was crawled to gather info for this alert creation/update.", Type: proto.ColumnType_TIMESTAMP, Transform: transform.FromField("CrawledTimestamp").Transform(strfmtDatetimeTransformer)},
			{Name: "context_timestamp", Description: "Context timestamp for the alert.", Type: proto.ColumnType_TIMESTAMP, Transform: transform.FromField("ContextTimestamp").Transform(strfmtDatetimeTransformer)},
			{Name: "timestamp", Description: "Stored value coming in directly from the ingested event or set by cloud in the absence of it.", Type: proto.ColumnType_TIMESTAMP, Transform: transform.FromField("Timestamp").Transform(strfmtDatetimeTransformer)},
			{Name: "device", Description: "The device where this was detected.", Type: proto.ColumnType_JSON, Transform: transform.FromField("Device")},
			{Name: "email_sent", Description: "Whether email was sent when this was detected.", Type: proto.ColumnType_BOOL, Transform: transform.FromField("EmailSent")},
			{Name: "show_in_ui", Description: "Whether this is shown in the User Interface.", Type: proto.ColumnType_BOOL, Transform: transform.FromField("ShowInUI")},
			{Name: "external", Description: "Boolean indicating if this Alert is internal or external.", Type: proto.ColumnType_BOOL, Transform: transform.FromField("External")},
			{Name: "status", Description: "The current status of the alert. Values include new, in_progress, true_positive, false_positive, and ignored.", Type: proto.ColumnType_STRING, Transform: transform.FromField("Status")},
			{Name: "resolution", Description: "Alert resolution. Could be one of the following values: true_positive, false_positive, ignored.", Type: proto.ColumnType_STRING, Transform: transform.FromField("Resolution")},
			{Name: "severity", Description: "The severity value of the alert. Value can be any integer between 1-100.", Type: proto.ColumnType_INT, Transform: transform.FromField("Severity")},
			{Name: "confidence", Description: "The confidence value of the alert. Value can be any integer between 1-100.", Type: proto.ColumnType_INT, Transform: transform.FromField("Confidence")},
			{Name: "severity_name", Description: "The name used in the UI to determine the severity of the alert. Values include Critical, High, Medium, and Low", Type: proto.ColumnType_STRING, Transform: transform.FromField("SeverityName")},
			{Name: "tags", Description: "Tags are string values associated with the alert that can be added or removed through the API.", Type: proto.ColumnType_JSON, Transform: transform.FromField("Tags")},
			{Name: "seconds_to_resolved", Description: "Time that it took to move an alert from new to one of the resolved states (true_positive, false_positive, and ignored).", Type: proto.ColumnType_INT, Transform: transform.FromField("SecondsToResolved")},
			{Name: "seconds_to_triaged", Description: "Time that it took to move an alert from new to in_progress.", Type: proto.ColumnType_INT, Transform: transform.FromField("SecondsToTriaged")},
			{Name: "quarantined_files", Description: "Files that have been quarantined.", Type: proto.ColumnType_JSON, Transform: transform.FromField("QuarantinedFiles")},
			{Name: "name", Description: "Pattern Name coming either from Taxonomy or directly from the ingested Alert.", Type: proto.ColumnType_STRING, Transform: transform.FromField("Name")},
			{Name: "display_name", Description: "Customer visible name for the Alert's pattern.", Type: proto.ColumnType_STRING, Transform: transform.FromField("DisplayName")},
			{Name: "description", Description: "Short, customer-visible summary of the detected activity.", Type: proto.ColumnType_STRING, Transform: transform.FromField("Description")},
			{Name: "type", Description: "Type of definition Detections Extensibility use. Keyed-off of Pattern of the incoming events/Alerts.", Type: proto.ColumnType_STRING, Transform: transform.FromField("Type")},
			{Name: "pattern_id", Description: "Taxonomy patternID for this Alert.", Type: proto.ColumnType_INT, Transform: transform.FromField("PatternID")},
			{Name: "platform", Description: "Platform that this Alert was triggered on e.g. Android, Windows, etc.", Type: proto.ColumnType_STRING, Transform: transform.FromField("Platform")},
			{Name: "product", Description: "Product specifies the SKU that this Alert belongs to e.g. mobile, idp, epp.", Type: proto.ColumnType_STRING, Transform: transform.FromField("Product")},
			{Name: "scenario", Description: "Scenario was used pre-Handrails to display additional killchain context for UI alerts.", Type: proto.ColumnType_STRING, Transform: transform.FromField("Scenario")},
			{Name: "objective", Description: "End goal that an attack adversary intends to achieve according to MITRE.", Type: proto.ColumnType_STRING, Transform: transform.FromField("Objective")},
			{Name: "tactic", Description: "Tactic reference to MITRE ATT&CK, which is a public framework for tracking and modeling adversary tools techniques and procedures.", Type: proto.ColumnType_STRING, Transform: transform.FromField("Tactic")},
			{Name: "tactic_id", Description: "Unique ID for the tactic seen in the Alert.", Type: proto.ColumnType_STRING, Transform: transform.FromField("TacticID")},
			{Name: "technique", Description: "Technique reference to MITRE ATT&CK, which is a public framework for tracking and modeling adversary tools techniques and procedures.", Type: proto.ColumnType_STRING, Transform: transform.FromField("Technique")},
			{Name: "technique_id", Description: "Unique ID for the technique seen in the Alert.", Type: proto.ColumnType_STRING, Transform: transform.FromField("TechniqueID")},
			{Name: "mitre_attack", Description: "References to MITRE ATT&CK, which is a public framework for tracking and modeling adversary tools techniques and procedures.", Type: proto.ColumnType_JSON, Transform: transform.FromField("MitreAttack")},
			{Name: "data_domains", Description: "Data Domains represents domains to which this alert belongs to.", Type: proto.ColumnType_JSON, Transform: transform.FromField("DataDomains")},
			{Name: "source_products", Description: "Source Products are products that produced events which contributed to this alert.", Type: proto.ColumnType_JSON, Transform: transform.FromField("SourceProducts")},
			{Name: "source_vendors", Description: "Source Vendors are vendors that produced events which contributed to this alert.", Type: proto.ColumnType_JSON, Transform: transform.FromField("SourceVendors")},
			{Name: "linked_case_ids", Description: "Linked Case Ids are cases that are associated with this alert.", Type: proto.ColumnType_JSON, Transform: transform.FromField("LinkedCaseIds")},
			{Name: "id", Description: "Vertex key which triggers the formation of the Alert.", Type: proto.ColumnType_STRING, Transform: transform.FromField("ID")},
			{Name: "process_id", Description: "Process ID associated with the alert.", Type: proto.ColumnType_STRING, Transform: transform.FromField("ProcessID")},
			{Name: "parent_process_id", Description: "Parent process ID associated with the alert.", Type: proto.ColumnType_STRING, Transform: transform.FromField("ParentProcessID")},
			{Name: "local_process_id", Description: "Local process ID associated with the alert.", Type: proto.ColumnType_STRING, Transform: transform.FromField("LocalProcessID")},
			{Name: "process_start_time", Description: "Process start time.", Type: proto.ColumnType_STRING, Transform: transform.FromField("ProcessStartTime")},
			{Name: "process_end_time", Description: "Process end time.", Type: proto.ColumnType_STRING, Transform: transform.FromField("ProcessEndTime")},
			{Name: "tree_id", Description: "Tree ID associated with the alert.", Type: proto.ColumnType_STRING, Transform: transform.FromField("TreeID")},
			{Name: "tree_root", Description: "Tree root associated with the alert.", Type: proto.ColumnType_STRING, Transform: transform.FromField("TreeRoot")},
			{Name: "triggering_process_graph_id", Description: "Triggering process graph ID.", Type: proto.ColumnType_STRING, Transform: transform.FromField("TriggeringProcessGraphID")},
			{Name: "control_graph_id", Description: "Control graph ID.", Type: proto.ColumnType_STRING, Transform: transform.FromField("ControlGraphID")},
			{Name: "user_id", Description: "User ID associated with the alert.", Type: proto.ColumnType_STRING, Transform: transform.FromField("UserID")},
			{Name: "user_name", Description: "User name associated with the alert.", Type: proto.ColumnType_STRING, Transform: transform.FromField("UserName")},
			{Name: "logon_domain", Description: "Logon domain associated with the alert.", Type: proto.ColumnType_STRING, Transform: transform.FromField("LogonDomain")},
			{Name: "cmdline", Description: "Command line associated with the alert.", Type: proto.ColumnType_STRING, Transform: transform.FromField("Cmdline")},
			{Name: "filename", Description: "Filename associated with the alert.", Type: proto.ColumnType_STRING, Transform: transform.FromField("Filename")},
			{Name: "filepath", Description: "File path associated with the alert.", Type: proto.ColumnType_STRING, Transform: transform.FromField("Filepath")},
			{Name: "md5", Description: "MD5 hash associated with the alert.", Type: proto.ColumnType_STRING, Transform: transform.FromField("Md5")},
			{Name: "sha1", Description: "SHA1 hash associated with the alert.", Type: proto.ColumnType_STRING, Transform: transform.FromField("Sha1")},
			{Name: "sha256", Description: "SHA256 hash associated with the alert.", Type: proto.ColumnType_STRING, Transform: transform.FromField("Sha256")},
			{Name: "alleged_filetype", Description: "Alleged file type associated with the alert.", Type: proto.ColumnType_STRING, Transform: transform.FromField("AllegedFiletype")},
			{Name: "cloud_indicator", Description: "Cloud indicator associated with the alert.", Type: proto.ColumnType_STRING, Transform: transform.FromField("CloudIndicator")},
			{Name: "poly_id", Description: "Poly ID associated with the alert.", Type: proto.ColumnType_STRING, Transform: transform.FromField("PolyID")},
			{Name: "indicator_id", Description: "Indicator ID associated with the alert.", Type: proto.ColumnType_STRING, Transform: transform.FromField("IndicatorID")},
			{Name: "ioc_type", Description: "IOC type associated with the alert.", Type: proto.ColumnType_STRING, Transform: transform.FromField("IocType")},
			{Name: "ioc_value", Description: "IOC value associated with the alert.", Type: proto.ColumnType_STRING, Transform: transform.FromField("IocValue")},
			{Name: "ioc_values", Description: "IOC values associated with the alert.", Type: proto.ColumnType_JSON, Transform: transform.FromField("IocValues")},
			{Name: "ioc_description", Description: "IOC description associated with the alert.", Type: proto.ColumnType_STRING, Transform: transform.FromField("IocDescription")},
			{Name: "ioc_source", Description: "IOC source associated with the alert.", Type: proto.ColumnType_STRING, Transform: transform.FromField("IocSource")},
			{Name: "ioc_context", Description: "IOC context associated with the alert.", Type: proto.ColumnType_JSON, Transform: transform.FromField("IocContext")},
			{Name: "falcon_host_link", Description: "Falcon host link associated with the alert.", Type: proto.ColumnType_STRING, Transform: transform.FromField("FalconHostLink")},
			{Name: "has_script_or_module_ioce", Description: "Boolean indicating if the alert has script or module IOCE.", Type: proto.ColumnType_BOOL, Transform: transform.FromField("HasScriptOrModuleIoce")},
			{Name: "is_synthetic_quarantine_disposition", Description: "Boolean indicating if the alert has synthetic quarantine disposition.", Type: proto.ColumnType_BOOL, Transform: transform.FromField("IsSyntheticQuarantineDisposition")},
			{Name: "pattern_disposition", Description: "Pattern disposition associated with the alert.", Type: proto.ColumnType_INT, Transform: transform.FromField("PatternDisposition")},
			{Name: "pattern_disposition_description", Description: "Pattern disposition description associated with the alert.", Type: proto.ColumnType_STRING, Transform: transform.FromField("PatternDispositionDescription")},
			{Name: "pattern_disposition_details", Description: "Pattern disposition details associated with the alert.", Type: proto.ColumnType_JSON, Transform: transform.FromField("PatternDispositionDetails")},
			{Name: "parent_details", Description: "Parent details associated with the alert.", Type: proto.ColumnType_JSON, Transform: transform.FromField("ParentDetails")},
			{Name: "grandparent_details", Description: "Grandparent details associated with the alert.", Type: proto.ColumnType_JSON, Transform: transform.FromField("GrandparentDetails")},
			{Name: "crawl_edge_ids", Description: "Crawl edge IDs associated with the alert.", Type: proto.ColumnType_JSON, Transform: transform.FromField("CrawlEdgeIds")},
			{Name: "crawl_vertex_ids", Description: "Crawl vertex IDs associated with the alert.", Type: proto.ColumnType_JSON, Transform: transform.FromField("CrawlVertexIds")},
			{Name: "major_version", Description: "Major version associated with the alert.", Type: proto.ColumnType_STRING, Transform: transform.FromField("MajorVersion")},
			{Name: "minor_version", Description: "Minor version associated with the alert.", Type: proto.ColumnType_STRING, Transform: transform.FromField("MinorVersion")},
			// Steampipe standard columns
			{Name: "title", Description: "Title of the resource.", Type: proto.ColumnType_STRING, Transform: transform.FromField("DisplayName")},
		},
	}
}

//// LIST FUNCTION

func listCrowdStrikeAlerts(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {

	client, err := getCrowdStrikeClient(ctx, d)
	if err != nil {
		plugin.Logger(ctx).Error("crowdstrike_alert.listCrowdStrikeAlerts", "connection_error", err)
		return nil, err
	}

	limit := int64(500)
	// Reduce the basic request limit down if the user has only requested a small number of rows
	if d.QueryContext.Limit != nil && *d.QueryContext.Limit < limit {
		limit = *d.QueryContext.Limit
	}
	ignoreKeys := []string{"filter"}
	filter, err := QualToFQL(ctx, d, ignoreKeys, "")
	if err != nil {
		return nil, err
	}

	filterQueryParam := d.EqualsQuals["filter"].GetStringValue()

	if filterQueryParam != "" {
		filter = filterQueryParam
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
			plugin.Logger(ctx).Error("crowdstrike_alert.listCrowdStrikeAlerts", "query_error", err)
			return nil, err
		}
		if err = falcon.AssertNoError(response.Payload.Errors); err != nil {
			plugin.Logger(ctx).Error("crowdstrike_alert.listCrowdStrikeAlerts", "assert_error", err)
			return nil, err
		}

		// Batch size
		batchSize := 999
		alertIdBatch := response.Payload.Resources

		for i := 0; i < len(alertIdBatch); i += batchSize {
			// Get the end index for the batch
			end := i + batchSize
			if end > len(alertIdBatch) {
				end = len(alertIdBatch) // Ensure we don't go out of bounds
			}

			// Extract the batch
			batchIds := alertIdBatch[i:end]

			plugin.Logger(ctx).Trace("alert batch length", len(batchIds))
			batchAlerts, err := getAlertsByIds(ctx, client, batchIds)
			if err != nil {
				return nil, err
			}

			for _, alert := range batchAlerts {
				d.StreamListItem(ctx, alert)
				if d.RowsRemaining(ctx) < 1 {
					return nil, nil
				}
			}

		}
		offset = offset + int64(len(alertIdBatch))
		if offset >= *response.Payload.Meta.Pagination.Total {
			break
		}
	}

	return nil, nil
}

func getCrowdStrikeAlert(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {
	client, err := getCrowdStrikeClient(ctx, d)
	if err != nil {
		plugin.Logger(ctx).Error("crowdstrike_alert.getCrowdStrikeAlert", "connection_error", err)
		return nil, err
	}

	compositeId := d.EqualsQuals["composite_id"].GetStringValue()

	alert, err := getAlertsByIds(ctx, client, []string{compositeId})

	if err != nil {
		plugin.Logger(ctx).Error("crowdstrike_alert.getCrowdStrikeAlert", "GetAlertDetails error", err)
		return nil, err
	}

	return alert[0], nil
}

func getAlertsByIds(ctx context.Context, client *client.CrowdStrikeAPISpecification, ids []string) ([]*models.DetectsAlert, error) {
	if len(ids) == 0 {
		return []*models.DetectsAlert{}, nil
	}

	response, err := client.Alerts.GetV2(&alerts.GetV2Params{
		Body: &models.DetectsapiPostEntitiesAlertsV2Request{
			CompositeIds: ids,
		},
	})

	if err != nil {
		plugin.Logger(ctx).Error("crowdstrike_alert.getAlertsByIds", "GetAlertDetails", err)
		return nil, err
	}
	if err = falcon.AssertNoError(response.Payload.Errors); err != nil {
		plugin.Logger(ctx).Error("crowdstrike_alert.getAlertsByIds", "GetAlertDetails", err)
		return nil, err
	}

	return response.Payload.Resources, nil
}
