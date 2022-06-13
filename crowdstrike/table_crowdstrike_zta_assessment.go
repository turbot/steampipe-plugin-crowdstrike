package crowdstrike

import (
	"context"

	"github.com/crowdstrike/gofalcon/falcon/client/zero_trust_assessment"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/turbot/steampipe-plugin-sdk/v3/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v3/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v3/plugin/transform"
)

type ztaAssesmentStruct struct {
	models.DomainSignalProperties
	DeviceID string
}

func tableCrowdStrikeZtaAssessment(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "crowdstrike_zta_assessment",
		Description: "TODO.",
		List: &plugin.ListConfig{
			Hydrate:       listCrowdStrikeZtaAssesment,
			ParentHydrate: listCrowdStrikeHosts,
		},
		Columns: []*plugin.Column{
			{Name: "device_id", Description: "Host device ID.", Type: proto.ColumnType_STRING},
			{Name: "cid", Description: "TODO", Type: proto.ColumnType_STRING},
			{Name: "aid", Description: "TODO", Type: proto.ColumnType_STRING},
			{Name: "assessment", Description: "TODO", Type: proto.ColumnType_JSON},
			{Name: "assessment_items", Description: "TODO", Type: proto.ColumnType_JSON},
			{Name: "event_platform", Description: "TODO", Type: proto.ColumnType_STRING},
			{Name: "modified_time", Description: "TODO", Type: proto.ColumnType_TIMESTAMP, Transform: transform.From(func(ctx context.Context, td *transform.TransformData) (interface{}, error) {
				breach := td.HydrateItem.(ztaAssesmentStruct)
				return transformDate(ctx, *breach.ModifiedTime)
			})},
			{Name: "product_type_desc", Description: "TODO", Type: proto.ColumnType_STRING},
			{Name: "sensor_file_status", Description: "TODO", Type: proto.ColumnType_STRING},
			{Name: "system_serial_number", Description: "TODO", Type: proto.ColumnType_STRING},
			{Name: "raw", Description: "Raw info.", Type: proto.ColumnType_JSON, Transform: transform.FromValue()},

			// Steampipe standard columns
			{Name: "title", Description: "Title of the resource.", Type: proto.ColumnType_STRING, Transform: transform.FromField("Hostname")},
		},
	}
}

func listCrowdStrikeZtaAssesment(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {
	client, err := getCrowdStrikeClient(ctx, d)
	if err != nil {
		plugin.Logger(ctx).Error("crowdstrike_host.listCrowdStrikeZtaAssesment", "connection_error", err)
		return nil, err
	}

	var deviceId string

	if h.Item != nil {
		plugin.Logger(ctx).Trace("h.Item is not nil")
		result := h.Item.(hostStruct)
		deviceId = result.DeviceId
		plugin.Logger(ctx).Trace("deviceID is", deviceId)
	} else {
		plugin.Logger(ctx).Trace("h.Item is nil")
		deviceId = d.KeyColumnQuals["device_id"].GetStringValue()
	}

	for {
		response, err := client.ZeroTrustAssessment.GetAssessmentV1(
			zero_trust_assessment.NewGetAssessmentV1Params().
				WithContext(ctx).
				WithIds([]string{deviceId}),
		)
		if err != nil {
			plugin.Logger(ctx).Error("crowdstrike_host.listCrowdStrikeHosts", "query_error", err)
			return nil, err
		}

		domainSignalProps := response.Payload.Resources
		if len(domainSignalProps) == 0 {
			break
		}

		for _, dsp := range domainSignalProps {
			d.StreamListItem(ctx, ztaAssesmentStruct{
				DomainSignalProperties: *dsp,
				DeviceID:               deviceId,
			})
			if d.QueryStatus.RowsRemaining(ctx) < 1 {
				return nil, nil
			}
		}
	}

	return nil, nil
}
