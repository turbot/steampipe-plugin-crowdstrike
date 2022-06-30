package crowdstrike

import (
	"context"
	"runtime/debug"
	"time"

	"github.com/crowdstrike/gofalcon/falcon"
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
		Description: "ZeroTrust Assessments.",
		List: &plugin.ListConfig{
			Hydrate:       listCrowdStrikeZtaAssesment,
			ParentHydrate: listCrowdStrikeHosts,
		},
		Columns: []*plugin.Column{
			{Name: "device_id", Description: "Host device ID.", Type: proto.ColumnType_STRING},
			{Name: "cid", Description: "The Customer ID.", Type: proto.ColumnType_STRING},
			{Name: "aid", Description: "The agent ID.", Type: proto.ColumnType_STRING},
			{Name: "assessment", Description: "The Assessment object.", Type: proto.ColumnType_JSON},
			{Name: "assessment_items", Description: "Assessment items.", Type: proto.ColumnType_JSON},
			{Name: "event_platform", Description: "The platform on which the event occurred.", Type: proto.ColumnType_STRING},
			{Name: "modified_time", Description: "Timestamp of last modified.", Type: proto.ColumnType_TIMESTAMP, Transform: transform.FromField("ModifiedTime").Transform(strfmtDatetimeTransformer)},
			{Name: "product_type_desc", Description: "Product type.", Type: proto.ColumnType_STRING},
			{Name: "sensor_file_status", Description: "Sensor file status.", Type: proto.ColumnType_STRING},
			{Name: "system_serial_number", Description: "System serial number.", Type: proto.ColumnType_STRING},

			// Steampipe standard columns
			{Name: "title", Description: "Title of the resource.", Type: proto.ColumnType_STRING, Transform: transform.FromField("SystemSerialNumber")},
		},
	}
}

func listCrowdStrikeZtaAssesment(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {
	client, err := getCrowdStrikeClient(ctx, d)
	if err != nil {
		plugin.Logger(ctx).Error("crowdstrike_zta_assessment.listCrowdStrikeZtaAssesment", "connection_error", err)
		return nil, err
	}

	var deviceId string
	defer func() {
		r := recover()
		if r != nil {
			plugin.Logger(ctx).Error("panic recover for device id", deviceId)
			plugin.Logger(ctx).Error("recovered error for device ", deviceId, r)
			plugin.Logger(ctx).Error("stack for device ", deviceId, string(debug.Stack()))

			debug.Stack()
		}
	}()

	if h.Item != nil {
		result := h.Item.(*models.DomainDeviceSwagger)
		deviceId = *result.DeviceID
	} else {
		deviceId = d.KeyColumnQuals["device_id"].GetStringValue()
	}

	plugin.Logger(ctx).Trace("DEVICE_ID", deviceId)

	response, err := client.ZeroTrustAssessment.GetAssessmentV1(
		zero_trust_assessment.NewGetAssessmentV1Params().
			WithContext(ctx).
			WithIds([]string{deviceId}),
	)
	if response != nil && (response.XRateLimitRemaining == 0) {
		time.Sleep(500 * time.Millisecond)
		return nil, nil
	}

	if err != nil {
		if _, ok := err.(*zero_trust_assessment.GetAssessmentV1NotFound); ok {
			// no records
			return nil, nil
		}
		return nil, err
	}
	if err = falcon.AssertNoError(response.Payload.Errors); err != nil {
		plugin.Logger(ctx).Error("crowdstrike_zta_assessment.listCrowdStrikeZtaAssesment", "assert_error", err)
		return nil, err
	}

	domainSignalProps := response.Payload.Resources
	if len(domainSignalProps) == 0 {
		return nil, nil
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

	return nil, nil
}
