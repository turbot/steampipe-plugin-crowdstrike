package crowdstrike

import (
	"context"
	"time"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client/zero_trust_assessment"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/sethvargo/go-retry"
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
			{Name: "cid", Description: "The Customer ID.", Type: proto.ColumnType_STRING},
			{Name: "aid", Description: "TODO", Type: proto.ColumnType_STRING},
			{Name: "assessment", Description: "The Assessment object", Type: proto.ColumnType_JSON},
			{Name: "assessment_items", Description: "Assessment items", Type: proto.ColumnType_JSON},
			{Name: "event_platform", Description: "TODO", Type: proto.ColumnType_STRING},
			{Name: "modified_time", Description: "TODO", Type: proto.ColumnType_TIMESTAMP, Transform: transform.From(func(ctx context.Context, td *transform.TransformData) (interface{}, error) {
				assessment := td.HydrateItem.(ztaAssesmentStruct)
				return transformStrFmtDateTime(ctx, *assessment.ModifiedTime)
			})},
			{Name: "product_type_desc", Description: "TODO", Type: proto.ColumnType_STRING},
			{Name: "sensor_file_status", Description: "TODO", Type: proto.ColumnType_STRING},
			{Name: "system_serial_number", Description: "TODO", Type: proto.ColumnType_STRING},

			// Steampipe standard columns
			{Name: "title", Description: "Title of the resource.", Type: proto.ColumnType_STRING, Transform: transform.FromField("Hostname")},
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

	if h.Item != nil {
		result := h.Item.(*models.DomainDeviceSwagger)
		deviceId = *result.DeviceID
	} else {
		deviceId = d.KeyColumnQuals["device_id"].GetStringValue()
	}

	for {
		var response *zero_trust_assessment.GetAssessmentV1OK
		err = retry.Constant(ctx, 500*time.Millisecond, func(retryCtx context.Context) error {
			if retryCtx.Err() != nil {
				return retryCtx.Err()
			}
			response, err := client.ZeroTrustAssessment.GetAssessmentV1(
				zero_trust_assessment.NewGetAssessmentV1Params().
					WithContext(retryCtx).
					WithIds([]string{deviceId}),
			)
			if response.XRateLimitRemaining == 0 {
				return retry.RetryableError(err)
			}
			if err != nil {
				if _, ok := err.(*zero_trust_assessment.GetAssessmentV1NotFound); ok {
					return retry.RetryableError(err)
				}
				plugin.Logger(retryCtx).Error("crowdstrike_zta_assessment.listCrowdStrikeZtaAssesment", "query_error", err)
				return err
			}
			if err = falcon.AssertNoError(response.Payload.Errors); err != nil {
				plugin.Logger(retryCtx).Error("crowdstrike_zta_assessment.listCrowdStrikeZtaAssesment", "assert_error", err)
				return err
			}
			return nil
		})

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
