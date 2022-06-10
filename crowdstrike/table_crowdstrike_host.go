package crowdstrike

import (
	"context"

	"github.com/crowdstrike/gofalcon/falcon/client/hosts"
	"github.com/turbot/steampipe-plugin-sdk/v3/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v3/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v3/plugin/transform"
)

//// TABLE DEFINITION

func tableCrowdStrikeHost(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "crowdstrike_host",
		Description: "TODO.",
		List: &plugin.ListConfig{
			Hydrate: listCrowdStrikeHosts,
		},
		Get: &plugin.GetConfig{
			Hydrate:    getCrowdStrikeHost,
			KeyColumns: plugin.SingleColumn("device_id"),
		},
		Columns: []*plugin.Column{
			{
				Name:        "device_id",
				Description: "Host device ID.",
				Type:        proto.ColumnType_STRING,
				Hydrate:     getCrowdStrikeHost,
			},
			{
				Name:        "agent_load_flags",
				Description: "TODO.",
				Type:        proto.ColumnType_INT,
				Hydrate:     getCrowdStrikeHost,
			},
			{
				Name:        "agent_local_time",
				Description: "TODO.",
				Type:        proto.ColumnType_TIMESTAMP,
				Hydrate:     getCrowdStrikeHost,
			},
			{
				Name:        "agent_version",
				Description: "TODO.",
				Type:        proto.ColumnType_STRING,
				Hydrate:     getCrowdStrikeHost,
			},
			{
				Name:        "hostname",
				Description: "TODO.",
				Type:        proto.ColumnType_STRING,
				Hydrate:     getCrowdStrikeHost,
			},
			{
				Name:        "raw",
				Description: "Raw info.",
				Type:        proto.ColumnType_JSON,
				Hydrate:     getCrowdStrikeHost,
				Transform:   transform.FromValue(),
			},

			// Steampipe standard columns
			{
				Name:        "title",
				Description: "Title of the resource.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("device_id"),
			},
		},
	}
}

type hostStruct struct {
	DeviceId string
}

//// LIST FUNCTION

func listCrowdStrikeHosts(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {
	client, err := getCrowdStrikeClient(ctx, d)
	if err != nil {
		plugin.Logger(ctx).Error("crowdstrike_host.listCrowdStrikeHosts", "connection_error", err)
		return nil, err
	}

	filter := ""
	var deviceIds []string

	limit := int64(500)

	for offset := ""; ; {
		response, err := client.Hosts.QueryDevicesByFilterScroll(&hosts.QueryDevicesByFilterScrollParams{
			Context: context.Background(),
			Limit:   &limit,
			Offset:  &offset,
			Filter:  &filter,
		})
		if err != nil {
			plugin.Logger(ctx).Error("crowdstrike_host.listCrowdStrikeHosts", "query_error", err)
			return nil, err
		}

		hostDeviceIds := response.Payload.Resources
		if len(hostDeviceIds) == 0 {
			break
		}

		deviceIds = append(deviceIds, hostDeviceIds...)

		if *response.Payload.Meta.Pagination.Offset == "" {
			break // no more next page indicates we are done
		}

		offset = *response.Payload.Meta.Pagination.Offset
	}

	for _, deviceId := range deviceIds {
		d.StreamListItem(ctx, hostStruct{
			DeviceId: deviceId,
		})
	}

	return nil, nil
}

//// HYDRATE FUNCTIONS

func getCrowdStrikeHost(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {
	client, err := getCrowdStrikeClient(ctx, d)
	if err != nil {
		plugin.Logger(ctx).Error("crowdstrike_host.getCrowdStrikeHost", "connection_error", err)
		return nil, err
	}

	var deviceId string

	if h.Item != nil {
		result := h.Item.(hostStruct)
		deviceId = result.DeviceId
	} else {
		deviceId = d.KeyColumnQuals["device_id"].GetStringValue()
	}

	response, err := client.Hosts.GetDeviceDetails(&hosts.GetDeviceDetailsParams{
		Ids:     []string{deviceId},
		Context: context.Background(),
	})

	if err != nil {
		plugin.Logger(ctx).Error("crowdstrike_host.GetCrowdStrikeHost", "get_device_error", err)
		return nil, err
	}

	return response.Payload.Resources[0], nil
}
