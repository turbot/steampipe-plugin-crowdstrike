package crowdstrike

import (
	"context"
	"errors"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/hosts"
	"github.com/crowdstrike/gofalcon/falcon/models"
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
			{Name: "agent_load_flags", Description: "TODO.", Type: proto.ColumnType_INT, Hydrate: getCrowdStrikeHost},
			{Name: "agent_local_time", Description: "TODO.", Type: proto.ColumnType_TIMESTAMP, Hydrate: getCrowdStrikeHost},
			{Name: "agent_version", Description: "TODO.", Type: proto.ColumnType_STRING, Hydrate: getCrowdStrikeHost},

			{Name: "bios_manufacturer", Description: "TODO.", Type: proto.ColumnType_STRING, Hydrate: getCrowdStrikeHost},
			{Name: "bios_version", Description: "TODO.", Type: proto.ColumnType_STRING, Hydrate: getCrowdStrikeHost},

			{Name: "build_number", Description: "TODO.", Type: proto.ColumnType_STRING, Hydrate: getCrowdStrikeHost},

			{Name: "cid", Description: "TODO.", Type: proto.ColumnType_STRING, Hydrate: getCrowdStrikeHost},

			{Name: "config_id_base", Description: "TODO.", Type: proto.ColumnType_STRING, Hydrate: getCrowdStrikeHost},
			{Name: "config_id_build", Description: "TODO.", Type: proto.ColumnType_STRING, Hydrate: getCrowdStrikeHost},
			{Name: "config_id_platform", Description: "TODO.", Type: proto.ColumnType_STRING, Hydrate: getCrowdStrikeHost},

			{Name: "cpu_signature", Description: "TODO.", Type: proto.ColumnType_STRING, Hydrate: getCrowdStrikeHost},

			{Name: "detection_suppression_status", Description: "TODO.", Type: proto.ColumnType_STRING, Hydrate: getCrowdStrikeHost},

			{Name: "device_id", Description: "Host device ID.", Type: proto.ColumnType_STRING, Hydrate: getCrowdStrikeHost},
			{Name: "device_policies", Description: "TODO.", Type: proto.ColumnType_JSON, Hydrate: getCrowdStrikeHost},

			{Name: "email", Description: "TODO.", Type: proto.ColumnType_STRING, Hydrate: getCrowdStrikeHost},

			{Name: "external_ip", Description: "TODO.", Type: proto.ColumnType_STRING, Hydrate: getCrowdStrikeHost},

			{Name: "first_login_timestamp", Description: "TODO.", Type: proto.ColumnType_TIMESTAMP, Hydrate: getCrowdStrikeHost},
			{Name: "first_seen", Description: "TODO.", Type: proto.ColumnType_TIMESTAMP, Hydrate: getCrowdStrikeHost},

			{Name: "host_hidden_status", Description: "TODO.", Type: proto.ColumnType_STRING, Hydrate: getCrowdStrikeHost},

			{Name: "hostname", Description: "TODO.", Type: proto.ColumnType_STRING, Hydrate: getCrowdStrikeHost},

			{Name: "instance_id", Description: "TODO.", Type: proto.ColumnType_STRING, Hydrate: getCrowdStrikeHost},

			{Name: "last_login_timestamp", Description: "TODO.", Type: proto.ColumnType_TIMESTAMP, Hydrate: getCrowdStrikeHost},
			{Name: "last_seen", Description: "TODO.", Type: proto.ColumnType_TIMESTAMP, Hydrate: getCrowdStrikeHost},

			{Name: "local_ip", Description: "TODO.", Type: proto.ColumnType_INET, Hydrate: getCrowdStrikeHost},
			{Name: "mac_address", Description: "TODO.", Type: proto.ColumnType_STRING, Hydrate: getCrowdStrikeHost},
			{Name: "machine_domain", Description: "TODO.", Type: proto.ColumnType_STRING, Hydrate: getCrowdStrikeHost},

			{Name: "major_version", Description: "TODO.", Type: proto.ColumnType_STRING, Hydrate: getCrowdStrikeHost},
			{Name: "minor_version", Description: "TODO.", Type: proto.ColumnType_STRING, Hydrate: getCrowdStrikeHost},

			{Name: "managed_apps", Description: "TODO.", Type: proto.ColumnType_JSON, Hydrate: getCrowdStrikeHost},
			{Name: "meta", Description: "TODO.", Type: proto.ColumnType_JSON, Hydrate: getCrowdStrikeHost},

			{Name: "notes", Description: "TODO.", Type: proto.ColumnType_JSON, Hydrate: getCrowdStrikeHost},
			{Name: "os_version", Description: "TODO.", Type: proto.ColumnType_STRING, Hydrate: getCrowdStrikeHost},

			{Name: "ou", Description: "TODO.", Type: proto.ColumnType_JSON, Hydrate: getCrowdStrikeHost},

			{Name: "platform_id", Description: "TODO.", Type: proto.ColumnType_STRING, Hydrate: getCrowdStrikeHost},
			{Name: "platform_name", Description: "TODO.", Type: proto.ColumnType_STRING, Hydrate: getCrowdStrikeHost},

			{Name: "pod_id", Description: "TODO.", Type: proto.ColumnType_STRING, Hydrate: getCrowdStrikeHost},
			{Name: "pod_name", Description: "TODO.", Type: proto.ColumnType_STRING, Hydrate: getCrowdStrikeHost},
			{Name: "pod_namespace", Description: "TODO.", Type: proto.ColumnType_STRING, Hydrate: getCrowdStrikeHost},
			{Name: "pod_service_account_name", Description: "TODO.", Type: proto.ColumnType_STRING, Hydrate: getCrowdStrikeHost},
			{Name: "pod_hostname", Description: "TODO.", Type: proto.ColumnType_STRING, Hydrate: getCrowdStrikeHost},
			{Name: "pod_annotations", Description: "TODO.", Type: proto.ColumnType_JSON, Hydrate: getCrowdStrikeHost},
			{Name: "pod_labels", Description: "TODO.", Type: proto.ColumnType_JSON, Hydrate: getCrowdStrikeHost},
			{Name: "pod_host_ipv4", Transform: transform.FromField("PodHostIp4"), Description: "TODO.", Type: proto.ColumnType_INET, Hydrate: getCrowdStrikeHost},
			{Name: "pod_host_ipv6", Transform: transform.FromField("PodHostIp6"), Description: "TODO.", Type: proto.ColumnType_INET, Hydrate: getCrowdStrikeHost},
			{Name: "pod_ipv4", Transform: transform.FromField("PodIp4"), Description: "TODO.", Type: proto.ColumnType_INET, Hydrate: getCrowdStrikeHost},
			{Name: "pod_ipv6", Transform: transform.FromField("PodIp6"), Description: "TODO.", Type: proto.ColumnType_INET, Hydrate: getCrowdStrikeHost},

			{Name: "pointer_size", Description: "TODO.", Type: proto.ColumnType_INT, Hydrate: getCrowdStrikeHost},
			{Name: "policies", Description: "TODO.", Type: proto.ColumnType_JSON, Hydrate: getCrowdStrikeHost},

			{Name: "product_type", Description: "TODO.", Type: proto.ColumnType_STRING, Hydrate: getCrowdStrikeHost},
			{Name: "product_type_desc", Description: "TODO.", Type: proto.ColumnType_STRING, Hydrate: getCrowdStrikeHost},

			{Name: "provision_status", Description: "TODO.", Type: proto.ColumnType_STRING, Hydrate: getCrowdStrikeHost},
			{Name: "reduced_functionality_mode", Description: "TODO.", Type: proto.ColumnType_STRING, Hydrate: getCrowdStrikeHost},

			{Name: "release_group", Description: "TODO.", Type: proto.ColumnType_STRING, Hydrate: getCrowdStrikeHost},
			{Name: "serial_number", Description: "TODO.", Type: proto.ColumnType_STRING, Hydrate: getCrowdStrikeHost},

			{Name: "service_pack_major", Description: "TODO.", Type: proto.ColumnType_STRING, Hydrate: getCrowdStrikeHost},
			{Name: "service_pack_minor", Description: "TODO.", Type: proto.ColumnType_STRING, Hydrate: getCrowdStrikeHost},
			{Name: "service_provider", Description: "TODO.", Type: proto.ColumnType_STRING, Hydrate: getCrowdStrikeHost},
			{Name: "service_provider_account_id", Description: "TODO.", Type: proto.ColumnType_STRING, Hydrate: getCrowdStrikeHost},

			{Name: "site_name", Description: "TODO.", Type: proto.ColumnType_STRING, Hydrate: getCrowdStrikeHost},
			{Name: "slow_changing_modified_timestamp", Description: "TODO.", Type: proto.ColumnType_TIMESTAMP, Hydrate: getCrowdStrikeHost},

			{Name: "status", Description: "TODO.", Type: proto.ColumnType_STRING, Hydrate: getCrowdStrikeHost},

			{Name: "system_manufacturer", Description: "TODO.", Type: proto.ColumnType_STRING, Hydrate: getCrowdStrikeHost},
			{Name: "system_product_name", Description: "TODO.", Type: proto.ColumnType_STRING, Hydrate: getCrowdStrikeHost},

			{Name: "tags", Description: "TODO.", Type: proto.ColumnType_JSON, Hydrate: getCrowdStrikeHost},
			{Name: "zone_group", Description: "TODO.", Type: proto.ColumnType_STRING, Hydrate: getCrowdStrikeHost},

			// Steampipe standard columns
			{Name: "title", Description: "Title of the resource.", Type: proto.ColumnType_STRING, Hydrate: getCrowdStrikeHost, Transform: transform.FromField("Hostname")},
		},
	}
}

//// LIST FUNCTION

func listCrowdStrikeHosts(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {
	client, err := getCrowdStrikeClient(ctx, d)
	if err != nil {
		plugin.Logger(ctx).Error("crowdstrike_host.listCrowdStrikeHosts", "connection_error", err)
		return nil, err
	}

	filter := ""

	limit := int64(500)
	offset := ""

	for {
		response, err := client.Hosts.QueryDevicesByFilterScroll(&hosts.QueryDevicesByFilterScrollParams{
			Context: ctx,
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
			return nil, nil
		}
		devices, err := getDeviceByIdBatch(ctx, client, hostDeviceIds)
		for _, device := range devices {
			d.StreamListItem(ctx, device)
			if d.QueryStatus.RowsRemaining(ctx) < 1 {
				return nil, nil
			}
		}

		if *response.Payload.Meta.Pagination.Offset == "" {
			break // no more next page indicates we are done
		}

		offset = *response.Payload.Meta.Pagination.Offset
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

	deviceId := d.KeyColumnQuals["device_id"].GetStringValue()

	return getDeviceByIdBatch(ctx, client, []string{deviceId})
}

func getDeviceByIdBatch(ctx context.Context, client *client.CrowdStrikeAPISpecification, ids []string) ([]*models.DomainDeviceSwagger, error) {
	response, err := client.Hosts.GetDeviceDetails(&hosts.GetDeviceDetailsParams{
		Ids:     ids,
		Context: ctx,
	})

	if err != nil {
		plugin.Logger(ctx).Error("crowdstrike_host.GetCrowdStrikeHost", "get_device_error", err)
		return nil, errors.New(falcon.ErrorExplain(err))
	}
	if err = falcon.AssertNoError(response.Payload.Errors); err != nil {
		return nil, err
	}

	return response.Payload.Resources, err
}
