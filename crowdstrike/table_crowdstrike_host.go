package crowdstrike

import (
	"context"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/hosts"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/turbot/steampipe-plugin-sdk/v4/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v4/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v4/plugin/transform"
)

//// TABLE DEFINITION

func tableCrowdStrikeHost(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "crowdstrike_host",
		Description: "Hosts are endpoints that run the Falcon sensor.",
		List: &plugin.ListConfig{
			Hydrate: listCrowdStrikeHosts,
		},
		Get: &plugin.GetConfig{
			Hydrate:    getCrowdStrikeHost,
			KeyColumns: plugin.SingleColumn("device_id"),
		},
		Columns: []*plugin.Column{
			{Name: "agent_load_flags", Description: "Load flags of the installed agent.", Type: proto.ColumnType_INT},
			{Name: "agent_local_time", Description: "Local time of the installed agent.", Type: proto.ColumnType_TIMESTAMP},
			{Name: "agent_version", Description: "The version of the installed agent.", Type: proto.ColumnType_STRING},
			{Name: "bios_manufacturer", Description: "The BIOS manufacturer.", Type: proto.ColumnType_STRING},
			{Name: "bios_version", Description: "The version of the BIOS.", Type: proto.ColumnType_STRING},
			{Name: "build_number", Description: "The build number.", Type: proto.ColumnType_STRING},
			{Name: "cid", Description: "The customer ID.", Type: proto.ColumnType_STRING},
			{Name: "config_id_base", Description: "Config ID base.", Type: proto.ColumnType_STRING},
			{Name: "config_id_build", Description: "Config ID build.", Type: proto.ColumnType_STRING},
			{Name: "config_id_platform", Description: "Config ID platform.", Type: proto.ColumnType_STRING},
			{Name: "cpu_signature", Description: "The CPU signature.", Type: proto.ColumnType_STRING},
			{Name: "detection_suppression_status", Description: "Detection suppression status.", Type: proto.ColumnType_STRING},
			{Name: "device_id", Description: "Host device ID.", Type: proto.ColumnType_STRING},
			{Name: "device_policies", Description: "The device control policies.", Type: proto.ColumnType_JSON},
			{Name: "email", Description: "The email address.", Type: proto.ColumnType_STRING},
			{Name: "external_ip", Description: "The external IP of the host.", Type: proto.ColumnType_INET},
			{Name: "first_login_timestamp", Description: "Time when the first login to this host was detected.", Type: proto.ColumnType_TIMESTAMP},
			{Name: "first_seen", Description: "Time when this host was first seen.", Type: proto.ColumnType_TIMESTAMP},
			{Name: "host_hidden_status", Description: "Whether the host is hidden.", Type: proto.ColumnType_STRING},
			{Name: "hostname", Description: "The system hostname.", Type: proto.ColumnType_STRING},
			{Name: "instance_id", Description: "The instance ID.", Type: proto.ColumnType_STRING},
			{Name: "last_login_timestamp", Description: "Time when the last login to this host was detected.", Type: proto.ColumnType_TIMESTAMP},
			{Name: "last_seen", Description: "Time when this host was last seen.", Type: proto.ColumnType_TIMESTAMP},
			{Name: "local_ip", Description: "The local IP address of the host.", Type: proto.ColumnType_INET},
			{Name: "mac_address", Description: "The MAC address of the host.", Type: proto.ColumnType_STRING},
			{Name: "machine_domain", Description: "The domain of the host.", Type: proto.ColumnType_STRING},
			{Name: "major_version", Description: "Major version.", Type: proto.ColumnType_STRING},
			{Name: "minor_version", Description: "Minor version.", Type: proto.ColumnType_STRING},
			{Name: "managed_apps", Description: "Apps managed by the agent.", Type: proto.ColumnType_JSON},
			{Name: "meta", Description: "Metadata information.", Type: proto.ColumnType_JSON},
			{Name: "notes", Description: "Notes (if any).", Type: proto.ColumnType_JSON},
			{Name: "os_version", Description: "The version of the operating system.", Type: proto.ColumnType_STRING},
			{Name: "ou", Description: "The organizational unit.", Type: proto.ColumnType_JSON},
			{Name: "platform_id", Description: "The ID of the platform in Falcon.", Type: proto.ColumnType_STRING},
			{Name: "platform_name", Description: "The platform running in the host.", Type: proto.ColumnType_STRING},
			{Name: "pod_id", Description: "Pod ID.", Type: proto.ColumnType_STRING},
			{Name: "pod_name", Description: "Pod name.", Type: proto.ColumnType_STRING},
			{Name: "pod_namespace", Description: "Pod namespace.", Type: proto.ColumnType_STRING},
			{Name: "pod_service_account_name", Description: "Pod service account name.", Type: proto.ColumnType_STRING},
			{Name: "pod_hostname", Description: "Pod hostname.", Type: proto.ColumnType_STRING},
			{Name: "pod_annotations", Description: "Pod annotations.", Type: proto.ColumnType_JSON},
			{Name: "pod_labels", Description: "Pod labels.", Type: proto.ColumnType_JSON},
			{Name: "pod_host_ipv4", Transform: transform.FromField("PodHostIp4"), Description: "IPv4 address of the pod host.", Type: proto.ColumnType_INET},
			{Name: "pod_host_ipv6", Transform: transform.FromField("PodHostIp6"), Description: "IPv6 address of the pod host.", Type: proto.ColumnType_INET},
			{Name: "pod_ipv4", Transform: transform.FromField("PodIp4"), Description: "IPv4 address of the pod.", Type: proto.ColumnType_INET},
			{Name: "pod_ipv6", Transform: transform.FromField("PodIp6"), Description: "IPv6 address of the pod.", Type: proto.ColumnType_INET},
			{Name: "pointer_size", Description: "Pointer size.", Type: proto.ColumnType_INT},
			{Name: "policies", Description: "Device control policies applied to this host.", Type: proto.ColumnType_JSON},
			{Name: "product_type", Description: "The type of hardware.", Type: proto.ColumnType_STRING},
			{Name: "product_type_desc", Description: "The description of the type of hardware.", Type: proto.ColumnType_STRING},
			{Name: "provision_status", Description: "The provisioning status.", Type: proto.ColumnType_STRING},
			{Name: "reduced_functionality_mode", Description: "Whether this host is operating with reduced functionality.", Type: proto.ColumnType_STRING},
			{Name: "release_group", Description: "The release group of the host.", Type: proto.ColumnType_STRING},
			{Name: "serial_number", Description: "The serial number.", Type: proto.ColumnType_STRING},
			{Name: "service_pack_major", Description: "Service pack minor version.", Type: proto.ColumnType_STRING},
			{Name: "service_pack_minor", Description: "Service pack major version.", Type: proto.ColumnType_STRING},
			{Name: "service_provider", Description: "Service provider.", Type: proto.ColumnType_STRING},
			{Name: "service_provider_account_id", Description: "Service provider account ID.", Type: proto.ColumnType_STRING},
			{Name: "site_name", Description: "Site name.", Type: proto.ColumnType_STRING},
			{Name: "slow_changing_modified_timestamp", Description: "Slow changing modified timestamp.", Type: proto.ColumnType_TIMESTAMP},
			{Name: "status", Description: "Operating ststus.", Type: proto.ColumnType_STRING},
			{Name: "system_manufacturer", Description: "The name of the manufacturer.", Type: proto.ColumnType_STRING},
			{Name: "system_product_name", Description: "The name of the product.", Type: proto.ColumnType_STRING},
			{Name: "tags", Description: "Falcon tags.", Type: proto.ColumnType_JSON},
			{Name: "zone_group", Description: "Zone group.", Type: proto.ColumnType_STRING},

			// Steampipe standard columns
			{Name: "title", Description: "Title of the resource.", Type: proto.ColumnType_STRING, Transform: transform.FromField("Hostname")},
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
	// Reduce the basic request limit down if the user has only requested a small number of rows
	if d.QueryContext.Limit != nil && *d.QueryContext.Limit < limit {
		limit = *d.QueryContext.Limit
	}

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
		if err = falcon.AssertNoError(response.Payload.Errors); err != nil {
			return nil, err
		}

		hostDeviceIds := response.Payload.Resources
		devices, err := getDeviceByIdBatch(ctx, client, hostDeviceIds)
		if err != nil {
			return nil, err
		}
		for _, device := range devices {
			d.StreamListItem(ctx, device)
			if d.QueryStatus.RowsRemaining(ctx) < 1 {
				return nil, nil
			}
		}

		if err != nil {
			return nil, err
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

func getDeviceByIdBatch(ctx context.Context, client *client.CrowdStrikeAPISpecification, ids []string) (res []*models.DomainDeviceSwagger, err error) {
	if len(ids) == 0 {
		return []*models.DomainDeviceSwagger{}, nil
	}
	response, err := client.Hosts.GetDeviceDetails(&hosts.GetDeviceDetailsParams{
		Ids:     ids,
		Context: ctx,
	})

	if err != nil {
		plugin.Logger(ctx).Error("crowdstrike_host.GetCrowdStrikeHost", "get_device_error", err)
		return nil, err
	}
	if err = falcon.AssertNoError(response.Payload.Errors); err != nil {
		return nil, err
	}

	return response.Payload.Resources, nil
}
