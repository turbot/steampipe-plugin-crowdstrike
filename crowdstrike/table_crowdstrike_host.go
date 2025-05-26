package crowdstrike

import (
	"context"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/hosts"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"
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
			{Name: "agent_version", Description: "The version of the installed agent.", Type: proto.ColumnType_STRING, Transform: transform.FromField("AgentVersion")},
			{Name: "config_id_base", Description: "Config ID base.", Type: proto.ColumnType_STRING, Transform: transform.FromField("ConfigIDBase")},
			{Name: "config_id_build", Description: "Config ID build.", Type: proto.ColumnType_STRING, Transform: transform.FromField("ConfigIDBuild")},
			{Name: "config_id_platform", Description: "Config ID platform.", Type: proto.ColumnType_STRING, Transform: transform.FromField("ConfigIDPlatform")},
			{Name: "device_id", Description: "Host device ID.", Type: proto.ColumnType_STRING, Transform: transform.FromField("DeviceID")},
			{Name: "device_policies", Description: "The device control policies.", Type: proto.ColumnType_JSON, Transform: transform.FromField("DevicePolicies")},
			{Name: "external_ip", Description: "The external IP of the host.", Type: proto.ColumnType_STRING, Transform: transform.FromField("ExternalIP")},
			{Name: "first_login_timestamp", Description: "Time when the first login to this host was detected.", Type: proto.ColumnType_STRING, Transform: transform.FromField("FirstLoginTimestamp")},
			{Name: "first_login_user", Description: "First login user.", Type: proto.ColumnType_STRING, Transform: transform.FromField("FirstLoginUser")},
			{Name: "first_seen", Description: "Time when this host was first seen.", Type: proto.ColumnType_STRING, Transform: transform.FromField("FirstSeen")},
			{Name: "hostname", Description: "The system hostname.", Type: proto.ColumnType_STRING, Transform: transform.FromField("Hostname")},
			{Name: "last_login_timestamp", Description: "Time when the last login to this host was detected.", Type: proto.ColumnType_STRING, Transform: transform.FromField("LastLoginTimestamp")},
			{Name: "last_login_user", Description: "Last login user.", Type: proto.ColumnType_STRING, Transform: transform.FromField("LastLoginUser")},
			{Name: "last_seen", Description: "Time when this host was last seen.", Type: proto.ColumnType_STRING, Transform: transform.FromField("LastSeen")},
			{Name: "last_seen_ago_seconds", Description: "Seconds since last seen.", Type: proto.ColumnType_INT, Transform: transform.FromField("LastSeenAgoSeconds")},
			{Name: "local_ip", Description: "The local IP address of the host.", Type: proto.ColumnType_STRING, Transform: transform.FromField("LocalIP")},
			{Name: "mac_address", Description: "The MAC address of the host.", Type: proto.ColumnType_STRING, Transform: transform.FromField("MacAddress")},
			{Name: "machine_domain", Description: "The domain of the host.", Type: proto.ColumnType_STRING, Transform: transform.FromField("MachineDomain")},
			{Name: "major_version", Description: "Major version.", Type: proto.ColumnType_STRING, Transform: transform.FromField("MajorVersion")},
			{Name: "minor_version", Description: "Minor version.", Type: proto.ColumnType_STRING, Transform: transform.FromField("MinorVersion")},
			{Name: "modified_timestamp", Description: "Last modified timestamp.", Type: proto.ColumnType_STRING, Transform: transform.FromField("ModifiedTimestamp")},
			{Name: "notes", Description: "Notes (if any).", Type: proto.ColumnType_JSON, Transform: transform.FromField("Notes")},
			{Name: "os_version", Description: "The version of the operating system.", Type: proto.ColumnType_STRING, Transform: transform.FromField("OsVersion")},
			{Name: "ou", Description: "The organizational unit.", Type: proto.ColumnType_JSON, Transform: transform.FromField("Ou")},
			{Name: "platform_id", Description: "The ID of the platform in Falcon.", Type: proto.ColumnType_STRING, Transform: transform.FromField("PlatformID")},
			{Name: "platform_name", Description: "The platform running in the host.", Type: proto.ColumnType_STRING, Transform: transform.FromField("PlatformName")},
			{Name: "product_type", Description: "The type of hardware.", Type: proto.ColumnType_STRING, Transform: transform.FromField("ProductType")},
			{Name: "product_type_desc", Description: "The description of the type of hardware.", Type: proto.ColumnType_STRING, Transform: transform.FromField("ProductTypeDesc")},
			{Name: "release_group", Description: "The release group of the host.", Type: proto.ColumnType_STRING, Transform: transform.FromField("ReleaseGroup")},
			{Name: "site_name", Description: "Site name.", Type: proto.ColumnType_STRING, Transform: transform.FromField("SiteName")},
			{Name: "status", Description: "Operating status.", Type: proto.ColumnType_STRING, Transform: transform.FromField("Status")},
			{Name: "system_manufacturer", Description: "The name of the manufacturer.", Type: proto.ColumnType_STRING, Transform: transform.FromField("SystemManufacturer")},
			{Name: "system_product_name", Description: "The name of the product.", Type: proto.ColumnType_STRING, Transform: transform.FromField("SystemProductName")},
			{Name: "tags", Description: "Falcon tags.", Type: proto.ColumnType_JSON, Transform: transform.FromField("Tags")},
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
			if d.RowsRemaining(ctx) < 1 {
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

	deviceId := d.EqualsQuals["device_id"].GetStringValue()

	return getDeviceByIdBatch(ctx, client, []string{deviceId})
}

func getDeviceByIdBatch(ctx context.Context, client *client.CrowdStrikeAPISpecification, ids []string) (res []*models.DeviceapiDeviceSwagger, err error) {
	if len(ids) == 0 {
		return []*models.DeviceapiDeviceSwagger{}, nil
	}
	params := hosts.NewGetDeviceDetailsV2Params().WithIds(ids).WithContext(ctx)
	response, err := client.Hosts.GetDeviceDetailsV2(params)
	if err != nil {
		plugin.Logger(ctx).Error("crowdstrike_host.GetCrowdStrikeHost", "get_device_error", err)
		return nil, err
	}
	if err = falcon.AssertNoError(response.Payload.Errors); err != nil {
		return nil, err
	}
	return response.Payload.Resources, nil
}
