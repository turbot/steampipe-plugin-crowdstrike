package crowdstrike

import (
	"context"
	"time"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/hosts"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/sethvargo/go-retry"
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
			{Name: "agent_load_flags", Description: "TODO.", Type: proto.ColumnType_INT},
			{Name: "agent_local_time", Description: "TODO.", Type: proto.ColumnType_TIMESTAMP},
			{Name: "agent_version", Description: "TODO.", Type: proto.ColumnType_STRING},

			{Name: "bios_manufacturer", Description: "TODO.", Type: proto.ColumnType_STRING},
			{Name: "bios_version", Description: "TODO.", Type: proto.ColumnType_STRING},

			{Name: "build_number", Description: "TODO.", Type: proto.ColumnType_STRING},

			{Name: "cid", Description: "TODO.", Type: proto.ColumnType_STRING},

			{Name: "config_id_base", Description: "TODO.", Type: proto.ColumnType_STRING},
			{Name: "config_id_build", Description: "TODO.", Type: proto.ColumnType_STRING},
			{Name: "config_id_platform", Description: "TODO.", Type: proto.ColumnType_STRING},

			{Name: "cpu_signature", Description: "TODO.", Type: proto.ColumnType_STRING},

			{Name: "detection_suppression_status", Description: "TODO.", Type: proto.ColumnType_STRING},

			{Name: "device_id", Description: "Host device ID.", Type: proto.ColumnType_STRING},
			{Name: "device_policies", Description: "TODO.", Type: proto.ColumnType_JSON},

			{Name: "email", Description: "TODO.", Type: proto.ColumnType_STRING},

			{Name: "external_ip", Description: "TODO.", Type: proto.ColumnType_STRING},

			{Name: "first_login_timestamp", Description: "TODO.", Type: proto.ColumnType_TIMESTAMP},
			{Name: "first_seen", Description: "TODO.", Type: proto.ColumnType_TIMESTAMP},

			{Name: "host_hidden_status", Description: "TODO.", Type: proto.ColumnType_STRING},

			{Name: "hostname", Description: "TODO.", Type: proto.ColumnType_STRING},

			{Name: "instance_id", Description: "TODO.", Type: proto.ColumnType_STRING},

			{Name: "last_login_timestamp", Description: "TODO.", Type: proto.ColumnType_TIMESTAMP},
			{Name: "last_seen", Description: "TODO.", Type: proto.ColumnType_TIMESTAMP},

			{Name: "local_ip", Description: "TODO.", Type: proto.ColumnType_INET},
			{Name: "mac_address", Description: "TODO.", Type: proto.ColumnType_STRING},
			{Name: "machine_domain", Description: "TODO.", Type: proto.ColumnType_STRING},

			{Name: "major_version", Description: "TODO.", Type: proto.ColumnType_STRING},
			{Name: "minor_version", Description: "TODO.", Type: proto.ColumnType_STRING},

			{Name: "managed_apps", Description: "TODO.", Type: proto.ColumnType_JSON},
			{Name: "meta", Description: "TODO.", Type: proto.ColumnType_JSON},

			{Name: "notes", Description: "TODO.", Type: proto.ColumnType_JSON},
			{Name: "os_version", Description: "TODO.", Type: proto.ColumnType_STRING},

			{Name: "ou", Description: "TODO.", Type: proto.ColumnType_JSON},

			{Name: "platform_id", Description: "TODO.", Type: proto.ColumnType_STRING},
			{Name: "platform_name", Description: "TODO.", Type: proto.ColumnType_STRING},

			{Name: "pod_id", Description: "TODO.", Type: proto.ColumnType_STRING},
			{Name: "pod_name", Description: "TODO.", Type: proto.ColumnType_STRING},
			{Name: "pod_namespace", Description: "TODO.", Type: proto.ColumnType_STRING},
			{Name: "pod_service_account_name", Description: "TODO.", Type: proto.ColumnType_STRING},
			{Name: "pod_hostname", Description: "TODO.", Type: proto.ColumnType_STRING},
			{Name: "pod_annotations", Description: "TODO.", Type: proto.ColumnType_JSON},
			{Name: "pod_labels", Description: "TODO.", Type: proto.ColumnType_JSON},
			{Name: "pod_host_ipv4", Transform: transform.FromField("PodHostIp4"), Description: "TODO.", Type: proto.ColumnType_INET},
			{Name: "pod_host_ipv6", Transform: transform.FromField("PodHostIp6"), Description: "TODO.", Type: proto.ColumnType_INET},
			{Name: "pod_ipv4", Transform: transform.FromField("PodIp4"), Description: "TODO.", Type: proto.ColumnType_INET},
			{Name: "pod_ipv6", Transform: transform.FromField("PodIp6"), Description: "TODO.", Type: proto.ColumnType_INET},

			{Name: "pointer_size", Description: "TODO.", Type: proto.ColumnType_INT},
			{Name: "policies", Description: "TODO.", Type: proto.ColumnType_JSON},

			{Name: "product_type", Description: "TODO.", Type: proto.ColumnType_STRING},
			{Name: "product_type_desc", Description: "TODO.", Type: proto.ColumnType_STRING},

			{Name: "provision_status", Description: "TODO.", Type: proto.ColumnType_STRING},
			{Name: "reduced_functionality_mode", Description: "TODO.", Type: proto.ColumnType_STRING},

			{Name: "release_group", Description: "TODO.", Type: proto.ColumnType_STRING},
			{Name: "serial_number", Description: "TODO.", Type: proto.ColumnType_STRING},

			{Name: "service_pack_major", Description: "TODO.", Type: proto.ColumnType_STRING},
			{Name: "service_pack_minor", Description: "TODO.", Type: proto.ColumnType_STRING},
			{Name: "service_provider", Description: "TODO.", Type: proto.ColumnType_STRING},
			{Name: "service_provider_account_id", Description: "TODO.", Type: proto.ColumnType_STRING},

			{Name: "site_name", Description: "TODO.", Type: proto.ColumnType_STRING},
			{Name: "slow_changing_modified_timestamp", Description: "TODO.", Type: proto.ColumnType_TIMESTAMP},

			{Name: "status", Description: "TODO.", Type: proto.ColumnType_STRING},

			{Name: "system_manufacturer", Description: "TODO.", Type: proto.ColumnType_STRING},
			{Name: "system_product_name", Description: "TODO.", Type: proto.ColumnType_STRING},

			{Name: "tags", Description: "TODO.", Type: proto.ColumnType_JSON},
			{Name: "zone_group", Description: "TODO.", Type: proto.ColumnType_STRING},

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

		if err := getRateLimiter(ctx, d).Wait(ctx); err != nil {
			return nil, err
		}

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
	err = retry.Constant(ctx, 500*time.Millisecond, func(ctx context.Context) error {
		response, err := client.Hosts.GetDeviceDetails(&hosts.GetDeviceDetailsParams{
			Ids:     ids,
			Context: ctx,
		})
		if response != nil && response.XRateLimitRemaining == 0 {
			return retry.RetryableError(ErrRateLimitExceeded)
		}
		if err != nil {
			plugin.Logger(ctx).Error("crowdstrike_host.GetCrowdStrikeHost", "get_device_error", err)
			return err
		}
		if err = falcon.AssertNoError(response.Payload.Errors); err != nil {
			return err
		}
		res = response.Payload.Resources

		return nil
	})
	return
}
