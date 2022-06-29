package crowdstrike

import (
	"context"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/user_management"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/turbot/steampipe-plugin-sdk/v3/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v3/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v3/plugin/transform"
)

func tableCrowdStrikeUserRole(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "crowdstrike_user_role",
		Description: "TODO.",
		List: &plugin.ListConfig{
			Hydrate: listCrowdStrikeUserRole,
		},
		Get: &plugin.GetConfig{
			Hydrate:    getCrowdStrikeUserRole,
			KeyColumns: plugin.AllColumns([]string{"id"}),
		},
		Columns: []*plugin.Column{
			{Name: "id", Description: "TODO", Type: proto.ColumnType_STRING},
			{Name: "cid", Description: "TODO.", Type: proto.ColumnType_STRING},
			{Name: "description", Description: "TODO.", Type: proto.ColumnType_STRING},
			{Name: "display_name", Description: "TODO.", Type: proto.ColumnType_STRING},
			// Steampipe standard columns
			{Name: "title", Description: "Title of the resource.", Type: proto.ColumnType_STRING, Transform: transform.FromField("DisplayName")},
		},
	}
}

type roleIdStruct struct {
	RoleId string
}

func listCrowdStrikeUserRole(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {
	client, err := getCrowdStrikeClient(ctx, d)
	if err != nil {
		plugin.Logger(ctx).Error("crowdstrike_host.listCrowdStrikeUserRole", "connection_error", err)
		return nil, err
	}

	if err := getRateLimiter(ctx, d).Wait(ctx); err != nil {
		return nil, err
	}

	response, err := client.UserManagement.GetAvailableRoleIds(
		user_management.NewGetAvailableRoleIdsParamsWithContext(ctx),
	)

	if err != nil {
		return nil, err
	}
	if err = falcon.AssertNoError(response.Payload.Errors); err != nil {
		return nil, err
	}

	roleIdbatch := response.Payload.Resources
	if roles, err := getUserRolesByIds(ctx, client, roleIdbatch); err == nil {
		for _, role := range roles {
			d.StreamListItem(ctx, role)
			if d.QueryStatus.RowsRemaining(ctx) < 1 {
				return nil, nil
			}
		}
	}

	return nil, nil
}

func getCrowdStrikeUserRole(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {
	client, err := getCrowdStrikeClient(ctx, d)
	if err != nil {
		plugin.Logger(ctx).Error("crowdstrike_host.getCrowdStrikeUserRole", "connection_error", err)
		return nil, err
	}

	var roleId string
	roleId = d.KeyColumnQuals["id"].GetStringValue()

	response, err := getUserRolesByIds(ctx, client, []string{roleId})

	if err != nil {
		plugin.Logger(ctx).Error("crowdstrike_host.getCrowdStrikeUserRole", "get_role_error", err)
		return nil, err
	}

	return response[0], nil
}

func getUserRolesByIds(ctx context.Context, client *client.CrowdStrikeAPISpecification, ids []string) ([]*models.DomainUserRole, error) {
	response, err := client.UserManagement.GetRoles(
		user_management.NewGetRolesParams().WithContext(ctx).WithIds(ids),
	)
	if err != nil {
		plugin.Logger(ctx).Error("crowdstrike_host.getUsersByIds", "RetrieveUserError", err)
		return nil, err
	}
	if err = falcon.AssertNoError(response.Payload.Errors); err != nil {
		plugin.Logger(ctx).Error("crowdstrike_host.getUsersByIds", "RetrieveUserError", err)
		return nil, err
	}

	return response.Payload.Resources, nil
}
