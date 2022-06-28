package crowdstrike

import (
	"context"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client/user_management"
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
			{Name: "id", Description: "TODO", Type: proto.ColumnType_STRING, Hydrate: getCrowdStrikeUserRole},
			{Name: "cid", Description: "TODO.", Type: proto.ColumnType_STRING, Hydrate: getCrowdStrikeUserRole},
			{Name: "description", Description: "TODO.", Type: proto.ColumnType_STRING, Hydrate: getCrowdStrikeUserRole},
			{Name: "display_name", Description: "TODO.", Type: proto.ColumnType_STRING, Hydrate: getCrowdStrikeUserRole},
			// Steampipe standard columns
			{Name: "title", Description: "Title of the resource.", Type: proto.ColumnType_STRING, Transform: transform.FromField("Cid")},
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
		user_management.NewGetAvailableRoleIdsParams().WithContext(ctx),
	)

	if err != nil {
		return nil, err
	}
	if err = falcon.AssertNoError(response.Payload.Errors); err != nil {
		return nil, err
	}

	roleIdbatch := response.Payload.Resources

	for _, roleId := range roleIdbatch {
		d.StreamListItem(ctx, roleIdStruct{
			RoleId: roleId,
		})
		if d.QueryStatus.RowsRemaining(ctx) < 1 {
			return nil, nil
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

	if h.Item != nil {
		result := h.Item.(roleIdStruct)
		roleId = result.RoleId
	} else {
		roleId = d.KeyColumnQuals["id"].GetStringValue()
	}

	if err := getRateLimiter(ctx, d).Wait(ctx); err != nil {
		return nil, err
	}

	response, err := client.UserManagement.GetRoles(
		user_management.NewGetRolesParams().WithContext(ctx).WithIds([]string{roleId}),
	)

	if err != nil {
		plugin.Logger(ctx).Error("crowdstrike_host.getCrowdStrikeUserRole", "get_role_error", err)
		return nil, err
	}

	return response.Payload.Resources[0], nil
}
