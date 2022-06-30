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

func tableCrowdStrikeUser(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "crowdstrike_user",
		Description: "TODO.",
		List: &plugin.ListConfig{
			Hydrate: listCrowdStrikeUser,
		},
		Columns: []*plugin.Column{
			{Name: "customer", Description: "TODO", Type: proto.ColumnType_STRING},
			{Name: "first_name", Description: "TODO", Type: proto.ColumnType_STRING},
			{Name: "last_name", Description: "TODO", Type: proto.ColumnType_STRING},
			{Name: "uid", Description: "TODO", Type: proto.ColumnType_STRING},
			{Name: "uuid", Description: "TODO", Type: proto.ColumnType_STRING},
			{Name: "roles", Description: "Role IDs of roles assigned to a user", Type: proto.ColumnType_JSON, Hydrate: getCrowdStrikeUserRoleId},
			// Steampipe standard columns
			{Name: "title", Description: "Title of the resource.", Type: proto.ColumnType_STRING, Transform: transform.FromField("UID")},
		},
	}
}

func listCrowdStrikeUser(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {
	client, err := getCrowdStrikeClient(ctx, d)
	if err != nil {
		plugin.Logger(ctx).Error("crowdstrike_host.listCrowdStrikeUser", "connection_error", err)
		return nil, err
	}

	response, err := client.UserManagement.RetrieveUserUUIDsByCID(
		user_management.NewRetrieveUserUUIDsByCIDParamsWithContext(ctx),
	)

	if err != nil {
		return nil, err
	}
	if err = falcon.AssertNoError(response.Payload.Errors); err != nil {
		return nil, err
	}

	userIdBatch := response.Payload.Resources
	userBatch, err := getUsersByIds(ctx, client, userIdBatch)
	if err != nil {
		return nil, err
	}

	for _, user := range userBatch {
		d.StreamListItem(ctx, user)
		if d.QueryStatus.RowsRemaining(ctx) < 1 {
			return nil, nil
		}
	}

	return nil, nil
}

func getCrowdStrikeUserRoleId(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {
	client, err := getCrowdStrikeClient(ctx, d)
	if err != nil {
		plugin.Logger(ctx).Error("crowdstrike_user.getCrowdStrikeUser", "connection_error", err)
		return nil, err
	}

	item := h.Item.(*models.DomainUserMetadata)
	response, err := client.UserManagement.GetUserRoleIds(
		user_management.NewGetUserRoleIdsParamsWithContext(ctx).WithUserUUID(*item.UUID),
	)
	if err != nil {
		plugin.Logger(ctx).Error("crowdstrike_user.getCrowdStrikeUserRoleId", "RetrieveUserRoleError", err)
		return nil, err
	}
	if err = falcon.AssertNoError(response.Payload.Errors); err != nil {
		plugin.Logger(ctx).Error("crowdstrike_user.getCrowdStrikeUserRoleId", "RetrieveUserRoleError", err)
		return nil, err
	}

	plugin.Logger(ctx).Trace("", response.Payload.Resources)

	return response.Payload.Resources, nil
}

func getCrowdStrikeUser(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {
	client, err := getCrowdStrikeClient(ctx, d)
	if err != nil {
		plugin.Logger(ctx).Error("crowdstrike_host.getCrowdStrikeUser", "connection_error", err)
		return nil, err
	}

	userId := d.KeyColumnQuals["uid"].GetStringValue()

	u, err := getUsersByIds(ctx, client, []string{userId})
	if err != nil {
		return nil, err
	}

	return u[0], nil
}

func getUsersByIds(ctx context.Context, client *client.CrowdStrikeAPISpecification, ids []string) ([]*models.DomainUserMetadata, error) {
	if len(ids) == 0 {
		return []*models.DomainUserMetadata{}, nil
	}
	response, err := client.UserManagement.RetrieveUser(
		user_management.NewRetrieveUserParamsWithContext(ctx).WithIds(ids),
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
