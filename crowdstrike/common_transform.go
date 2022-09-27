package crowdstrike

import (
	"context"
	"time"

	"github.com/go-openapi/strfmt"
	"github.com/turbot/steampipe-plugin-sdk/v4/plugin/transform"
)

func strfmtDatetimeTransformer(ctx context.Context, td *transform.TransformData) (interface{}, error) {
	return td.Value.(*strfmt.DateTime).String(), nil
}
func epochTimestampTransformer(ctx context.Context, td *transform.TransformData) (interface{}, error) {
	v := td.Value.(*int64)
	return time.Unix(*v, 0).Format(time.RFC3339), nil
}
