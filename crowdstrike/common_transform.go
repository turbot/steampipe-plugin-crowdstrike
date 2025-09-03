package crowdstrike

import (
	"context"
	"time"

	"github.com/go-openapi/strfmt"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"
)

func strfmtDatetimeTransformer(ctx context.Context, td *transform.TransformData) (interface{}, error) {
	if td == nil || td.Value == nil {
		return nil, nil
	}

	switch v := td.Value.(type) {
	case *strfmt.DateTime:
		if v == nil {
			return nil, nil
		}
		return v.String(), nil
	case strfmt.DateTime:
		return v.String(), nil
	default:
		return nil, nil
	}
}
func epochTimestampTransformer(ctx context.Context, td *transform.TransformData) (interface{}, error) {
	if td == nil || td.Value == nil {
		return nil, nil
	}

	switch v := td.Value.(type) {
	case *int64:
		if v == nil {
			return nil, nil
		}
		return time.Unix(*v, 0).Format(time.RFC3339), nil
	case int64:
		return time.Unix(v, 0).Format(time.RFC3339), nil
	case *int:
		if v == nil {
			return nil, nil
		}
		return time.Unix(int64(*v), 0).Format(time.RFC3339), nil
	case int:
		return time.Unix(int64(v), 0).Format(time.RFC3339), nil
	case float64:
		return time.Unix(int64(v), 0).Format(time.RFC3339), nil
	default:
		return nil, nil
	}
}
