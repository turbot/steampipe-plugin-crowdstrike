package crowdstrike

import (
	"context"
	"time"

	"github.com/go-openapi/strfmt"
)

func transformStrFmtDateTime(ctx context.Context, date strfmt.DateTime) (interface{}, error) {
	return date.String(), nil
}

func transformInt64Timestamp(ctx context.Context, date int64) (interface{}, error) {
	return time.Unix(date, 0).Format(time.RFC3339), nil
}
