package crowdstrike

import (
	"context"

	"github.com/go-openapi/strfmt"
)

func transformStrFmtDateTime(ctx context.Context, date strfmt.DateTime) (interface{}, error) {
	return date.String(), nil
}
