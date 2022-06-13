package crowdstrike

import (
	"context"

	"github.com/go-openapi/strfmt"
)

func transformDate(ctx context.Context, date strfmt.DateTime) (interface{}, error) {
	return date.String(), nil
}
