package crowdstrike

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/turbot/steampipe-plugin-sdk/v3/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v3/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v3/plugin/quals"
)

func QualToFQL(ctx context.Context, d *plugin.QueryData, zeroValue string) (*string, error) {
	plugin.Logger(ctx).Trace("generating filter from quals")
	filters := []string{}
	for _, qualifiers := range d.Quals {
		// check if the context was cancelled
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		for _, qual := range qualifiers.Quals {
			if property, operator, value, err := contructFQLLine(qual); err != nil {
				filters = append(filters, fmt.Sprintf("%s:%s%s", property, operator, value))
			}
		}
	}
	constructedFilter := strings.Join(filters, "\n")
	if len(constructedFilter) == 0 {
		constructedFilter = zeroValue
	}
	plugin.Logger(ctx).Trace("Generated filter:", constructedFilter)
	return &constructedFilter, nil
}

func contructFQLLine(qual *quals.Qual) (property string, operator string, value string, _ error) {
	property = qual.Column
	switch qual.Operator {
	case ">":
		operator = ">"
	case ">=":
		operator = ">="
	case "=":
		operator = ""
	case "<=":
		operator = "<="
	case "<":
		operator = "<"
	case quals.QualOperatorIsNull:
		operator = ""
		value = "null"
		return
	}

	switch qual.Value.Value.(type) {
	case *proto.QualValue_BoolValue:
		value = fmt.Sprintf("%t", qual.Value.GetBoolValue())
	case *proto.QualValue_Int64Value:
		value = fmt.Sprintf("%d", qual.Value.GetInt64Value())
	case *proto.QualValue_DoubleValue:
		value = fmt.Sprintf("%f", qual.Value.GetDoubleValue())
	case *proto.QualValue_StringValue:
		value = fmt.Sprintf("'%s'", qual.Value.GetStringValue())
	case *proto.QualValue_TimestampValue:
		asUtcTime := qual.Value.GetTimestampValue().AsTime().UTC()
		value = fmt.Sprintf("'%s'", asUtcTime.Format(time.RFC3339))
	}

	return
}