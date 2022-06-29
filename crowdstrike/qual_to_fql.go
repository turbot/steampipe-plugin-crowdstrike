package crowdstrike

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/turbot/go-kit/helpers"
	"github.com/turbot/steampipe-plugin-sdk/v3/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v3/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v3/plugin/quals"
)

var QualToFqlNoKeyignore = []string{}

const (
	qualToFqlTimestampFormat = time.RFC3339
)

func QualToFQL(ctx context.Context, d *plugin.QueryData, ignoreKeys []string, zeroValue ...string) (string, error) {
	plugin.Logger(ctx).Trace("generating filter from quals")
	filters := []string{}
	for key, qualifiers := range d.Quals {
		if helpers.StringSliceContains(ignoreKeys, key) {
			continue
		}
		// check if the context was cancelled
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		for _, qual := range qualifiers.Quals {
			property, operator, value := contructFQLLine(qual)
			filters = append(filters, fmt.Sprintf("%s: %s%s", property, operator, value))
		}
	}
	if len(filters) == 0 {
		filters = append([]string{}, zeroValue...)
	}

	constructedFilter := strings.Join(filters, "+")

	plugin.Logger(ctx).Trace("Generated filter", constructedFilter)
	return constructedFilter, nil
}

func contructFQLLine(qual *quals.Qual) (property string, operator string, value string) {
	property = qual.Column
	switch qual.Operator {
	case ">":
	case ">=":
		operator = ">"
	case "=":
		operator = ""
	case "<=":
	case "<":
		operator = "<"
	case quals.QualOperatorIsNull:
		operator = ""
		value = "null"
	case quals.QualOperatorIsNotNull:
		operator = "!"
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
		value = fmt.Sprintf("'%s'", asUtcTime.Format(qualToFqlTimestampFormat))
	}

	return
}
