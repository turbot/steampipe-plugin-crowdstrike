package crowdstrike

import (
	"context"
	"fmt"
	"math"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/quals"
)

var QualToFqlNoKeyignore = []string{}

const (
	qualToFqlTimestampFormat = time.RFC3339Nano
)

func QualToFQL(ctx context.Context, d *plugin.QueryData, ignoreKeys []string, zeroValue ...string) (string, error) {
	plugin.Logger(ctx).Trace("generating filter from quals")
	filters := []string{}
	keys := make([]string, 0, len(d.Quals))
	for key := range d.Quals {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if slices.Contains(ignoreKeys, key) {
			continue
		}
		// check if the context was cancelled
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		for _, qual := range d.Quals[key].Quals {
			property, operator, value, err := contructFQLLine(ctx, qual)
			if err != nil {
				return "", err
			}
			filters = append(filters, fmt.Sprintf("%s:%s%s", property, operator, value))
		}
	}
	if len(filters) == 0 {
		filters = append([]string{}, zeroValue...)
	}

	constructedFilter := strings.Join(filters, "+")

	plugin.Logger(ctx).Trace("Generated filter", constructedFilter)
	return constructedFilter, nil
}

func contructFQLLine(_ context.Context, qual *quals.Qual) (property string, operator string, value string, err error) {
	if qual == nil {
		return "", "", "", fmt.Errorf("cannot convert a nil qualifier to FQL")
	}
	property = qual.Column
	if property == "cve_id" {
		property = "cve.id"
	}
	switch qual.Operator {
	case ">", ">=", "<", "<=":
		operator = qual.Operator
	case "=":
		operator = ""
	case quals.QualOperatorIsNull:
		return property, "", "null", nil
	case quals.QualOperatorIsNotNull:
		return property, "!", "null", nil
	default:
		return "", "", "", fmt.Errorf("unsupported FQL operator %q for %s", qual.Operator, qual.Column)
	}

	if qual.Value == nil {
		return "", "", "", fmt.Errorf("missing FQL value for %s", qual.Column)
	}
	if list, ok := qual.Value.Value.(*proto.QualValue_ListValue); ok {
		if qual.Operator != "=" || list.ListValue == nil || len(list.ListValue.Values) == 0 {
			return "", "", "", fmt.Errorf("FQL lists require equality and at least one value for %s", qual.Column)
		}
		values := make([]string, 0, len(list.ListValue.Values))
		for _, item := range list.ListValue.Values {
			literal, literalErr := fqlScalar(item)
			if literalErr != nil {
				return "", "", "", fmt.Errorf("%s: %w", qual.Column, literalErr)
			}
			values = append(values, literal)
		}
		return property, operator, "[" + strings.Join(values, ",") + "]", nil
	}
	value, err = fqlScalar(qual.Value)
	return
}

func fqlScalar(value *proto.QualValue) (string, error) {
	if value == nil {
		return "", fmt.Errorf("missing FQL scalar value")
	}
	switch value.Value.(type) {
	case *proto.QualValue_BoolValue:
		return strconv.FormatBool(value.GetBoolValue()), nil
	case *proto.QualValue_Int64Value:
		return strconv.FormatInt(value.GetInt64Value(), 10), nil
	case *proto.QualValue_DoubleValue:
		number := value.GetDoubleValue()
		if math.IsNaN(number) || math.IsInf(number, 0) {
			return "", fmt.Errorf("non-finite FQL number")
		}
		return strconv.FormatFloat(number, 'f', -1, 64), nil
	case *proto.QualValue_StringValue:
		// Escape backslashes first, so an escaped quote cannot end the literal.
		escaped := strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(value.GetStringValue())
		return "'" + escaped + "'", nil
	case *proto.QualValue_TimestampValue:
		timestamp := value.GetTimestampValue()
		if err := timestamp.CheckValid(); err != nil {
			return "", fmt.Errorf("invalid FQL timestamp: %w", err)
		}
		return "'" + timestamp.AsTime().UTC().Format(qualToFqlTimestampFormat) + "'", nil
	default:
		return "", fmt.Errorf("unsupported FQL value type %T", value.Value)
	}
}
