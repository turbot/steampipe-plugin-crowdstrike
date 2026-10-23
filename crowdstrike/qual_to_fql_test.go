package crowdstrike

import (
	"context"
	"math"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/context_key"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/quals"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func fqlTestString(value string) *proto.QualValue {
	return &proto.QualValue{Value: &proto.QualValue_StringValue{StringValue: value}}
}

func fqlTestList(values ...*proto.QualValue) *proto.QualValue {
	return &proto.QualValue{Value: &proto.QualValue_ListValue{ListValue: &proto.QualValueList{Values: values}}}
}

func fqlTestContext() context.Context {
	return context.WithValue(context.Background(), context_key.Logger, hclog.NewNullLogger())
}

func TestQualToFQLMultipleLists(t *testing.T) {
	d := &plugin.QueryData{Quals: plugin.KeyColumnQualMap{
		"cve_id": {Quals: quals.QualSlice{{Column: "cve_id", Operator: "=", Value: fqlTestList(fqlTestString("CVE-2026-109618"), fqlTestString("CVE-2026-109619"))}}},
		"status": {Quals: quals.QualSlice{{Column: "status", Operator: "=", Value: fqlTestList(fqlTestString("open"), fqlTestString("reopen"))}}},
	}}
	got, err := QualToFQL(fqlTestContext(), d, nil)
	want := "cve.id:['CVE-2026-109618','CVE-2026-109619']+status:['open','reopen']"
	if err != nil || got != want {
		t.Fatalf("QualToFQL = %q, %v; want %q", got, err, want)
	}
}

func TestConstructFQLLine(t *testing.T) {
	timestamp := time.Date(2026, 10, 23, 12, 34, 56, 123456789, time.FixedZone("offset", 3600))
	for _, test := range []struct {
		name, column, operator, want string
		value                        *proto.QualValue
	}{
		{"cve mapping", "cve_id", "=", "cve.id:'CVE-2026-109618'", fqlTestString("CVE-2026-109618")},
		{"escaped quote and slash", "slug", "=", `slug:'O\'Brien\\host'`, fqlTestString(`O'Brien\host`)},
		{"greater inclusive precision", "created_timestamp", ">=", "created_timestamp:>='2026-10-23T11:34:56.123456789Z'", &proto.QualValue{Value: &proto.QualValue_TimestampValue{TimestampValue: timestamppb.New(timestamp)}}},
		{"less inclusive", "severity", "<=", "severity:<=5", &proto.QualValue{Value: &proto.QualValue_Int64Value{Int64Value: 5}}},
		{"greater", "confidence", ">", "confidence:>0.123456789", &proto.QualValue{Value: &proto.QualValue_DoubleValue{DoubleValue: 0.123456789}}},
		{"less", "confidence", "<", "confidence:<9", &proto.QualValue{Value: &proto.QualValue_Int64Value{Int64Value: 9}}},
		{"boolean", "active", "=", "active:true", &proto.QualValue{Value: &proto.QualValue_BoolValue{BoolValue: true}}},
		{"is null", "closed_timestamp", quals.QualOperatorIsNull, "closed_timestamp:null", nil},
		{"is not null", "closed_timestamp", quals.QualOperatorIsNotNull, "closed_timestamp:!null", nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			property, operator, value, err := contructFQLLine(context.Background(), &quals.Qual{Column: test.column, Operator: test.operator, Value: test.value})
			got := property + ":" + operator + value
			if err != nil || got != test.want {
				t.Fatalf("contructFQLLine = %q, %v; want %q", got, err, test.want)
			}
		})
	}
}

func TestQualToFQLRejectsUnsupportedInputs(t *testing.T) {
	for _, test := range []struct {
		name string
		qual *quals.Qual
	}{
		{"nil qual", nil},
		{"unsupported operator", &quals.Qual{Column: "status", Operator: "LIKE", Value: fqlTestString("open%")}},
		{"missing scalar", &quals.Qual{Column: "status", Operator: "="}},
		{"unsupported JSON", &quals.Qual{Column: "status", Operator: "=", Value: &proto.QualValue{Value: &proto.QualValue_JsonbValue{JsonbValue: `{}`}}}},
		{"empty list", &quals.Qual{Column: "status", Operator: "=", Value: fqlTestList()}},
		{"nil list item", &quals.Qual{Column: "status", Operator: "=", Value: fqlTestList(nil)}},
		{"nested list", &quals.Qual{Column: "status", Operator: "=", Value: fqlTestList(fqlTestList(fqlTestString("open")))}},
		{"list comparison", &quals.Qual{Column: "status", Operator: ">", Value: fqlTestList(fqlTestString("open"))}},
		{"non-finite float", &quals.Qual{Column: "confidence", Operator: "=", Value: &proto.QualValue{Value: &proto.QualValue_DoubleValue{DoubleValue: math.Inf(1)}}}},
		{"invalid timestamp", &quals.Qual{Column: "created_timestamp", Operator: "=", Value: &proto.QualValue{Value: &proto.QualValue_TimestampValue{TimestampValue: &timestamppb.Timestamp{Seconds: math.MaxInt64}}}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			d := &plugin.QueryData{Quals: plugin.KeyColumnQualMap{"test": {Quals: quals.QualSlice{test.qual}}}}
			got, err := QualToFQL(fqlTestContext(), d, nil)
			if err == nil || got != "" {
				t.Fatalf("QualToFQL = %q, %v; want empty filter and error", got, err)
			}
		})
	}
}

func TestQualToFQLDefaultIgnoredAndCancellation(t *testing.T) {
	d := &plugin.QueryData{Quals: plugin.KeyColumnQualMap{"filter": {Quals: quals.QualSlice{{Column: "filter", Operator: "=", Value: fqlTestString("raw")}}}}}
	got, err := QualToFQL(fqlTestContext(), d, []string{"filter"}, "default-filter")
	if err != nil || got != "default-filter" {
		t.Fatalf("default filter = %q, %v", got, err)
	}
	ctx, cancel := context.WithCancel(fqlTestContext())
	cancel()
	if _, err := QualToFQL(ctx, d, nil); err != context.Canceled {
		t.Fatalf("cancelled query error = %v", err)
	}
}

func TestSpotlightCVEColumnAndKey(t *testing.T) {
	table := tableCrowdStrikeSpotlightVulnerability(context.Background())
	columns := map[string]*plugin.Column{}
	for _, column := range table.Columns {
		columns[column.Name] = column
	}
	if columns["cve"] == nil || columns["cve"].Type != proto.ColumnType_JSON {
		t.Fatal("existing cve JSON column must remain available")
	}
	if columns["cve_id"] == nil || columns["cve_id"].Type != proto.ColumnType_STRING || columns["cve_id"].Transform == nil {
		t.Fatal("cve_id must be a transformed string column")
	}
	for _, key := range table.List.KeyColumns {
		if key.Name == "cve_id" && key.Require == plugin.Optional && len(key.Operators) == 1 && key.Operators[0] == "=" {
			return
		}
	}
	t.Fatal("cve_id must be an optional equality key")
}
