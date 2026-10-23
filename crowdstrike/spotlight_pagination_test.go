package crowdstrike

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/models"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
	"github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/quals"
)

func spotlightTestClient(t *testing.T, handler http.HandlerFunc) *client.CrowdStrikeAPISpecification {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	transport := httptransport.New(serverURL.Host, "", []string{"https"})
	transport.Transport = server.Client().Transport
	transport.Debug = false
	return client.New(transport, strfmt.Default)
}

func spotlightJSON(w http.ResponseWriter, value interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

func spotlightPage(ids []string, after interface{}, limit int) map[string]interface{} {
	return map[string]interface{}{"resources": ids, "errors": []interface{}{}, "meta": map[string]interface{}{"pagination": map[string]interface{}{"limit": limit, "after": after}}}
}

func spotlightDetails(w http.ResponseWriter, r *http.Request) {
	resources := make([]map[string]string, 0)
	for _, id := range r.URL.Query()["ids"] {
		resources = append(resources, map[string]string{"id": id})
	}
	spotlightJSON(w, map[string]interface{}{"resources": resources, "errors": []interface{}{}})
}

func TestSpotlightDetailBatchSizes(t *testing.T) {
	for _, count := range []int{0, 1, 399, 400, 401} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			ids := make([]string, count)
			for i := range ids {
				ids[i] = fmt.Sprint(i)
			}
			queryCalls := 0
			batches := []int{}
			api := spotlightTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/spotlight/queries/vulnerabilities/v1":
					queryCalls++
					spotlightJSON(w, spotlightPage(ids, "", 400))
				case "/spotlight/entities/vulnerabilities/v2":
					batches = append(batches, len(r.URL.Query()["ids"]))
					spotlightDetails(w, r)
				default:
					t.Errorf("unexpected endpoint %s", r.URL.Path)
					http.NotFound(w, r)
				}
			})
			got := []string{}
			err := fetchSpotlightVulnerabilities(context.Background(), api, "cve.id:'CVE-2026-109618'", 400, func(v *models.DomainAPIVulnerabilityV2) bool { got = append(got, *v.ID); return true })
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, ids) {
				t.Fatalf("IDs: got %d, want %d", len(got), len(ids))
			}
			wantBatches := []int{}
			for remaining := count; remaining > 0; remaining -= 400 {
				size := remaining
				if size > 400 {
					size = 400
				}
				wantBatches = append(wantBatches, size)
			}
			if queryCalls != 1 || !reflect.DeepEqual(batches, wantBatches) {
				t.Fatalf("requests: query=%d batches=%v, want query=1 batches=%v", queryCalls, batches, wantBatches)
			}
		})
	}
}

func TestSpotlightPaginationSafety(t *testing.T) {
	tests := []struct {
		name      string
		pages     []map[string]interface{}
		wantRows  int
		wantError string
	}{
		{"missing metadata", []map[string]interface{}{{"resources": []string{"a"}}}, 0, "pagination information missing"},
		{"missing pagination", []map[string]interface{}{{"resources": []string{"a"}, "meta": map[string]interface{}{}}}, 0, "pagination information missing"},
		{"missing limit", []map[string]interface{}{{"resources": []string{"a"}, "meta": map[string]interface{}{"pagination": map[string]interface{}{"after": "next"}}}}, 0, "pagination information missing"},
		{"invalid limit", []map[string]interface{}{spotlightPage([]string{"a"}, "next", 0)}, 0, "invalid page limit"},
		{"missing cursor ends", []map[string]interface{}{spotlightPage([]string{"a"}, nil, 1)}, 1, ""},
		{"empty cursor ends", []map[string]interface{}{spotlightPage([]string{"a"}, "", 1)}, 1, ""},
		{"short page with cursor continues", []map[string]interface{}{spotlightPage([]string{"a"}, "next", 400), spotlightPage([]string{"b"}, "", 400)}, 2, ""},
		{"repeated cursor", []map[string]interface{}{spotlightPage([]string{"a"}, "same", 1), spotlightPage([]string{"b"}, "same", 1)}, 1, "repeated continuation cursor"},
		{"cursor cycle", []map[string]interface{}{spotlightPage([]string{"a"}, "first", 1), spotlightPage([]string{"b"}, "second", 1), spotlightPage([]string{"c"}, "first", 1)}, 2, "repeated continuation cursor"},
		{"successive pages", []map[string]interface{}{spotlightPage([]string{"a"}, "first", 1), spotlightPage([]string{"b"}, "second", 1), spotlightPage([]string{"c"}, "", 1)}, 3, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			queryCalls := 0
			api := spotlightTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				if strings.Contains(r.URL.Path, "/queries/") {
					if queryCalls >= len(tt.pages) {
						t.Error("unexpected extra page request")
						http.Error(w, "too many pages", 500)
						return
					}
					if queryCalls > 0 {
						previousMeta := tt.pages[queryCalls-1]["meta"].(map[string]interface{})
						previousPaging := previousMeta["pagination"].(map[string]interface{})
						if got, want := r.URL.Query().Get("after"), previousPaging["after"].(string); got != want {
							t.Errorf("request after = %q, want %q", got, want)
						}
					}
					spotlightJSON(w, tt.pages[queryCalls])
					queryCalls++
				} else {
					spotlightDetails(w, r)
				}
			})
			rows := 0
			err := fetchSpotlightVulnerabilities(context.Background(), api, "status:'open'", 1, func(*models.DomainAPIVulnerabilityV2) bool { rows++; return true })
			if tt.wantError == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("got error %v, want %s", err, tt.wantError)
			}
			if rows != tt.wantRows || queryCalls != len(tt.pages) {
				t.Fatalf("rows=%d queries=%d; want rows=%d queries=%d", rows, queryCalls, tt.wantRows, len(tt.pages))
			}
		})
	}
}

func TestSpotlightCancellationStopsRequests(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	api := spotlightTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if strings.Contains(r.URL.Path, "/queries/") {
			spotlightJSON(w, spotlightPage([]string{"a", "b"}, "next", 2))
		} else {
			spotlightDetails(w, r)
		}
	})
	rows := 0
	err := fetchSpotlightVulnerabilities(ctx, api, "status:'open'", 2, func(*models.DomainAPIVulnerabilityV2) bool { rows++; cancel(); return true })
	if !errors.Is(err, context.Canceled) || rows != 1 || calls != 2 {
		t.Fatalf("error=%v rows=%d calls=%d", err, rows, calls)
	}
	calls = 0
	err = fetchSpotlightVulnerabilities(ctx, api, "status:'open'", 2, func(*models.DomainAPIVulnerabilityV2) bool { return true })
	if !errors.Is(err, context.Canceled) || calls != 0 {
		t.Fatalf("pre-cancel error=%v calls=%d", err, calls)
	}
}

func TestSpotlightFirstRequestIncludesCVEAndStatusLists(t *testing.T) {
	listQual := func(column string, values ...string) *plugin.KeyColumnQuals {
		list := &proto.QualValueList{}
		for _, value := range values {
			list.Values = append(list.Values, &proto.QualValue{Value: &proto.QualValue_StringValue{StringValue: value}})
		}
		return &plugin.KeyColumnQuals{Quals: quals.QualSlice{&quals.Qual{Column: column, Operator: "=", Value: &proto.QualValue{Value: &proto.QualValue_ListValue{ListValue: list}}}}}
	}
	d := &plugin.QueryData{Quals: plugin.KeyColumnQualMap{"cve_id": listQual("cve_id", "CVE-2026-109618", "CVE-2026-109619"), "status": listQual("status", "open", "reopen")}}
	filter, err := QualToFQL(fqlTestContext(), d, QualToFqlNoKeyignore, "created_timestamp:>'0001-01-01T00:00:00Z'")
	if err != nil {
		t.Fatal(err)
	}
	want := "cve.id:['CVE-2026-109618','CVE-2026-109619']+status:['open','reopen']"
	calls := 0
	api := spotlightTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if got := r.URL.Query().Get("filter"); got != want {
			t.Errorf("FIRST API filter = %q, want %q", got, want)
		}
		spotlightJSON(w, spotlightPage([]string{}, "", 400))
	})
	if err = fetchSpotlightVulnerabilities(context.Background(), api, filter, 400, func(*models.DomainAPIVulnerabilityV2) bool { return true }); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("API calls = %d, want 1", calls)
	}
}

func TestSpotlightDetailsErrorsAndEmpty(t *testing.T) {
	for _, tt := range []struct {
		name, body string
		wantError  bool
	}{
		{"empty", `{"resources":[],"errors":[]}`, false},
		{"API error", `{"resources":[],"errors":[{"code":400,"message":"bad request"}]}`, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			api := spotlightTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, tt.body)
			})
			rows, err := getVulnerabilityDetails(context.Background(), api, []string{"a"})
			if (err != nil) != tt.wantError || len(rows) != 0 {
				t.Fatalf("rows=%v error=%v", rows, err)
			}
		})
	}
}

func TestSpotlightCancellationInterruptsHTTPRequest(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{})
	api := spotlightTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
	})
	done := make(chan error, 1)
	go func() {
		done <- fetchSpotlightVulnerabilities(ctx, api, "status:'open'", 400, func(*models.DomainAPIVulnerabilityV2) bool { return true })
	}()
	<-started
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want cancellation", err)
	}
}

func TestSpotlightCallerCanStopWithoutAnotherPage(t *testing.T) {
	calls := 0
	api := spotlightTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if strings.Contains(r.URL.Path, "/queries/") {
			spotlightJSON(w, spotlightPage([]string{"a", "b"}, "next", 2))
		} else {
			spotlightDetails(w, r)
		}
	})
	rows := 0
	err := fetchSpotlightVulnerabilities(context.Background(), api, "status:'open'", 2, func(*models.DomainAPIVulnerabilityV2) bool { rows++; return false })
	if err != nil || rows != 1 || calls != 2 {
		t.Fatalf("err=%v rows=%d calls=%d", err, rows, calls)
	}
}

func TestSpotlightQueryAPIErrorStopsBeforeDetails(t *testing.T) {
	calls := 0
	api := spotlightTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		spotlightJSON(w, map[string]interface{}{"resources": []string{"a"}, "errors": []map[string]interface{}{{"code": 400, "message": "invalid filter"}}})
	})
	err := fetchSpotlightVulnerabilities(context.Background(), api, "invalid filter", 400, func(*models.DomainAPIVulnerabilityV2) bool { t.Error("must not stream on API error"); return true })
	if err == nil || calls != 1 {
		t.Fatalf("err=%v calls=%d", err, calls)
	}
}
