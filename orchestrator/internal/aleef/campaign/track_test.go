package campaign

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/aleef/model"
)

func trackFixture(t *testing.T, status int, body string) (*trackRT, *[]model.CreatedObject, *fakeNext) {
	t.Helper()
	m := aliasModel(t)
	for i := range m.Operations {
		switch m.Operations[i].ID {
		case "createItem":
			m.Operations[i].Class = model.ClassSetupSafe
		case "deleteItem":
			m.Operations[i].Class = model.ClassReversible
		}
	}
	nx := &fakeNext{resp: func() *http.Response {
		return &http.Response{StatusCode: status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body))}
	}}
	cfg := Config{
		BaseURL: "http://h", Secrets: toySecrets(), Accounts: toyAccounts(),
		Setup: []model.SetupOp{{OperationID: "createItem", Compensate: "deleteItem"}},
	}
	tr := newTrackRT(nx, cfg, m)
	var got []model.CreatedObject
	tr.setTrack(func(o model.CreatedObject) { got = append(got, o) })
	return tr, &got, nx
}

func doTracked(t *testing.T, tr *trackRT, method, url, tok string) string {
	t.Helper()
	r := req(t, method, url, "")
	r.Header.Set("Authorization", "Bearer "+tok)
	resp, err := tr.RoundTrip(r)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

func TestTrackRegistersObjectsCreatedByTestsForCompensation(t *testing.T) {
	tr, got, _ := trackFixture(t, 201, `{"id":"item-77","title":"x"}`)
	body := doTracked(t, tr, "POST", "http://h/api/v2/items", "tok-alice")
	if body != `{"id":"item-77","title":"x"}` {
		t.Fatalf("response body altered: %s", body)
	}
	if len(*got) != 1 || (*got)[0].ID != "item-77" || (*got)[0].Owner != "cust-a" || (*got)[0].Compensate != "deleteItem" {
		t.Fatalf("tracked: %+v", *got)
	}
}

func TestTrackIgnoresWhatItShouldNot(t *testing.T) {
	tr, got, _ := trackFixture(t, 201, `{"id":"item-77"}`)
	doTracked(t, tr, "GET", "http://h/api/v2/items/item-1", "tok-alice")          // not a POST
	doTracked(t, tr, "POST", "http://h/api/v2/items", "unknown-token")            // owner unknown
	doTracked(t, tr, "POST", "http://h/api/v2/items/item-1/archive", "tok-alice") // not a creating operation
	if len(*got) != 0 {
		t.Fatalf("tracked %+v", *got)
	}
	tr2, got2, _ := trackFixture(t, 403, `{"id":"item-77"}`)
	doTracked(t, tr2, "POST", "http://h/api/v2/items", "tok-alice")
	tr3, got3, _ := trackFixture(t, 201, `{"id":42}`)
	doTracked(t, tr3, "POST", "http://h/api/v2/items", "tok-alice")
	if len(*got2)+len(*got3) != 0 {
		t.Fatal("failed response or non-string id was tracked")
	}
}

func TestAliasLearnedIDsAreNotRefusedButOthersStillAre(t *testing.T) {
	rt, nx := newTestAlias(t, []string{"item-1"}, []string{"item-7"})
	al := rt.(aliasRT)
	// before learning, an id that merely contains a generation id is refused
	if _, err := rt.RoundTrip(req(t, "GET", "http://h/api/v2/items/item-12", "")); !errors.Is(err, ErrUntranslatedID) {
		t.Fatalf("err %v", err)
	}
	al.learn("item-12")
	if _, err := rt.RoundTrip(req(t, "GET", "http://h/api/v2/items/item-12", "")); err != nil {
		t.Fatal(err)
	}
	if nx.got.URL.Path != "/api/v2/items/item-12" {
		t.Fatalf("learned id was rewritten: %s", nx.got.URL.Path)
	}
	// an unlearned lookalike is still refused
	if _, err := rt.RoundTrip(req(t, "GET", "http://h/api/v2/items/item-13x", "")); err != nil && !errors.Is(err, ErrUntranslatedID) {
		t.Fatal(err)
	}
	if _, err := rt.RoundTrip(req(t, "GET", "http://h/api/v2/items/item-1x", "")); !errors.Is(err, ErrUntranslatedID) {
		t.Fatalf("lookalike must still be refused: %v", err)
	}
	// generation ids still translate
	if _, err := rt.RoundTrip(req(t, "GET", "http://h/api/v2/items/item-1", "")); err != nil || nx.got.URL.Path != "/api/v2/items/item-7" {
		t.Fatalf("generation id: %v %s", err, nx.got.URL.Path)
	}
	// ids that are not plain segments or equal a route literal are never learned
	al.learn("a/b")
	al.learn("items")
	for id := range al.known.ids {
		if id == "a/b" || id == "items" {
			t.Fatalf("learned %q", id)
		}
	}
}
