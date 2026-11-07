package migrations

import (
	"reflect"
	"testing"
)

func TestPendingVersionsDiffsEmbeddedAgainstLedger(t *testing.T) {
	embedded := []string{"0001_initial_schema", "0002_ticket_approval", "0017_iam_role_extra_attrs"}

	if got := pendingVersions(embedded, map[string]bool{}); !reflect.DeepEqual(got, embedded) {
		t.Errorf("empty ledger = %v, want all embedded", got)
	}

	applied := map[string]bool{"0001_initial_schema": true}
	want := []string{"0002_ticket_approval", "0017_iam_role_extra_attrs"}
	if got := pendingVersions(embedded, applied); !reflect.DeepEqual(got, want) {
		t.Errorf("partial ledger = %v, want %v", got, want)
	}

	full := map[string]bool{
		"0001_initial_schema":       true,
		"0002_ticket_approval":      true,
		"0017_iam_role_extra_attrs": true,
	}
	if got := pendingVersions(embedded, full); len(got) != 0 {
		t.Errorf("fully migrated = %v, want none", got)
	}
}

// A ledger row for an unknown/removed migration must not resurrect it: the
// diff is driven by the embedded files only.
func TestPendingVersionsIgnoresUnknownLedgerRows(t *testing.T) {
	applied := map[string]bool{"0001_initial_schema": true, "9999_removed": true}
	if got := pendingVersions([]string{"0001_initial_schema"}, applied); len(got) != 0 {
		t.Errorf("pending = %v, want none", got)
	}
}

func TestEmbeddedVersionsAreSortedAndMatchFiles(t *testing.T) {
	versions, err := embeddedVersions()
	if err != nil {
		t.Fatalf("embeddedVersions() error = %v", err)
	}
	if len(versions) == 0 {
		t.Fatal("embedded migrations must not be empty")
	}
	if versions[len(versions)-1] != "0039_sync_run_superseded" {
		t.Errorf("latest embedded migration = %q", versions[len(versions)-1])
	}
	for index := 1; index < len(versions); index++ {
		if versions[index-1] >= versions[index] {
			t.Fatalf("versions not sorted: %q >= %q", versions[index-1], versions[index])
		}
	}
}
