package app

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestTrafficStoreAccumulatesAcrossCounterReset(t *testing.T) {
	store := NewTrafficStore(filepath.Join(t.TempDir(), "traffic.json"))

	first := `{"stat":[{"name":"outbound>>>proxy-vpn_admin>>>traffic>>>downlink","value":1000}]}`
	out, err := store.Update(first, `[2:500] -A FORWARD -s 10.10.10.2/32 -m comment --comment "vpnproxi user=vpn_admin direct-upload" -j ACCEPT`)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `"value":1000`) || !strings.Contains(out, `"value":500`) {
		t.Fatalf("unexpected first cumulative stats: %s", out)
	}

	second := `{"stat":[{"name":"outbound>>>proxy-vpn_admin>>>traffic>>>downlink","value":1500}]}`
	out, err = store.Update(second, `[4:900] -A FORWARD -s 10.10.10.2/32 -m comment --comment "vpnproxi user=vpn_admin direct-upload" -j ACCEPT`)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `"value":1500`) || !strings.Contains(out, `"value":900`) {
		t.Fatalf("unexpected second cumulative stats: %s", out)
	}

	afterRestart := `{"stat":[{"name":"outbound>>>proxy-vpn_admin>>>traffic>>>downlink","value":200}]}`
	out, err = store.Update(afterRestart, `[1:100] -A FORWARD -s 10.10.10.2/32 -m comment --comment "vpnproxi user=vpn_admin direct-upload" -j ACCEPT`)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `"value":1700`) || !strings.Contains(out, `"value":1000`) {
		t.Fatalf("counter reset must add new samples to existing totals: %s", out)
	}
}

func TestTrafficStoreResetClearsTotals(t *testing.T) {
	store := NewTrafficStore(filepath.Join(t.TempDir(), "traffic.json"))
	if _, err := store.Update(`{"stat":[{"name":"outbound>>>proxy-vpn_admin>>>traffic>>>uplink","value":42}]}`, ""); err != nil {
		t.Fatal(err)
	}
	if err := store.Reset(); err != nil {
		t.Fatal(err)
	}
	out, err := store.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, `"value":42`) {
		t.Fatalf("traffic reset did not clear totals: %s", out)
	}
}
