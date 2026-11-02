package antizapret

import (
	"strings"
	"testing"
	"time"
)

const wgDump = "SERVERPRIVATE\tSERVERPUB\t51820\toff\n" +
	"ALICEPUB\tALICEPSK\t1.2.3.4:5555\t10.29.8.2/32\t1793564373\t48024\t227676\t0\n" +
	"BOBPUB\tBOBPSK\t(none)\t10.29.8.3/32\t0\t0\t0\t0\n" +
	"CAROLPUB\t(none)\t[2001:db8::1]:51820\t10.29.8.4/32\t1793564000\t1\t2\t25\n"

func TestParseWGDump(t *testing.T) {
	got, err := ParseWGDump("antizapret", strings.NewReader(wgDump))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("пиров %d", len(got))
	}
	a := got[0]
	if a.Interface != "antizapret" || a.PublicKey != "ALICEPUB" || a.Endpoint != "1.2.3.4:5555" ||
		!a.LatestHandshake.Equal(time.Unix(1793564373, 0)) || a.RxBytes != 48024 || a.TxBytes != 227676 {
		t.Fatalf("alice %+v", a)
	}
	if b := got[1]; b.Endpoint != "" || !b.LatestHandshake.IsZero() {
		t.Fatalf("bob %+v", b)
	}
	if c := got[2]; c.Endpoint != "[2001:db8::1]:51820" {
		t.Fatalf("carol %+v", c)
	}
}

func TestParseWGDumpBadLineHidesKeys(t *testing.T) {
	_, err := ParseWGDump("vpn", strings.NewReader("SERVERPRIVATE\tSERVERPUB\t51820\toff\nALICEPUB\tALICEPSK\n"))
	if err == nil || strings.Contains(err.Error(), "ALICEPSK") || strings.Contains(err.Error(), "PRIVATE") {
		t.Fatalf("err = %v", err)
	}
}
