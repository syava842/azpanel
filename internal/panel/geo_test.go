package panel

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOpenGeoNoFiles(t *testing.T) {
	g, err := OpenGeo(t.TempDir())
	if g != nil || err != nil {
		t.Fatalf("%v, %v", g, err)
	}
}

func TestGeoNilLookup(t *testing.T) {
	var g *Geo
	if c, i := g.Lookup("1.2.3.4:5"); c != "" || i != "" {
		t.Fatalf("%q %q", c, i)
	}
	g.Close()
}

func TestOpenGeoBrokenFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "GeoLite2-City.mmdb"), []byte("не база"), 0o600); err != nil {
		t.Fatal(err)
	}
	if g, err := OpenGeo(dir); err == nil || g != nil {
		t.Fatalf("битый файл принят: %v, %v", g, err)
	}
}
