package config

import "testing"

func TestProxyDefaultAndValidate(t *testing.T) {
	c := Default()
	if c.Proxy.Listen != "127.0.0.1:9101" {
		t.Fatalf("listen = %q", c.Proxy.Listen)
	}
	for _, tc := range []struct {
		listen string
		ok     bool
	}{
		{"127.0.0.1:9101", true}, {"[::1]:9101", true}, {"127.0.0.1:0", false},
		{"", false}, {"0.0.0.0:9101", false}, {"9101", false}, {"proxy:9101", false},
	} {
		c := Default()
		c.Proxy.Listen = tc.listen
		if err := c.Validate(); (err == nil) != tc.ok {
			t.Errorf("%q: ошибка %v, ждали ok=%v", tc.listen, err, tc.ok)
		}
	}
}

func TestProxyLoadFromFile(t *testing.T) {
	c, err := Load(write(t, "config_version = 2\n[proxy]\nlisten = \"127.0.0.1:9201\"\n"))
	if err != nil || c.Proxy.Listen != "127.0.0.1:9201" {
		t.Fatalf("%+v %v", c.Proxy, err)
	}
	if _, err := Load(write(t, "config_version = 2\n[proxy]\nlisten = \"10.0.0.1:9101\"\n")); err == nil {
		t.Fatal("ждали ошибку проверки")
	}
}
