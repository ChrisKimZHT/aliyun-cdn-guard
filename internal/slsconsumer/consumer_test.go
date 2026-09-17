package slsconsumer

import "testing"

func TestToEventFallbackIDIsStable(t *testing.T) {
	fields := map[string]string{"domain": " Example.COM ", "client_ip": " 192.0.2.1 ", "user_agent": "ua", "uri": "/x", "uri_param": "a=1"}
	a, ok := toEvent(fields, 123)
	if !ok {
		t.Fatal("event rejected")
	}
	b, _ := toEvent(fields, 123)
	if a.EventID == "" || a.EventID != b.EventID {
		t.Fatalf("ids %q %q", a.EventID, b.EventID)
	}
	if a.Domain != "example.com" || a.ClientIP != "192.0.2.1" {
		t.Fatalf("event=%+v", a)
	}
}
