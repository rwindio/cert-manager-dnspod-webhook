package main

import (
	"os"
	"testing"

	dns "github.com/cert-manager/cert-manager/test/acme"
)

var (
	zone      = os.Getenv("TEST_ZONE_NAME")
	dnsServer = getEnv("TEST_DNS_SERVER", "119.29.29.29:53")
)

func TestRunsSuite(t *testing.T) {
	// Uncomment the below fixture when implementing your custom DNS provider
	fixture := dns.NewFixture(&dnsPodProviderSolver{},
		dns.SetDNSName(zone),
		dns.SetDNSServer(dnsServer),
		dns.SetResolvedZone(zone),
		dns.SetAllowAmbientCredentials(false),
		dns.SetManifestPath("testdata/dnspod-solver"),
	)

	fixture.RunBasic(t)
	fixture.RunExtended(t)

}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}
