package main

import (
	"os"
	"testing"

	"github.com/cert-manager/cert-manager/test/acme/dns"
)

var (
	zone = os.Getenv("TEST_ZONE_NAME")
)

func TestRunsSuite(t *testing.T) {
	fixture := dns.NewFixture(&dnsPodProviderSolver{},
		dns.SetDNSName(zone),
		dns.SetResolvedZone(zone),
		dns.SetAllowAmbientCredentials(false),
		dns.SetManifestPath("testdata/dnspod-solver"),
		dns.SetDNSServer("119.29.29.29:53"),
	)
	fixture.RunBasic(t)
	fixture.RunExtended(t)

}
