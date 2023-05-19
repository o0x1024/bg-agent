package resolve

import (
	"github.com/projectdiscovery/dnsx/libs/dnsx"
)

// DefaultResolvers contains the default list of resolvers known to be good
var DefaultResolvers = []string{
	"1.1.1.1:53",        // Cloudflare primary
	"1.0.0.1:53",        // Cloudflare secondary
	"8.8.8.8:53",        // Google primary
	"8.8.4.4:53",        // Google secondary
	"9.9.9.9:53",        // Quad9 Primary
	"9.9.9.10:53",       // Quad9 Secondary
	"77.88.8.8:53",      // Yandex Primary
	"77.88.8.1:53",      // Yandex Secondary
	"208.67.222.222:53", // OpenDNS Primary
	"208.67.220.220:53", // OpenDNS Secondary
	"114.114.114.114",
	"1.2.4.8",
	"180.76.76.76",
	"223.5.5.5",
	"119.29.29.29",
	"101.226.4.6",
}

// Resolver is a struct for resolving DNS names
type Resolver struct {
	DNSClient *dnsx.DNSX
	Resolvers []string
}

// New creates a new resolver struct with the default resolvers
func New() *Resolver {
	return &Resolver{
		Resolvers: []string{},
	}
}
