package ksubdomain

import (
	"bg-agent/internal/assetCollect/ksubdomain/core"
	"testing"
)

func TestLocalKSubdomain(t *testing.T) {

	options := &core.Options{Domain: []string{"sf-express.com"}}

	core.Start(options)
}
