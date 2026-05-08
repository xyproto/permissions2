package permissions

import (
	"testing"

	"github.com/xyproto/pinterface/v2"
)

func TestInterface(_ *testing.T) {
	// Check that the value qualifies for the interface
	var _ pinterface.IPermissions = New()
}
