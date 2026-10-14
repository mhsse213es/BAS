package tcv

import "testing"

func TestNewStore_ReturnsNonNil(t *testing.T) {
	s := NewStore(sharedDB.Pool)
	if s == nil {
		t.Fatal("NewStore returned nil")
	}
}
