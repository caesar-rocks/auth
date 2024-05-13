package auth

import (
	"testing"
)

func TestRetrievePrimaryKey(t *testing.T) {
	type user struct {
		ID string `bun:"id,pk"`
	}

	type article struct {
		Identifier int `bun:"id,pk,autoincrement"`
	}

	pk := retrievePrimaryKey(user{ID: "la-jeune-parque"})
	if pk != "la-jeune-parque" {
		t.Errorf("Expected %s, got %s", "la-jeune-parque", pk)
	}

	pk = retrievePrimaryKey(article{Identifier: 123})
	if pk != 123 {
		t.Errorf("Expected %d, got %s", 123, pk)
	}
}
