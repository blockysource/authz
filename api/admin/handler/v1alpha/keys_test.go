package adminhandlerv1alpha

import (
	"testing"

	"go.einride.tech/aip/filtering"
)

func TestFiltering(t *testing.T) {
	decl, err := filtering.NewDeclarations(
		filtering.DeclareStandardFunctions(),
		filtering.DeclareIdent("a", filtering.TypeInt),
		filtering.DeclareIdent("b", filtering.TypeFloat),
	)
	if err != nil {
		t.Fatal(err)
	}

	f := filterGetter{filter: "a = 1"}

	parsed, err := filtering.ParseFilter(f, decl)
	if err != nil {
		t.Fatal(err)
	}

	t.Log(parsed.CheckedExpr.Expr.GetCallExpr())
}

type filterGetter struct {
	filter string
}

func (f filterGetter) GetFilter() string {
	return f.filter
}
