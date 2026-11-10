package integration

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// Keep production functions reviewable on one screen. Tests are exempt because
// table fixtures often benefit from remaining next to their assertions.
func TestProductionFunctionLength(t *testing.T) {
	const linesMax = 70
	for _, root := range []string{"../cmd", "../internal"} {
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			positions := token.NewFileSet()
			file, err := parser.ParseFile(positions, path, nil, 0)
			if err != nil {
				return err
			}
			for _, declaration := range file.Decls {
				function, ok := declaration.(*ast.FuncDecl)
				if !ok {
					continue
				}
				first := positions.Position(function.Pos())
				last := positions.Position(function.End())
				if count := last.Line - first.Line + 1; count > linesMax {
					t.Errorf("%s: %s spans %d lines (maximum %d)", first, function.Name, count, linesMax)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}
