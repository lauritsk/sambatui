package integration

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

type productionSource struct {
	path      string
	positions *token.FileSet
	file      *ast.File
	text      string
}

func productionSources(t *testing.T) []productionSource {
	t.Helper()
	var sources []productionSource
	for _, root := range []string{"../cmd", "../internal"} {
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			positions := token.NewFileSet()
			file, err := parser.ParseFile(positions, path, data, 0)
			if err != nil {
				return err
			}
			sources = append(sources, productionSource{path, positions, file, string(data)})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return sources
}

// Tests are exempt: large table fixtures should stay beside their assertions.
// Parent lengths include callbacks, so nesting cannot hide an oversized routine.
func TestProductionFunctionLength(t *testing.T) {
	const linesMax = 70
	for _, source := range productionSources(t) {
		ast.Inspect(source.file, func(node ast.Node) bool {
			var name string
			switch function := node.(type) {
			case *ast.FuncDecl:
				name = function.Name.Name
			case *ast.FuncLit:
				name = "callback"
			default:
				return true
			}
			first := source.positions.Position(node.Pos())
			last := source.positions.Position(node.End())
			if count := last.Line - first.Line + 1; count > linesMax {
				t.Errorf("%s: %s spans %d lines (maximum %d)", first, name, count, linesMax)
			}
			return true
		})
	}
}

func TestProductionLineWidth(t *testing.T) {
	const columnsMax = 100
	for _, source := range productionSources(t) {
		for index, line := range strings.Split(source.text, "\n") {
			columns := utf8.RuneCountInString(strings.ReplaceAll(line, "\t", "    "))
			if columns > columnsMax {
				t.Errorf("%s:%d: %d columns (maximum %d)", source.path, index+1, columns, columnsMax)
			}
		}
	}
}

// Reject syntactically infinite loops and statically visible call cycles. Data
// bounds, interface callbacks and dependency internals still require review.
func TestProductionControlFlow(t *testing.T) {
	functions := map[string]*ast.FuncDecl{}
	for _, source := range productionSources(t) {
		prefix := filepath.Dir(source.path) + ":"
		for _, declaration := range source.file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok {
				continue
			}
			name := function.Name.Name
			if function.Recv != nil {
				name = receiverType(function.Recv.List[0].Type) + "." + name
			}
			functions[prefix+name] = function
		}
	}
	calls := map[string][]string{}
	for name, function := range functions {
		prefix := name[:strings.LastIndex(name, ":")+1]
		ast.Inspect(function.Body, func(node ast.Node) bool {
			if loop, ok := node.(*ast.ForStmt); ok && loop.Cond == nil {
				t.Errorf("%s contains a loop without an explicit termination condition", name)
			}
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			target := ""
			switch callee := call.Fun.(type) {
			case *ast.Ident:
				target = prefix + callee.Name
			case *ast.SelectorExpr:
				if function.Recv != nil {
					receiver := function.Recv.List[0]
					if owner, ok := callee.X.(*ast.Ident); ok && len(receiver.Names) == 1 && owner.Name == receiver.Names[0].Name {
						target = prefix + receiverType(receiver.Type) + "." + callee.Sel.Name
					}
				}
			}
			if functions[target] != nil {
				calls[name] = append(calls[name], target)
			}
			return true
		})
	}
	visited, active := map[string]bool{}, map[string]bool{}
	var visit func(string)
	visit = func(name string) {
		if active[name] {
			t.Errorf("recursive production call path through %s", name)
			return
		}
		if visited[name] {
			return
		}
		visited[name], active[name] = true, true
		for _, target := range calls[name] {
			visit(target)
		}
		active[name] = false
	}
	for name := range functions {
		visit(name)
	}
}

func receiverType(expression ast.Expr) string {
	if pointer, ok := expression.(*ast.StarExpr); ok {
		expression = pointer.X
	}
	return expression.(*ast.Ident).Name
}
