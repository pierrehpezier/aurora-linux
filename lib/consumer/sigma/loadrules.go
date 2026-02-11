package sigma

import (
	"path/filepath"
	"strings"
)

// isYAMLFile returns true if the file has a .yml or .yaml extension.
func isYAMLFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".yml" || ext == ".yaml"
}
