package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Regression: the deployment templates kept shipping knobs that Load warns
// about (SK_MAX_ACTIVE_SESSIONS, SK_SESSION_TTL_SECONDS) or refuses when
// true (SK_MAINTENANCE_MODE). An operator copying them believed they did
// something; flipping maintenance mode on broke startup.
func TestShippedDeploymentFilesOmitDeadKnobs(t *testing.T) {
	t.Parallel()
	root := filepath.Join("..", "..")
	files := []string{
		".env.example",
		"docker-compose.yml",
		"k8s/configmap.yaml",
		"helm/sealkeeper/values.yaml",
		"helm/sealkeeper/templates/configmap.yaml",
	}
	dead := []string{
		"SK_MAX_ACTIVE_SESSIONS", "SK_SESSION_TTL_SECONDS", "SK_MAINTENANCE_MODE",
		"maxActiveSessions", "sessionTTLSeconds", "maintenanceMode",
	}
	for _, f := range files {
		b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(f)))
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		for _, k := range dead {
			if strings.Contains(string(b), k) {
				t.Errorf("%s still ships %s", f, k)
			}
		}
	}
}
