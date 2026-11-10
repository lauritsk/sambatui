package devtool

import (
	"context"
	"time"
)

func (tools *Tools) fixtureTests(ctx context.Context, name string) error {
	for _, packageName := range []string{"dnsrpc", "directory", "integration"} {
		filter := "."
		if packageName == "integration" {
			// The binary-only fixture deliberately contains no checkout sources.
			filter = "^TestDisposable"
		}
		if _, err := tools.execute(ctx, command{
			name: "docker", timeout: 150 * time.Second,
			arguments: []string{
				"exec", "--env", "SAMBATUI_DISPOSABLE_TEST=YES", name,
				"/tmp/native-ad/" + packageName + ".test",
				"-test.v", "-test.timeout=120s", "-test.run=" + filter,
			},
		}); err != nil {
			return err
		}
	}
	return nil
}
