package integration

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"wanopt/internal/client"
	"wanopt/internal/protocol"
	"wanopt/internal/tunnel"
)

// TestDockerImageAuthenticationAndRestart exercises the built image, including
// its unprivileged user, read-only filesystem, mounted persistent certificate,
// config-relative paths, SIGTERM shutdown and HTTP/3 authentication. The Docker
// daemon must run on the test host so the bind mount and loopback port are local.
func TestDockerImageAuthenticationAndRestart(t *testing.T) {
	image := os.Getenv("WANOPT_DOCKER_IMAGE")
	if image == "" {
		t.Skip("set WANOPT_DOCKER_IMAGE to test a locally built Docker image")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatal(err)
	}

	cert, pin, err := tunnel.GenerateSelfSigned()
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, err := tunnel.EncodeCertPEM(cert)
	if err != nil {
		t.Fatal(err)
	}
	psk := make([]byte, 32)
	if _, err := rand.Read(psk); err != nil {
		t.Fatal(err)
	}
	fixture := t.TempDir()
	// These are fresh test-only credentials. World-readable fixture permissions
	// let the image's fixed unprivileged UID read the read-only bind mount.
	if err := os.Chmod(fixture, 0o755); err != nil {
		t.Fatal(err)
	}
	config := fmt.Sprintf("listen: ':4242'\npsk: '%s'\ncert_file: server.crt\nkey_file: server.key\nacl:\n  deny: ['127.0.0.1/32']\n", base64.StdEncoding.EncodeToString(psk))
	for name, contents := range map[string][]byte{
		"server.yaml": []byte(config),
		"server.crt":  certPEM,
		"server.key":  keyPEM,
	} {
		path := filepath.Join(fixture, name)
		if err := os.WriteFile(path, contents, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// Register cleanup before creating the container. Docker writes the ID as
	// soon as it creates the container, so even a failed start can be cleaned up.
	cidFile := filepath.Join(t.TempDir(), "container.cid")
	t.Cleanup(func() {
		id, err := dockerContainerID(cidFile)
		if errors.Is(err, os.ErrNotExist) {
			return
		}
		if err != nil {
			t.Errorf("read test container ID for cleanup: %v", err)
			return
		}
		if t.Failed() {
			logs, err := dockerCommand("logs", "--tail", "100", id)
			t.Logf("test container logs (error=%v):\n%s", err, logs)
		}
		if _, err := dockerCommand("rm", "-f", id); err != nil {
			t.Errorf("remove test container %s: %v", id, err)
		}
	})
	if _, err := dockerCommand("run", "-d", "--pull=never", "--cidfile", cidFile,
		"--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
		"--publish", "127.0.0.1::4242/udp", "--mount", "type=bind,src="+fixture+",dst=/etc/wanopt,readonly", image); err != nil {
		t.Fatal(err)
	}
	id, err := dockerContainerID(cidFile)
	if err != nil {
		t.Fatal(err)
	}

	user, err := dockerCommand("inspect", "--format", "{{.Config.User}}", id)
	if err != nil || user != "10001:10001" {
		t.Fatalf("container must run as UID/GID10001, got %q: %v", user, err)
	}

	t.Log("authenticate against the newly started image")
	assertDockerAuthentication(t, dockerUDPAddress(t, id), pin, psk)
	stopDockerServer(t, id)

	if _, err := dockerCommand("start", id); err != nil {
		t.Fatal(err)
	}
	t.Log("authenticate after restart with the same pinned certificate and PSK")
	assertDockerAuthentication(t, dockerUDPAddress(t, id), pin, psk)
	stopDockerServer(t, id)
}

func dockerCommand(args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.WaitDelay = 2 * time.Second
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("docker %s: %w: %s", args[0], err, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}

func dockerContainerID(path string) (string, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	id := strings.TrimSpace(string(contents))
	if decoded, err := hex.DecodeString(id); err != nil || len(decoded) != 32 {
		return "", errors.New("Docker did not provide a full container ID")
	}
	return id, nil
}

func dockerUDPAddress(t *testing.T, id string) string {
	t.Helper()
	out, err := dockerCommand("port", id, "4242/udp")
	if err != nil {
		t.Fatal(err)
	}
	addresses := strings.Fields(out)
	if len(addresses) != 1 {
		t.Fatalf("expected one loopback UDP binding, got %q", out)
	}
	host, port, err := net.SplitHostPort(addresses[0])
	if err != nil || host != "127.0.0.1" {
		t.Fatalf("unexpected UDP binding %q: %v", out, err)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		t.Fatalf("invalid published UDP port %q", port)
	}
	return net.JoinHostPort(host, port)
}

func assertDockerAuthentication(t *testing.T, address, pin string, psk []byte) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	c := client.New(client.Options{
		Server: address, PSK: psk, Pin: pin,
		HandshakeTimeout: 5 * time.Second,
		RequestTimeout:   15 * time.Second,
		Log:              slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	done := make(chan struct{})
	go func() { defer close(done); c.Run(ctx) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("Docker smoke client did not join during shutdown")
		}
	}()
	target, err := protocol.ParseAddress("127.0.0.1:9")
	if err != nil {
		t.Fatal(err)
	}
	requestCtx, requestCancel := context.WithTimeout(ctx, 15*time.Second)
	defer requestCancel()
	stream, err := c.OpenTCP(requestCtx, target, false)
	if stream != nil {
		_ = stream.Close()
	}
	var denied *client.DialError
	if !errors.As(err, &denied) || denied.Status != protocol.StatusNotAllowed {
		t.Fatalf("expected authenticated ACL rejection, got %T: %v", err, err)
	}
}

func stopDockerServer(t *testing.T, id string) {
	t.Helper()
	if _, err := dockerCommand("stop", "-t", "5", id); err != nil {
		t.Fatal(err)
	}
	exitCode, err := dockerCommand("inspect", "--format", "{{.State.ExitCode}}", id)
	if err != nil {
		t.Fatal(err)
	}
	if exitCode != "0" {
		t.Fatalf("server did not stop gracefully: container exit code %s", exitCode)
	}
}
