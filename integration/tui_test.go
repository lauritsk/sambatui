//go:build linux

package integration

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/creack/pty"
	"github.com/lauritsk/sambatui/internal/discovery"
	"github.com/lauritsk/sambatui/internal/dnsrpc"
	"github.com/miekg/dns"
)

func TestDisposableADServiceDiscovery(t *testing.T) {
	if os.Getenv("SAMBATUI_DISPOSABLE_TEST") != "YES" {
		t.Skip("opt-in isolated lab only")
	}
	marker, e := os.ReadFile("/tmp/native-ad/disposable.marker")
	if e != nil || string(marker) != "sambatui isolated disposable lab\n" {
		t.Fatal("not the authorized fixture")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, "127.0.0.1:53")
	}}
	services, e := discovery.Discover(ctx, "lab.invalid", resolver)
	if e != nil {
		t.Fatal(e)
	}
	ldap, kdc := false, false
	for _, s := range services {
		if s.Kind == "ldap" {
			ldap = true
		}
		if s.Kind == "kerberos" {
			kdc = true
		}
	}
	preferred, ok := discovery.Preferred(services)
	if !ldap || !kdc || !ok || preferred.Target != "dc.lab.invalid" {
		t.Fatal("AD discovery mismatch", services)
	}
}

func TestDisposableTerminalWriteLifecycle(t *testing.T) {
	if os.Getenv("SAMBATUI_DISPOSABLE_TEST") != "YES" {
		t.Skip("opt-in isolated Samba fixture only")
	}
	marker, e := os.ReadFile("/tmp/native-ad/disposable.marker")
	if e != nil || string(marker) != "sambatui isolated disposable lab\n" {
		t.Fatal("not the authorized disposable fixture")
	}
	cfg := dnsrpc.Config{Server: "127.0.0.1", User: `LAB\Administrator`, Password: dnsrpc.NewPassword("Disposable-test-only_42!"), Timeout: 5 * time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/tmp/native-ad/sambatui", "-config", "/tmp/native-ad/tui.json")
	cmd.Env = append(os.Environ(), "TERM=xterm-256color", "NO_COLOR=1", "PATH=/nonexistent", "TMUX=/synthetic-no-server", "SAMBATUI_AUTH=password", "SAMBATUI_SERVER=dc.lab.invalid", "SAMBATUI_DOMAIN=lab.invalid", "SAMBATUI_USER=Administrator@lab.invalid", "SAMBATUI_PASSWORD=Disposable-test-only_42!", "SAMBATUI_CA_FILE=/tmp/native-ad/cert.pem")
	terminal, e := pty.StartWithSize(cmd, &pty.Winsize{Rows: 42, Cols: 140})
	if e != nil {
		t.Fatal(e)
	}
	defer terminal.Close()
	var mu sync.Mutex
	output := ""
	transcript := ""
	done := make(chan struct{})
	go func() {
		defer close(done)
		b := make([]byte, 4096)
		for {
			n, e := terminal.Read(b)
			mu.Lock()
			output += string(b[:n])
			transcript += string(b[:n])
			mu.Unlock()
			if e != nil {
				return
			}
		}
	}()
	wait := func(needle string) {
		t.Helper()
		until := time.Now().Add(10 * time.Second)
		for time.Now().Before(until) {
			mu.Lock()
			text := output
			mu.Unlock()
			if strings.Contains(text, needle) {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		mu.Lock()
		defer mu.Unlock()
		t.Fatalf("terminal did not show %q; last output: %q", needle, output[max(0, len(output)-12000):])
	}
	send := func(s string) {
		t.Helper()
		mu.Lock()
		output = ""
		mu.Unlock()
		if _, e := io.WriteString(terminal, s); e != nil {
			t.Fatal(e)
		}
		time.Sleep(60 * time.Millisecond)
	}
	wait("sambatui")
	time.Sleep(500 * time.Millisecond)
	send("z")
	wait("records from")
	// Zones are sorted: reverse, _msdcs.lab.invalid, lab.invalid.
	send("\tjj\r")
	wait("records from lab.invalid")
	send("a")
	wait("Choose DNS record type")
	send("\x13")
	wait("Add A DNS record")
	send("native-tui-proof\t192.0.2.150\x13")
	wait("Optional matching PTR")
	send("\x15yes\x13")
	wait("Confirm write")
	send("yes\x13")
	wait("Write acknowledged")
	send("r")
	wait("records from lab.invalid")
	send("/")
	wait("Filter current")
	send("native-tui-proof\x13")
	send("\tu")
	wait("Update selected DNS record")
	send("\x15192.0.2.151\x13")
	wait("Confirm write")
	send("yes\x13")
	wait("Write acknowledged")
	send("r")
	wait("records from lab.invalid")
	send("d")
	wait("Confirm write")
	send("yes\x13")
	wait("Write acknowledged")
	c, e := dnsrpc.Dial(ctx, cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	ptr, e := c.Records(ctx, "2.0.192.in-addr.arpa", "150", dns.TypePTR)
	if e != nil || len(ptr) != 1 || ptr[0].Value != "native-tui-proof.lab.invalid." {
		t.Fatalf("guided PTR not reflected on server: %+v %v", ptr, e)
	}
	rows, e := c.Records(ctx, "lab.invalid", "native-tui-proof", dns.TypeANY)
	if e == nil && len(rows) != 0 {
		t.Fatalf("terminal delete not reflected on server: %+v", rows)
	}
	if e != nil {
		st, ok := e.(*dnsrpc.StatusError)
		if !ok || st.Code != 9714 {
			t.Fatal(e)
		}
	}
	send("l")
	wait("LDAP search")
	send("\x13")
	wait("entries (limit")
	send("h")
	wait("Choose findings view")
	send("\x13")
	wait("findings/check notices")
	send("?")
	wait("sambatui — native Go client")
	send("\x1b")
	send("Q")
	if e = cmd.Wait(); e != nil {
		t.Fatal(e)
	}
	<-done
	mu.Lock()
	defer mu.Unlock()
	if strings.Contains(transcript, "Disposable-test-only") {
		t.Fatal("credential exposed by terminal")
	}
	fmt.Println("Native PTY: DNS add/update/delete, LDAP paging view, dashboard, help and clean quit verified")
}
