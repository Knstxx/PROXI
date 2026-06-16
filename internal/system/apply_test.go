package system

import (
	"strings"
	"testing"
)

func TestCommandLine(t *testing.T) {
	t.Parallel()

	got := commandLine("systemctl", "restart", "xray")
	if got != "systemctl restart xray" {
		t.Fatalf("commandLine() = %q", got)
	}
}

func TestRunRequiredReturnsCommandFailure(t *testing.T) {
	t.Parallel()

	var res Result
	err := runRequired(&res, "sh", "-c", "echo fail >&2; exit 7")
	if err == nil {
		t.Fatal("runRequired() error = nil")
	}
	if !strings.Contains(err.Error(), "sh -c echo fail >&2; exit 7 failed: fail") {
		t.Fatalf("runRequired() error = %q", err)
	}
	if len(res.Commands) != 1 || res.Commands[0] != "sh -c echo fail >&2; exit 7" {
		t.Fatalf("runRequired() commands = %#v", res.Commands)
	}
}
