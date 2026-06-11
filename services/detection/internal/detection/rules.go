package detection

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/Prashant-koi/lavender/services/platform/events"
)

var suspiciousPorts = map[uint16]struct{}{
	4444:  {},
	1337:  {},
	9001:  {},
	9999:  {},
	6666:  {},
	31337: {},
	5555:  {},
}

var sensitiveFiles = []string{
	"/etc/shadow",
	"/etc/passwd",
	"/etc/sudoers",
	"/etc/sudoers.d",
	"/.ssh/id_rsa",
	"/.ssh/id_ed25519",
	"/.ssh/authorized_keys",
	"/.bash_history",
	"/.zsh_history",
	"/root/.ssh",
}

var safeFileReaders = []string{
	"sshd",
	"sudo",
	"passwd",
	"shadow",
	"pam",
	"bash",
	"zsh",
	"sh",
	"code",
	"vim",
	"nvim",
	"nano",
}

var shellNames = []string{
	"bash",
	"sh",
	"zsh",
	"fish",
	"dash",
}

var safeShellLaunchers = []string{
	"tmux",
	"alacritty",
	"kitty",
	"sshd",
	"sudo",
	"su",
	"login",
	"Hyprland",
	"code",
}

func suspiciousPortAlert(evt events.CanonicalEvent) *events.AlertEvent {
	if evt.Event.Type != "connect" {
		return nil
	}

	if _, ok := suspiciousPorts[evt.Event.DestPort]; !ok {
		return nil
	}

	detail := fmt.Sprintf(
		"'%s' connected to %s:%d (known C2/reverse shell port)",
		evt.Event.Comm,
		evt.Event.DestIP,
		evt.Event.DestPort,
	)

	alert := newAlert(
		evt,
		"T1071 [Connection to suspicious port]",
		"warning",
		detail,
	)

	return &alert
}

func shellNetworkConnectionAlert(evt events.CanonicalEvent) *events.AlertEvent {
	if evt.Event.Type != "connect" {
		return nil
	}

	if !equalsAny(evt.Event.Comm, shellNames) {
		return nil
	}

	if strings.HasPrefix(evt.Event.DestIP, "127.") || evt.Event.DestIP == "::1" {
		return nil
	}

	detail := fmt.Sprintf(
		"'%s' opened network connection to %s:%d",
		evt.Event.Comm,
		evt.Event.DestIP,
		evt.Event.DestPort,
	)

	alert := newAlert(
		evt,
		"T1059 [Shell making outbound connection]",
		"high",
		detail,
	)

	return &alert
}

func (d *Detector) unexpectedShellSpawnAlert(evt events.CanonicalEvent) *events.AlertEvent {
	if evt.Event.Type != "exec" {
		return nil
	}

	targetBase := filepath.Base(evt.Event.Filename)
	if !equalsAny(targetBase, shellNames) {
		return nil
	}

	parentComm := d.processes[evt.Event.PPID]
	if parentComm == "" {
		parentComm = "unknown"
	}

	if containsAny(parentComm, safeShellLaunchers) || containsAny(parentComm, shellNames) {
		return nil
	}

	detail := fmt.Sprintf("'%s' executed shell target (%s)", parentComm, targetBase)
	alert := newAlert(
		evt,
		"T1059 [Unexpected shell spawn]",
		"warning",
		detail,
	)

	return &alert
}

func sensitiveFileAlert(evt events.CanonicalEvent) *events.AlertEvent {
	if evt.Event.Type != "open" {
		return nil
	}

	if !containsAny(evt.Event.Filename, sensitiveFiles) {
		return nil
	}

	if containsAny(evt.Event.Comm, safeFileReaders) {
		return nil
	}

	detail := fmt.Sprintf("'%s' opened sensitive file: %s", evt.Event.Comm, evt.Event.Filename)
	alert := newAlert(
		evt,
		"T1003 [Sensitive file read]",
		"high",
		detail,
	)

	return &alert
}

func containsAny(value string, patterns []string) bool {
	for _, pattern := range patterns {
		if strings.Contains(value, pattern) {
			return true
		}
	}

	return false
}

func equalsAny(value string, patterns []string) bool {
	for _, pattern := range patterns {
		if value == pattern {
			return true
		}
	}

	return false
}
