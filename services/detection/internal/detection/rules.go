package detection

import (
	"fmt"
	"strings"

	"github.com/Prashant-koi/lavender/detection/internal/events"
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

func suspiciousPortAlert(evt events.CanonicalEvent) *AlertEvent {
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

func sensitiveFileAlert(evt events.CanonicalEvent) *AlertEvent {
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
