package logging

import (
	"strings"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
)

func TestSyslogFormatterFormatsRFC5424LikeLine(t *testing.T) {
	f := &SyslogFormatter{
		TimestampFormat: time.RFC3339,
		Hostname:        "test-host",
		AppName:         "aurora",
		Facility:        1,
	}

	entry := &log.Entry{
		Time:    time.Date(2026, 2, 11, 12, 0, 0, 0, time.UTC),
		Level:   log.WarnLevel,
		Message: "Sigma match",
		Data: log.Fields{
			"sigma_rule": "rule-1",
			"Image":      "/usr/bin/bash",
		},
	}

	out, err := f.Format(entry)
	if err != nil {
		t.Fatalf("Format() error = %v", err)
	}

	line := string(out)
	if !strings.HasPrefix(line, "<12>1 2026-02-11T12:00:00Z test-host aurora - - - Sigma match") {
		t.Fatalf("unexpected syslog prefix: %q", line)
	}
	if !strings.Contains(line, `Image="/usr/bin/bash"`) {
		t.Fatalf("expected Image field in %q", line)
	}
	if !strings.Contains(line, `sigma_rule="rule-1"`) {
		t.Fatalf("expected sigma_rule field in %q", line)
	}
	if !strings.HasSuffix(line, "\n") {
		t.Fatalf("expected newline-terminated output, got %q", line)
	}
}
