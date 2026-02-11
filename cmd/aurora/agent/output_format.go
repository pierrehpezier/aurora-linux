package agent

import (
	"fmt"
	"strings"
)

const (
	outputFormatSyslog = "syslog"
	outputFormatJSON   = "json"
)

func validateConfiguredOutputFormat(flagName string, value string) error {
	if strings.TrimSpace(value) == "" {
		return nil
	}

	_, err := resolveOutputFormat(value, false)
	if err != nil {
		return fmt.Errorf("%s: %w", flagName, err)
	}
	return nil
}

func resolveOutputFormat(value string, jsonOutputFallback bool) (string, error) {
	format := strings.ToLower(strings.TrimSpace(value))
	if format == "" {
		if jsonOutputFallback {
			return outputFormatJSON, nil
		}
		return outputFormatSyslog, nil
	}

	switch format {
	case outputFormatSyslog, outputFormatJSON:
		return format, nil
	default:
		return "", fmt.Errorf("unsupported format %q (allowed: syslog, json)", value)
	}
}
