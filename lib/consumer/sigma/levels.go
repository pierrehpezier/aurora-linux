package sigma

import "strings"

const (
	normalizedLevelInfo     = "info"
	normalizedLevelLow      = "low"
	normalizedLevelMedium   = "medium"
	normalizedLevelHigh     = "high"
	normalizedLevelCritical = "critical"
)

var levelPriority = map[string]int{
	normalizedLevelInfo:     0,
	normalizedLevelLow:      1,
	normalizedLevelMedium:   2,
	normalizedLevelHigh:     3,
	normalizedLevelCritical: 4,
}

// IsValidMinLevel returns true when the min-level value is one of the
// supported Sigma severities.
func IsValidMinLevel(level string) bool {
	_, _, ok := normalizeSigmaLevel(level)
	return ok
}

func normalizeSigmaLevel(level string) (string, int, bool) {
	normalized := strings.ToLower(strings.TrimSpace(level))
	switch normalized {
	case "informational":
		normalized = normalizedLevelInfo
	case normalizedLevelInfo, normalizedLevelLow, normalizedLevelMedium, normalizedLevelHigh, normalizedLevelCritical:
	default:
		return "", 0, false
	}

	priority, ok := levelPriority[normalized]
	if !ok {
		return "", 0, false
	}
	return normalized, priority, true
}

func passesMinLevel(ruleLevel string, minPriority int) bool {
	_, priority, ok := normalizeSigmaLevel(ruleLevel)
	if !ok {
		// Keep unknown levels when min-level is "info", otherwise exclude them.
		return minPriority == levelPriority[normalizedLevelInfo]
	}
	return priority >= minPriority
}
