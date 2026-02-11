package logging

import (
	"encoding/json"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"
)

// JSONFormatter formats log entries as single-line JSON objects, suitable for
// SIEM ingestion.
type JSONFormatter struct {
	TimestampFormat string
}

// Format renders a log entry as a JSON line.
func (f *JSONFormatter) Format(entry *log.Entry) ([]byte, error) {
	data := make(map[string]interface{}, len(entry.Data)+3)

	for k, v := range entry.Data {
		data[k] = v
	}

	tsFormat := f.TimestampFormat
	if tsFormat == "" {
		tsFormat = time.RFC3339Nano
	}

	data["timestamp"] = entry.Time.Format(tsFormat)
	data["level"] = entry.Level.String()
	if entry.Message != "" {
		data["message"] = entry.Message
	}

	serialized, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal fields to JSON: %w", err)
	}
	return append(serialized, '\n'), nil
}
