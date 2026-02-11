package replay

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/nicholasgasior/aurora-linux/lib/enrichment"
	"github.com/nicholasgasior/aurora-linux/lib/provider"
)

// ReplayProvider implements EventProvider by reading recorded events from a
// JSONL file. Used in CI and testing environments where BPF is unavailable.
type ReplayProvider struct {
	files   []string
	sources map[string]bool
}

// New creates a new ReplayProvider for the given JSONL files.
func New(files ...string) *ReplayProvider {
	return &ReplayProvider{
		files:   files,
		sources: make(map[string]bool),
	}
}

func (r *ReplayProvider) Name() string        { return "Replay" }
func (r *ReplayProvider) Description() string  { return "Replay provider for pre-recorded events" }
func (r *ReplayProvider) LostEvents() uint64   { return 0 }
func (r *ReplayProvider) Close() error         { return nil }
func (r *ReplayProvider) Initialize() error    { return nil }

func (r *ReplayProvider) AddSource(source string) error {
	r.sources[source] = true
	return nil
}

// SendEvents reads each JSONL file and emits events via the callback.
func (r *ReplayProvider) SendEvents(callback func(event provider.Event)) {
	for _, path := range r.files {
		r.replayFile(path, callback)
	}
}

func (r *ReplayProvider) replayFile(path string, callback func(event provider.Event)) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024) // 1 MB max line

	for scanner.Scan() {
		var record map[string]interface{}
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			continue
		}

		evt, err := recordToEvent(record)
		if err != nil {
			continue
		}

		callback(evt)
	}
}

func recordToEvent(record map[string]interface{}) (*replayEvent, error) {
	fields := make(enrichment.DataFieldsMap, len(record))

	var providerName string
	var eventID uint16
	var source string
	var pid uint32
	var ts time.Time

	for k, v := range record {
		switch k {
		case "_provider":
			providerName, _ = v.(string)
		case "_eventID":
			if f, ok := v.(float64); ok {
				eventID = uint16(f)
			}
		case "_source":
			source, _ = v.(string)
		case "_timestamp":
			if s, ok := v.(string); ok {
				ts, _ = time.Parse(time.RFC3339Nano, s)
			}
		case "ProcessId":
			if s, ok := v.(string); ok {
				if n, err := strconv.ParseUint(s, 10, 32); err == nil {
					pid = uint32(n)
				}
			}
			fields.AddField(k, fmt.Sprint(v))
		default:
			fields.AddField(k, fmt.Sprint(v))
		}
	}

	if providerName == "" {
		providerName = "LinuxEBPF"
	}
	if ts.IsZero() {
		ts = time.Now()
	}

	return &replayEvent{
		id: provider.EventIdentifier{
			ProviderName: providerName,
			EventID:      eventID,
		},
		pid:    pid,
		source: source,
		ts:     ts,
		fields: fields,
	}, nil
}

// replayEvent implements provider.Event for replayed events.
type replayEvent struct {
	id     provider.EventIdentifier
	pid    uint32
	source string
	ts     time.Time
	fields enrichment.DataFieldsMap
}

func (e *replayEvent) ID() provider.EventIdentifier     { return e.id }
func (e *replayEvent) Process() uint32                   { return e.pid }
func (e *replayEvent) Source() string                    { return e.source }
func (e *replayEvent) Time() time.Time                   { return e.ts }
func (e *replayEvent) Value(fieldname string) enrichment.DataValue { return e.fields.Value(fieldname) }
func (e *replayEvent) ForEach(fn func(key, value string)) { e.fields.ForEach(fn) }
func (e *replayEvent) Fields() enrichment.DataFieldsMap   { return e.fields }
