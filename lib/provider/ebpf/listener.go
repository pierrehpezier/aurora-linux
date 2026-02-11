package ebpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/nicholasgasior/aurora-linux/lib/enrichment"
	"github.com/nicholasgasior/aurora-linux/lib/provider"
	log "github.com/sirupsen/logrus"
)

// Source strings recognized by AddSource.
const (
	SourceProcessExec = "LinuxEBPF:ProcessExec"
	SourceFileCreate  = "LinuxEBPF:FileCreate"
	SourceNetConnect  = "LinuxEBPF:NetConnect"
)

// Listener implements the EventProvider interface using eBPF tracepoints.
type Listener struct {
	mu sync.Mutex

	// Which sources are enabled
	enableExec bool
	enableFile bool
	enableNet  bool

	// eBPF objects and links
	execObjs  *execMonitorObjects
	fileObjs  *fileMonitorObjects
	netObjs   *netMonitorObjects
	execLink  link.Link
	fileEnter link.Link
	fileExit  link.Link
	netLink   link.Link

	// Ring buffer readers
	execReader *ringbuf.Reader
	fileReader *ringbuf.Reader
	netReader  *ringbuf.Reader

	// Correlation and caches
	correlator *enrichment.Correlator
	userCache  *UserCache

	// Bookkeeping
	closed    atomic.Bool
	wg        sync.WaitGroup
	bootNanos int64 // boot time in nanoseconds (for ktime -> wall clock)
}

// NewListener creates a new eBPF listener with the given correlator.
func NewListener(correlator *enrichment.Correlator) *Listener {
	return &Listener{
		correlator: correlator,
	}
}

func (l *Listener) Name() string        { return ProviderName }
func (l *Listener) Description() string  { return "eBPF-based telemetry provider for Linux" }

// AddSource enables a specific telemetry source.
func (l *Listener) AddSource(source string) error {
	switch source {
	case SourceProcessExec:
		l.enableExec = true
	case SourceFileCreate:
		l.enableFile = true
	case SourceNetConnect:
		l.enableNet = true
	default:
		return fmt.Errorf("unknown source: %s", source)
	}
	return nil
}

// Initialize loads BPF programs and attaches to tracepoints.
func (l *Listener) Initialize() error {
	// Compute boot time for ktime_get_ns → wall clock conversion
	l.bootNanos = bootTimeNanos()

	// Initialize user cache
	uc, err := NewUserCache(256)
	if err != nil {
		return fmt.Errorf("creating user cache: %w", err)
	}
	l.userCache = uc

	// Load and attach enabled BPF programs
	if l.enableExec {
		if err := l.initExec(); err != nil {
			return fmt.Errorf("init exec monitor: %w", err)
		}
	}
	if l.enableFile {
		if err := l.initFile(); err != nil {
			return fmt.Errorf("init file monitor: %w", err)
		}
	}
	if l.enableNet {
		if err := l.initNet(); err != nil {
			return fmt.Errorf("init net monitor: %w", err)
		}
	}

	return nil
}

// initExec loads the exec monitor BPF program and attaches to sched_process_exec.
func (l *Listener) initExec() error {
	objs := &execMonitorObjects{}
	if err := loadExecMonitorObjects(objs, nil); err != nil {
		return classifyBPFError(err, "exec_monitor")
	}
	l.execObjs = objs

	lnk, err := link.Tracepoint("sched", "sched_process_exec", objs.TraceSchedProcessExec, nil)
	if err != nil {
		return fmt.Errorf("attaching sched_process_exec: %w", err)
	}
	l.execLink = lnk

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		return fmt.Errorf("creating exec ring buffer reader: %w", err)
	}
	l.execReader = rd

	return nil
}

// initFile loads the file monitor BPF program and attaches to openat enter/exit.
func (l *Listener) initFile() error {
	objs := &fileMonitorObjects{}
	if err := loadFileMonitorObjects(objs, nil); err != nil {
		return classifyBPFError(err, "file_monitor")
	}
	l.fileObjs = objs

	enter, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.TraceSysEnterOpenat, nil)
	if err != nil {
		return fmt.Errorf("attaching sys_enter_openat: %w", err)
	}
	l.fileEnter = enter

	exit, err := link.Tracepoint("syscalls", "sys_exit_openat", objs.TraceSysExitOpenat, nil)
	if err != nil {
		return fmt.Errorf("attaching sys_exit_openat: %w", err)
	}
	l.fileExit = exit

	rd, err := ringbuf.NewReader(objs.FileEvents)
	if err != nil {
		return fmt.Errorf("creating file ring buffer reader: %w", err)
	}
	l.fileReader = rd

	return nil
}

// initNet loads the network monitor BPF program and attaches to inet_sock_set_state.
func (l *Listener) initNet() error {
	objs := &netMonitorObjects{}
	if err := loadNetMonitorObjects(objs, nil); err != nil {
		return classifyBPFError(err, "net_monitor")
	}
	l.netObjs = objs

	lnk, err := link.Tracepoint("sock", "inet_sock_set_state", objs.TraceInetSockSetState, nil)
	if err != nil {
		return fmt.Errorf("attaching inet_sock_set_state: %w", err)
	}
	l.netLink = lnk

	rd, err := ringbuf.NewReader(objs.NetEvents)
	if err != nil {
		return fmt.Errorf("creating net ring buffer reader: %w", err)
	}
	l.netReader = rd

	return nil
}

// SendEvents starts reading events from all enabled ring buffers and calls
// the callback for each parsed event. This method blocks until Close() is called.
func (l *Listener) SendEvents(callback func(event provider.Event)) {
	if l.enableExec && l.execReader != nil {
		l.wg.Add(1)
		go l.readExecEvents(callback)
	}
	if l.enableFile && l.fileReader != nil {
		l.wg.Add(1)
		go l.readFileEvents(callback)
	}
	if l.enableNet && l.netReader != nil {
		l.wg.Add(1)
		go l.readNetEvents(callback)
	}

	l.wg.Wait()
}

// readExecEvents reads from the exec ring buffer and processes events.
func (l *Listener) readExecEvents(callback func(event provider.Event)) {
	defer l.wg.Done()

	for {
		record, err := l.execReader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.WithError(err).Error("Reading exec ring buffer")
			continue
		}

		evt, err := l.parseExecEvent(record.RawSample)
		if err != nil {
			log.WithError(err).Debug("Parsing exec event")
			continue
		}

		callback(evt)
	}
}

// readFileEvents reads from the file ring buffer and processes events.
func (l *Listener) readFileEvents(callback func(event provider.Event)) {
	defer l.wg.Done()

	for {
		record, err := l.fileReader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.WithError(err).Error("Reading file ring buffer")
			continue
		}

		evt, err := l.parseFileEvent(record.RawSample)
		if err != nil {
			log.WithError(err).Debug("Parsing file event")
			continue
		}

		callback(evt)
	}
}

// readNetEvents reads from the network ring buffer and processes events.
func (l *Listener) readNetEvents(callback func(event provider.Event)) {
	defer l.wg.Done()

	for {
		record, err := l.netReader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.WithError(err).Error("Reading net ring buffer")
			continue
		}

		evt, err := l.parseNetEvent(record.RawSample)
		if err != nil {
			log.WithError(err).Debug("Parsing net event")
			continue
		}

		callback(evt)
	}
}

// BPF binary structs for parsing ring buffer records.

type bpfExecEvent struct {
	TimestampNs uint64
	Pid         uint32
	Ppid        uint32
	Uid         uint32
	Gid         uint32
	Comm        [16]byte
	Filename    [256]byte
	FilenameLen uint32
}

type bpfFileEvent struct {
	TimestampNs uint64
	Pid         uint32
	Uid         uint32
	Dfd         int32
	Flags       uint32
	Filename    [256]byte
	FilenameLen uint32
}

type bpfNetEvent struct {
	TimestampNs uint64
	Pid         uint32
	Uid         uint32
	Sport       uint16
	Dport       uint16
	Saddr       [16]byte
	Daddr       [16]byte
	Family      uint8
	Initiated   uint8
	Pad         uint16
}

// parseExecEvent parses a raw exec event from the ring buffer and reconstructs
// all fields from /proc.
func (l *Listener) parseExecEvent(data []byte) (*ebpfEvent, error) {
	var raw bpfExecEvent
	if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &raw); err != nil {
		return nil, fmt.Errorf("decoding exec event: %w", err)
	}

	pid := raw.Pid
	ppid := raw.Ppid
	uid := raw.Uid

	// Resolve Image from /proc/PID/exe, fallback to BPF filename
	bpfFilename := nullTermStr(raw.Filename[:], int(raw.FilenameLen))
	image, err := readExeLink(pid)
	if err != nil {
		image = bpfFilename
	}

	// Read command line
	var cmdline string
	var truncated bool
	cmdBytes, err := readCmdline(pid)
	if err == nil {
		cmdline, truncated = joinCmdline(cmdBytes)
	}

	// Read cwd
	cwd, _ := readCwd(pid)

	// Read loginuid
	loginUID := readLoginUID(pid)

	// Resolve username
	username := l.userCache.Lookup(uid)

	// Resolve parent from correlator, then /proc fallback
	var parentImage, parentCmdline string
	if l.correlator != nil {
		if info := l.correlator.Lookup(ppid); info != nil {
			parentImage = info.Image
			parentCmdline = info.CommandLine
		}
	}
	if parentImage == "" {
		parentImage, _ = readExeLink(ppid)
	}
	if parentCmdline == "" {
		if pCmdBytes, err := readCmdline(ppid); err == nil {
			parentCmdline, _ = joinCmdline(pCmdBytes)
		}
	}

	fields := buildExecFieldsMap(
		pid, ppid, uid,
		bpfFilename, image, cmdline, truncated,
		cwd, loginUID, username,
		parentImage, parentCmdline,
	)

	// Store in correlator for future parent lookups
	if l.correlator != nil {
		l.correlator.Store(pid, &enrichment.ProcessInfo{
			PID:              pid,
			Image:            image,
			CommandLine:      cmdline,
			User:             username,
			CurrentDirectory: cwd,
		})
	}

	return &ebpfEvent{
		id: provider.EventIdentifier{
			ProviderName: ProviderName,
			EventID:      EventIDProcessCreation,
		},
		pid:    pid,
		source: SourceProcessExec,
		ts:     l.ktimeToWall(raw.TimestampNs),
		fields: fields,
	}, nil
}

// parseFileEvent parses a raw file event and reconstructs fields.
func (l *Listener) parseFileEvent(data []byte) (*ebpfEvent, error) {
	var raw bpfFileEvent
	if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &raw); err != nil {
		return nil, fmt.Errorf("decoding file event: %w", err)
	}

	pid := raw.Pid
	uid := raw.Uid
	filename := nullTermStr(raw.Filename[:], int(raw.FilenameLen))

	// Resolve filename to absolute path
	targetFilename := resolveFilename(pid, filename, raw.Dfd)

	// Resolve Image
	image, _ := readExeLink(pid)
	if image == "" && l.correlator != nil {
		if info := l.correlator.Lookup(pid); info != nil {
			image = info.Image
		}
	}

	username := l.userCache.Lookup(uid)

	fields := buildFileFieldsMap(pid, uid, targetFilename, image, username, raw.Flags)

	return &ebpfEvent{
		id: provider.EventIdentifier{
			ProviderName: ProviderName,
			EventID:      EventIDFileEvent,
		},
		pid:    pid,
		source: SourceFileCreate,
		ts:     l.ktimeToWall(raw.TimestampNs),
		fields: fields,
	}, nil
}

// parseNetEvent parses a raw network event and reconstructs fields.
func (l *Listener) parseNetEvent(data []byte) (*ebpfEvent, error) {
	var raw bpfNetEvent
	if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &raw); err != nil {
		return nil, fmt.Errorf("decoding net event: %w", err)
	}

	pid := raw.Pid
	uid := raw.Uid

	// Resolve Image
	image, _ := readExeLink(pid)
	if image == "" && l.correlator != nil {
		if info := l.correlator.Lookup(pid); info != nil {
			image = info.Image
		}
	}

	username := l.userCache.Lookup(uid)

	// Format IP addresses
	const afInet = 2
	var srcIP, dstIP string
	if raw.Family == afInet {
		srcIP = formatIPv4(raw.Saddr)
		dstIP = formatIPv4(raw.Daddr)
	} else {
		srcIP = formatIPv6(raw.Saddr)
		dstIP = formatIPv6(raw.Daddr)
	}

	initiated := raw.Initiated == 1

	fields := buildNetFieldsMap(
		pid, uid, image, username,
		srcIP, raw.Sport, dstIP, raw.Dport,
		initiated,
	)

	return &ebpfEvent{
		id: provider.EventIdentifier{
			ProviderName: ProviderName,
			EventID:      EventIDNetworkConnection,
		},
		pid:    pid,
		source: SourceNetConnect,
		ts:     l.ktimeToWall(raw.TimestampNs),
		fields: fields,
	}, nil
}

// LostEvents returns the total number of lost events across all enabled sources.
func (l *Listener) LostEvents() uint64 {
	var total uint64

	if l.execObjs != nil {
		total += readLostCounter(l.execObjs.LostEvents)
	}
	if l.fileObjs != nil {
		total += readLostCounter(l.fileObjs.FileLostEvents)
	}
	if l.netObjs != nil {
		total += readLostCounter(l.netObjs.NetLostEvents)
	}

	return total
}

// Close tears down all BPF programs and ring buffer readers.
func (l *Listener) Close() error {
	if l.closed.Swap(true) {
		return nil
	}

	// Close readers first to unblock Read() calls
	if l.execReader != nil {
		l.execReader.Close()
	}
	if l.fileReader != nil {
		l.fileReader.Close()
	}
	if l.netReader != nil {
		l.netReader.Close()
	}

	// Detach tracepoints
	if l.execLink != nil {
		l.execLink.Close()
	}
	if l.fileEnter != nil {
		l.fileEnter.Close()
	}
	if l.fileExit != nil {
		l.fileExit.Close()
	}
	if l.netLink != nil {
		l.netLink.Close()
	}

	// Close BPF objects
	if l.execObjs != nil {
		l.execObjs.Close()
	}
	if l.fileObjs != nil {
		l.fileObjs.Close()
	}
	if l.netObjs != nil {
		l.netObjs.Close()
	}

	return nil
}

// ktimeToWall converts a BPF ktime_get_ns() timestamp to wall clock time.
func (l *Listener) ktimeToWall(ktimeNs uint64) time.Time {
	wallNs := l.bootNanos + int64(ktimeNs)
	return time.Unix(0, wallNs)
}

// bootTimeNanos computes the wall-clock time of system boot in nanoseconds.
func bootTimeNanos() int64 {
	// Boot time = now - monotonic uptime
	// This is an approximation; for higher precision we could read /proc/stat btime.
	now := time.Now()
	var uptimeNs int64

	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return now.UnixNano()
	}

	// /proc/uptime: "seconds.centiseconds idle.centiseconds"
	fields := bytes.Fields(data)
	if len(fields) < 1 {
		return now.UnixNano()
	}

	// Parse the uptime seconds as float
	var secs, frac int64
	parts := bytes.SplitN(fields[0], []byte("."), 2)
	for _, b := range parts[0] {
		secs = secs*10 + int64(b-'0')
	}
	if len(parts) > 1 {
		// Parse fractional part (centiseconds → nanoseconds)
		fracStr := parts[1]
		for _, b := range fracStr {
			frac = frac*10 + int64(b-'0')
		}
		// Scale fractional part to nanoseconds
		scale := int64(1)
		for i := 0; i < 9-len(fracStr); i++ {
			scale *= 10
		}
		frac *= scale
	}

	uptimeNs = secs*1e9 + frac
	return now.UnixNano() - uptimeNs
}

// nullTermStr extracts a NUL-terminated string from a fixed byte array.
func nullTermStr(b []byte, maxLen int) string {
	if maxLen <= 0 || maxLen > len(b) {
		maxLen = len(b)
	}
	for i := 0; i < maxLen; i++ {
		if b[i] == 0 {
			return string(b[:i])
		}
	}
	return string(b[:maxLen])
}

// readLostCounter reads the single-entry BPF array map used as a lost event counter.
func readLostCounter(m *ebpf.Map) uint64 {
	if m == nil {
		return 0
	}
	var key uint32
	var count uint64
	if err := m.Lookup(&key, &count); err != nil {
		return 0
	}
	return count
}

// classifyBPFError wraps a BPF loading error with an actionable message.
func classifyBPFError(err error, program string) error {
	errStr := err.Error()

	switch {
	case contains(errStr, "unknown func") || contains(errStr, "BTF"):
		return fmt.Errorf(
			"loading %s: kernel too old or BTF disabled. "+
				"eBPF requires kernel 5.2+ with BTF. %w", program, err)
	case contains(errStr, "EPERM") || contains(errStr, "operation not permitted"):
		return fmt.Errorf(
			"loading %s: insufficient privileges. "+
				"Requires CAP_BPF+CAP_PERFMON (5.8+) or CAP_SYS_ADMIN (5.2-5.7) or root. %w", program, err)
	case contains(errStr, "ENOMEM"):
		return fmt.Errorf(
			"loading %s: memory limit too low. "+
				"Set LimitMEMLOCK=infinity in the systemd unit. %w", program, err)
	case contains(errStr, "EBUSY"):
		return fmt.Errorf(
			"loading %s: tracepoint is busy. "+
				"Another eBPF agent may be running. %w", program, err)
	default:
		return fmt.Errorf("loading %s: %w", program, err)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && bytes.Contains([]byte(s), []byte(substr))
}
