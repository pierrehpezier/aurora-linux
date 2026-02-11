package ebpf

import (
	"strconv"
	"strings"

	"github.com/nicholasgasior/aurora-linux/lib/enrichment"
)

// joinCmdline converts NUL-separated /proc/PID/cmdline bytes into a
// space-separated command line string. If the data fills the entire buffer
// (maxCmdlineBytes), a truncation suffix is appended.
func joinCmdline(data []byte) (cmdline string, truncated bool) {
	if len(data) == 0 {
		return "", false
	}

	// Replace NUL bytes with spaces
	s := strings.ReplaceAll(string(data), "\x00", " ")
	s = strings.TrimRight(s, " ")

	truncated = len(data) >= maxCmdlineBytes
	if truncated {
		s += " ...(truncated)"
	}
	return s, truncated
}

// buildExecFieldsMap constructs the DataFieldsMap for a process_creation event.
func buildExecFieldsMap(
	pid, ppid, uid uint32,
	bpfFilename string,
	image string,
	cmdline string,
	truncated bool,
	cwd string,
	loginUID string,
	username string,
	parentImage string,
	parentCmdline string,
) enrichment.DataFieldsMap {
	fields := make(enrichment.DataFieldsMap, 12)

	fields.AddField("Image", image)
	fields.AddField("CommandLine", cmdline)
	fields.AddField("ParentImage", parentImage)
	fields.AddField("ParentCommandLine", parentCmdline)
	fields.AddField("User", username)
	fields.AddField("LogonId", loginUID)
	fields.AddField("CurrentDirectory", cwd)
	fields.AddField("ProcessId", strconv.FormatUint(uint64(pid), 10))
	fields.AddField("ParentProcessId", strconv.FormatUint(uint64(ppid), 10))

	if truncated {
		fields.AddField("CommandLineTruncated", "true")
	}

	return fields
}

// buildFileFieldsMap constructs the DataFieldsMap for a file_event.
func buildFileFieldsMap(
	pid, uid uint32,
	targetFilename string,
	image string,
	username string,
	flags uint32,
) enrichment.DataFieldsMap {
	fields := make(enrichment.DataFieldsMap, 6)

	fields.AddField("TargetFilename", targetFilename)
	fields.AddField("Image", image)
	fields.AddField("User", username)
	fields.AddField("ProcessId", strconv.FormatUint(uint64(pid), 10))
	fields.AddField("FileFlags", strconv.FormatUint(uint64(flags), 10))

	return fields
}

// buildNetFieldsMap constructs the DataFieldsMap for a network_connection event.
func buildNetFieldsMap(
	pid, uid uint32,
	image string,
	username string,
	srcIP string,
	srcPort uint16,
	dstIP string,
	dstPort uint16,
	initiated bool,
) enrichment.DataFieldsMap {
	fields := make(enrichment.DataFieldsMap, 10)

	fields.AddField("Image", image)
	fields.AddField("DestinationIp", dstIP)
	fields.AddField("DestinationPort", strconv.Itoa(int(dstPort)))
	fields.AddField("SourceIp", srcIP)
	fields.AddField("SourcePort", strconv.Itoa(int(srcPort)))
	fields.AddField("User", username)
	fields.AddField("ProcessId", strconv.FormatUint(uint64(pid), 10))
	fields.AddField("Protocol", "tcp")
	fields.AddField("DestinationHostname", "") // Phase 2: DNS correlation

	if initiated {
		fields.AddField("Initiated", "true")
	} else {
		fields.AddField("Initiated", "false")
	}

	return fields
}

// formatIPv4 formats a v4-mapped-v6 address (bytes 12-15) as dotted decimal.
func formatIPv4(addr [16]byte) string {
	return strconv.Itoa(int(addr[12])) + "." +
		strconv.Itoa(int(addr[13])) + "." +
		strconv.Itoa(int(addr[14])) + "." +
		strconv.Itoa(int(addr[15]))
}

// formatIPv6 formats a 16-byte IPv6 address as a string.
func formatIPv6(addr [16]byte) string {
	// Use net.IP for proper formatting with zero compression
	ip := make([]byte, 16)
	copy(ip, addr[:])

	// Manual formatting to avoid net package dependency in hot path
	// Format as 8 groups of 4 hex digits, then compress
	groups := make([]string, 8)
	for i := 0; i < 8; i++ {
		groups[i] = strconv.FormatUint(uint64(addr[i*2])<<8|uint64(addr[i*2+1]), 16)
	}

	// Find longest run of zero groups for :: compression
	bestStart, bestLen := -1, 0
	curStart, curLen := -1, 0
	for i, g := range groups {
		if g == "0" {
			if curStart == -1 {
				curStart = i
				curLen = 1
			} else {
				curLen++
			}
		} else {
			if curLen > bestLen {
				bestStart = curStart
				bestLen = curLen
			}
			curStart = -1
			curLen = 0
		}
	}
	if curLen > bestLen {
		bestStart = curStart
		bestLen = curLen
	}

	if bestLen < 2 {
		return strings.Join(groups, ":")
	}

	var parts []string
	if bestStart == 0 {
		parts = append(parts, "")
	}
	parts = append(parts, strings.Join(groups[:bestStart], ":"))
	parts = append(parts, strings.Join(groups[bestStart+bestLen:], ":"))
	if bestStart+bestLen == 8 {
		parts = append(parts, "")
	}

	return strings.Join(parts, "::")
}
