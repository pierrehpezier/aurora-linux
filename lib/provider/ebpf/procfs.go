package ebpf

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	maxCmdlineBytes = 32768
	loginUIDUnset   = "4294967295"
)

// readExeLink resolves /proc/PID/exe symlink to the real binary path.
func readExeLink(pid uint32) (string, error) {
	link, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return "", err
	}
	// Kernel appends " (deleted)" if the binary was unlinked after exec
	link = strings.TrimSuffix(link, " (deleted)")
	return link, nil
}

// readCmdline reads /proc/PID/cmdline and returns the raw NUL-separated bytes.
func readCmdline(pid uint32) ([]byte, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return nil, err
	}
	if len(data) > maxCmdlineBytes {
		data = data[:maxCmdlineBytes]
	}
	return data, nil
}

// readCwd resolves /proc/PID/cwd symlink.
func readCwd(pid uint32) (string, error) {
	return os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid))
}

// readLoginUID reads /proc/PID/loginuid.
// Returns empty string if the value is unset (4294967295).
func readLoginUID(pid uint32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/loginuid", pid))
	if err != nil {
		return ""
	}
	s := strings.TrimSpace(string(data))
	if s == loginUIDUnset {
		return ""
	}
	return s
}

// readFdLink resolves /proc/PID/fd/N symlink — used for dfd resolution.
func readFdLink(pid uint32, fd int32) (string, error) {
	return os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", pid, fd))
}

// resolveFilename resolves a potentially relative filename using dfd.
// If filename is absolute, it is returned directly (with symlinks evaluated).
// If dfd == AT_FDCWD (-100), it is resolved relative to the process cwd.
// Otherwise it is resolved relative to the directory referenced by dfd.
func resolveFilename(pid uint32, filename string, dfd int32) string {
	if filepath.IsAbs(filename) {
		resolved, err := filepath.EvalSymlinks(filename)
		if err != nil {
			return filename
		}
		return resolved
	}

	var base string
	const atFDCWD = -100
	if dfd == atFDCWD {
		cwd, err := readCwd(pid)
		if err != nil {
			return filename
		}
		base = cwd
	} else {
		fdPath, err := readFdLink(pid, dfd)
		if err != nil {
			return filename
		}
		base = fdPath
	}

	full := filepath.Join(base, filename)
	resolved, err := filepath.EvalSymlinks(full)
	if err != nil {
		return full
	}
	return resolved
}
