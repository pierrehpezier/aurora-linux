package ioc

import (
	"bufio"
	"errors"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
)

func loadC2IOCs(path string, required bool) (map[string]struct{}, map[string]struct{}, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return map[string]struct{}{}, map[string]struct{}{}, nil
	}

	f, err := os.Open(path)
	if err != nil {
		if required {
			return nil, nil, missingIOCSourceError("c2", path, err)
		}
		if errors.Is(err, os.ErrNotExist) {
			log.WithField("path", path).Warn("C2 IOC file not found; C2 IOC matching disabled")
		} else {
			log.WithError(err).WithField("path", path).Warn("Failed to open C2 IOC file; C2 IOC matching disabled")
		}
		return map[string]struct{}{}, map[string]struct{}{}, nil
	}
	defer f.Close()

	domains := make(map[string]struct{})
	ips := make(map[string]struct{})

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)

	lineNo := 0
	for scanner.Scan() {
		lineNo++
		raw := strings.TrimSpace(scanner.Text())
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}

		if strings.ContainsAny(raw, " \t") {
			warnSkipIOCLine(path, lineNo, "unexpected whitespace")
			continue
		}

		if ip := normalizeIP(raw); ip != "" {
			ips[ip] = struct{}{}
			continue
		}

		host := normalizeDomain(raw)
		if !isLikelyDomain(host) {
			warnSkipIOCLine(path, lineNo, "invalid domain or IP")
			continue
		}
		domains[host] = struct{}{}
	}

	if err := scanner.Err(); err != nil {
		if required {
			return nil, nil, err
		}
		log.WithError(err).WithField("path", path).Warn("Error while reading C2 IOC file; using parsed entries")
	}

	return domains, ips, nil
}

func isLikelyDomain(value string) bool {
	if value == "" {
		return false
	}
	if strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") {
		return false
	}
	if strings.Contains(value, "..") {
		return false
	}
	if !strings.Contains(value, ".") {
		return false
	}

	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '.' || r == '-':
		default:
			return false
		}
	}

	return true
}
