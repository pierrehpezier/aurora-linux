package ioc

import (
	"bufio"
	"errors"
	"os"
	"regexp"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

type filenameIOCEntry struct {
	pattern          *regexp.Regexp
	falsePositive    *regexp.Regexp
	rawPattern       string
	rawFalsePositive string
	score            int
	line             int
}

func loadFilenameIOCs(path string, required bool) ([]filenameIOCEntry, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, nil
	}

	f, err := os.Open(path)
	if err != nil {
		if required {
			return nil, missingIOCSourceError("filename", path, err)
		}
		if errors.Is(err, os.ErrNotExist) {
			log.WithField("path", path).Warn("Filename IOC file not found; filename IOC matching disabled")
		} else {
			log.WithError(err).WithField("path", path).Warn("Failed to open filename IOC file; filename IOC matching disabled")
		}
		return nil, nil
	}
	defer f.Close()

	entries := make([]filenameIOCEntry, 0)
	seen := make(map[string]struct{})

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)

	lineNo := 0
	for scanner.Scan() {
		lineNo++
		raw := strings.TrimSpace(scanner.Text())
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}

		parts := strings.SplitN(raw, ";", 3)
		if len(parts) < 2 {
			warnSkipIOCLine(path, lineNo, "expected format REGEX;SCORE[;FALSE_POSITIVE_REGEX]")
			continue
		}

		patternRaw := strings.TrimSpace(parts[0])
		scoreRaw := strings.TrimSpace(parts[1])
		if patternRaw == "" {
			warnSkipIOCLine(path, lineNo, "empty regex")
			continue
		}
		if scoreRaw == "" {
			warnSkipIOCLine(path, lineNo, "empty score")
			continue
		}

		score, err := strconv.Atoi(scoreRaw)
		if err != nil {
			warnSkipIOCLine(path, lineNo, "invalid score")
			continue
		}

		compiledPattern, err := regexp.Compile(patternRaw)
		if err != nil {
			warnSkipIOCLine(path, lineNo, "invalid regex")
			continue
		}

		falsePositiveRaw := ""
		var compiledFalsePositive *regexp.Regexp
		if len(parts) == 3 {
			falsePositiveRaw = strings.TrimSpace(parts[2])
			if falsePositiveRaw != "" {
				compiledFalsePositive, err = regexp.Compile(falsePositiveRaw)
				if err != nil {
					warnSkipIOCLine(path, lineNo, "invalid false positive regex")
					continue
				}
			}
		}

		key := patternRaw + ";" + strconv.Itoa(score) + ";" + falsePositiveRaw
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}

		entries = append(entries, filenameIOCEntry{
			pattern:          compiledPattern,
			falsePositive:    compiledFalsePositive,
			rawPattern:       patternRaw,
			rawFalsePositive: falsePositiveRaw,
			score:            score,
			line:             lineNo,
		})
	}

	if err := scanner.Err(); err != nil {
		if required {
			return nil, err
		}
		log.WithError(err).WithField("path", path).Warn("Error while reading filename IOC file; using parsed entries")
	}

	return entries, nil
}

func warnSkipIOCLine(path string, lineNo int, reason string) {
	log.WithFields(log.Fields{
		"path": path,
		"line": lineNo,
	}).Warnf("Skipping IOC line: %s", reason)
}
