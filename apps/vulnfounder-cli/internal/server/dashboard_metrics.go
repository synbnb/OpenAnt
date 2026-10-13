package server

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// sourceRepositoryCount reports the actual number of direct repositories in
// source_code_base.  It intentionally does not use repositoryOptions(),
// because that catalog also contains recent jobs and initialized projects.
func sourceRepositoryCount() int {
	root, err := sourceCodeBaseRoot()
	if err != nil {
		return 0
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return 0
	}
	count := 0
	for _, entry := range entries {
		if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || strings.HasPrefix(entry.Name(), ".vulnfounder-") {
			continue
		}
		count++
	}
	return count
}

type exposureSnapshotCandidate struct {
	path      string
	updatedAt time.Time
	modTime   time.Time
}

// latestExposureAssetCount reads the newest per-device latest.json snapshot.
// The dashboard only displays the asset count; it does not invent a count when
// no successful snapshot exists.  A malformed or symlinked snapshot is skipped
// so one partial device run cannot hide another device's valid result.
func latestExposureAssetCount(outDir string) int {
	root := filepath.Join(outDir, "device-socket-assets")
	rootInfo, err := os.Lstat(root)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return 0
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return 0
	}
	candidates := make([]exposureSnapshotCandidate, 0)
	for _, entry := range entries {
		if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			continue
		}
		path := filepath.Join(root, entry.Name(), "latest.json")
		info, statErr := os.Lstat(path)
		if statErr != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			continue
		}
		payload, readErr := readDeviceSocketAssetJSON(root, path, deviceSocketAssetMaxSnapshotBytes)
		if readErr != nil {
			continue
		}
		updated := parseExposureSnapshotTime(payload, "latest_updated")
		if updated.IsZero() {
			updated = parseExposureSnapshotTime(payload, "generated_at")
		}
		candidates = append(candidates, exposureSnapshotCandidate{path: path, updatedAt: updated, modTime: info.ModTime()})
	}
	if len(candidates) == 0 {
		return 0
	}
	sort.Slice(candidates, func(i, j int) bool {
		left, right := candidates[i], candidates[j]
		if !left.updatedAt.Equal(right.updatedAt) {
			return left.updatedAt.After(right.updatedAt)
		}
		return left.modTime.After(right.modTime)
	})
	payload, err := readDeviceSocketAssetJSON(root, candidates[0].path, deviceSocketAssetMaxSnapshotBytes)
	if err != nil {
		return 0
	}
	if value := disclosureInt(payload["asset_count"]); value >= 0 {
		if value > 0 {
			return value
		}
	}
	if assets, ok := payload["assets"].([]any); ok {
		return len(assets)
	}
	return disclosureInt(payload["socket_record_count"])
}

func parseExposureSnapshotTime(payload map[string]any, key string) time.Time {
	value := disclosureScalar(payload[key])
	if value == "" {
		return time.Time{}
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}
	}
	return parsed
}

func totalVulnerabilityReports(jobs []*Job) int {
	total := 0
	for _, job := range jobs {
		if job == nil {
			continue
		}
		job.mu.Lock()
		total += len(job.DisclosurePaths)
		job.mu.Unlock()
	}
	return total
}

// dashboardMetricSnapshot is deliberately calculated on request.  The values
// are operational counters, not cached claims: a scan or device run completed
// in another process becomes visible after the next page refresh.
func dashboardMetricSnapshot(outDir string, jobs []*Job) (repositories, exposureAssets, vulnerabilityReports int) {
	return sourceRepositoryCount(), latestExposureAssetCount(outDir), totalVulnerabilityReports(jobs)
}
