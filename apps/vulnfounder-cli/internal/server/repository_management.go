package server

// Repository management for the Web scan workbench.  The API intentionally
// operates on direct children of source_code_base only.  It never accepts an
// arbitrary filesystem path from the browser, and ZIP extraction is performed
// into a temporary sibling directory before an atomic rename.

import (
	"archive/zip"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"vulnfounder/apps/vulnfounder-cli/internal/config"
)

const (
	repositoryMarkerFile       = ".vulnfounder-repository"
	maxRepositoryArchiveBytes  = int64(256 << 20) // compressed upload limit
	maxRepositoryExpandedBytes = int64(1 << 30)   // ZIP-bomb guard
	maxRepositoryFiles         = 200000
	maxRepositoryPreviewFiles  = 60
	maxRepositoryNameLength    = 128
)

type managedRepository struct {
	Name           string   `json:"name"`
	RelativePath   string   `json:"relative_path"`
	FileCount      int      `json:"file_count"`
	TotalBytes     int64    `json:"total_bytes"`
	ModifiedAt     string   `json:"modified_at,omitempty"`
	PreviewFiles   []string `json:"preview_files"`
	PreviewLimited bool     `json:"preview_limited"`
	ScanAvailable  bool     `json:"scan_available"`
}

type repositoryInventoryResponse struct {
	Root         string              `json:"root"`
	Repositories []managedRepository `json:"repositories"`
	Total        int                 `json:"total"`
}

type repositoryMutationResponse struct {
	Repository *managedRepository `json:"repository,omitempty"`
	Deleted    string             `json:"deleted,omitempty"`
	Error      string             `json:"error,omitempty"`
}

// sourceCodeBaseRoot is stricter than the read-only catalog resolver.  A
// mutation must not follow a symlinked corpus root or operate outside the
// project-local directory selected by the configuration.
func sourceCodeBaseRoot() (string, error) {
	root, err := config.SourceCodeBaseDir()
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(root) == "" {
		return "", errors.New("尚未找到 source_code_base 目录")
	}
	info, err := os.Lstat(root)
	if err != nil {
		return "", fmt.Errorf("无法读取 source_code_base：%w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("source_code_base 必须是非符号链接目录")
	}
	return filepath.Clean(root), nil
}

func validManagedRepositoryName(raw string) (string, error) {
	name := strings.TrimSpace(raw)
	if name == "" {
		return "", errors.New("仓库名称不能为空")
	}
	if len(name) > maxRepositoryNameLength {
		return "", fmt.Errorf("仓库名称不能超过 %d 个字符", maxRepositoryNameLength)
	}
	if name == "." || name == ".." || name == repositoryMarkerFile || strings.HasPrefix(name, ".vulnfounder-") {
		return "", errors.New("仓库名称不可用")
	}
	if strings.ContainsAny(name, `/\\`) || strings.IndexByte(name, 0) >= 0 {
		return "", errors.New("仓库名称不能包含路径分隔符或空字节")
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return "", errors.New("仓库名称不能包含控制字符")
		}
	}
	return name, nil
}

func managedRepositoryPath(root, rawName string) (string, string, error) {
	name, err := validManagedRepositoryName(rawName)
	if err != nil {
		return "", "", err
	}
	dest := filepath.Join(root, name)
	if filepath.Dir(dest) != filepath.Clean(root) {
		return "", "", errors.New("仓库路径必须是 source_code_base 的直接子目录")
	}
	return dest, name, nil
}

func isRepositoryMarker(pathname string) bool {
	info, err := os.Lstat(pathname)
	return err == nil && info.Mode().IsRegular()
}

func repositoryHasScanMetadata(repoPath string) bool {
	gitPath := filepath.Join(repoPath, ".git")
	if info, err := os.Lstat(gitPath); err == nil && info.Mode()&os.ModeSymlink == 0 && (info.IsDir() || info.Mode().IsRegular()) {
		return true
	}
	return isRepositoryMarker(filepath.Join(repoPath, repositoryMarkerFile))
}

func summarizeManagedRepository(root, name string) (managedRepository, error) {
	repoPath, cleanName, err := managedRepositoryPath(root, name)
	if err != nil {
		return managedRepository{}, err
	}
	info, err := os.Lstat(repoPath)
	if err != nil {
		return managedRepository{}, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return managedRepository{}, errors.New("仓库必须是非符号链接目录")
	}
	result := managedRepository{
		Name:          cleanName,
		RelativePath:  filepath.ToSlash(filepath.Join("source_code_base", cleanName)),
		PreviewFiles:  make([]string, 0, maxRepositoryPreviewFiles),
		ScanAvailable: repositoryHasScanMetadata(repoPath),
		ModifiedAt:    info.ModTime().UTC().Format(time.RFC3339),
	}
	err = filepath.WalkDir(repoPath, func(current string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if current == repoPath {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			// Git metadata is repository state, not source preview content.  It
			// can also be very large for the OpenHarmony corpus.
			if entry.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		fileInfo, infoErr := entry.Info()
		if infoErr != nil {
			return infoErr
		}
		if !fileInfo.Mode().IsRegular() {
			return nil
		}
		rel, relErr := filepath.Rel(repoPath, current)
		if relErr != nil {
			return relErr
		}
		if rel == repositoryMarkerFile {
			return nil
		}
		result.FileCount++
		result.TotalBytes += fileInfo.Size()
		if fileInfo.ModTime().After(info.ModTime()) {
			info = fileInfo
		}
		if len(result.PreviewFiles) < maxRepositoryPreviewFiles {
			result.PreviewFiles = append(result.PreviewFiles, filepath.ToSlash(rel))
		} else {
			result.PreviewLimited = true
		}
		return nil
	})
	if err != nil {
		return managedRepository{}, err
	}
	result.ModifiedAt = info.ModTime().UTC().Format(time.RFC3339)
	return result, nil
}

func listManagedRepositories(root string) ([]managedRepository, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	items := make([]managedRepository, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || strings.HasPrefix(entry.Name(), ".vulnfounder-") {
			continue
		}
		item, summaryErr := summarizeManagedRepository(root, entry.Name())
		if summaryErr != nil {
			// A single unreadable child should not hide the rest of the corpus.
			continue
		}
		items = append(items, item)
	}
	// os.ReadDir is name-sorted, but keep the ordering explicit so the UI and
	// tests remain stable if the source ever changes.
	sortManagedRepositories(items)
	return items, nil
}

func sortManagedRepositories(items []managedRepository) {
	for i := 1; i < len(items); i++ {
		for j := i; j > 0 && strings.ToLower(items[j].Name) < strings.ToLower(items[j-1].Name); j-- {
			items[j], items[j-1] = items[j-1], items[j]
		}
	}
}

func writeRepositoryJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func (s *Server) handleRepositoryInventory(w http.ResponseWriter, _ *http.Request) {
	root, err := sourceCodeBaseRoot()
	if err != nil {
		// An empty corpus is a valid installation state: return an empty list so
		// the page can explain how to upload the first repository.
		if strings.Contains(err.Error(), "尚未找到") {
			writeRepositoryJSON(w, http.StatusOK, repositoryInventoryResponse{Root: "source_code_base", Repositories: []managedRepository{}, Total: 0})
			return
		}
		writeRepositoryJSON(w, http.StatusInternalServerError, repositoryMutationResponse{Error: err.Error()})
		return
	}
	s.repositoryMu.Lock()
	items, listErr := listManagedRepositories(root)
	s.repositoryMu.Unlock()
	if listErr != nil {
		writeRepositoryJSON(w, http.StatusInternalServerError, repositoryMutationResponse{Error: "读取仓库列表失败：" + listErr.Error()})
		return
	}
	writeRepositoryJSON(w, http.StatusOK, repositoryInventoryResponse{Root: "source_code_base", Repositories: items, Total: len(items)})
}

func (s *Server) requireRepositoryMutation(w http.ResponseWriter, r *http.Request) bool {
	if !sameOriginOK(r) {
		writeRepositoryJSON(w, http.StatusForbidden, repositoryMutationResponse{Error: "跨来源请求被拒绝"})
		return false
	}
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(s.csrfToken)) != 1 {
		writeRepositoryJSON(w, http.StatusForbidden, repositoryMutationResponse{Error: "缺少或无效的 CSRF 令牌"})
		return false
	}
	return true
}

func randomRepositorySuffix() string {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(buf)
}

func normalizeArchiveEntryName(raw string) (string, bool, error) {
	if raw == "" || strings.IndexByte(raw, 0) >= 0 || strings.Contains(raw, `\`) {
		return "", false, errors.New("ZIP 条目名称无效")
	}
	trimmed := strings.TrimSuffix(raw, "/")
	if strings.HasPrefix(trimmed, "/") {
		return "", false, errors.New("ZIP 条目不能使用绝对路径")
	}
	for _, part := range strings.Split(trimmed, "/") {
		if part == ".." || part == "" || part == "." {
			return "", false, errors.New("ZIP 条目包含不安全路径")
		}
		for _, r := range part {
			if unicode.IsControl(r) {
				return "", false, errors.New("ZIP 条目包含控制字符")
			}
		}
	}
	clean := path.Clean(trimmed)
	if clean == "." || clean == "" {
		return "", true, nil
	}
	if strings.HasPrefix(clean, "/") || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", false, errors.New("ZIP 条目不能越过仓库目录")
	}
	converted := filepath.FromSlash(clean)
	if filepath.IsAbs(converted) || filepath.VolumeName(converted) != "" {
		return "", false, errors.New("ZIP 条目不能使用绝对卷路径")
	}
	return clean, strings.HasSuffix(raw, "/"), nil
}

func archiveTarget(root, clean string) (string, error) {
	target := filepath.Join(root, filepath.FromSlash(clean))
	rel, err := filepath.Rel(root, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", errors.New("ZIP 条目解析后超出临时目录")
	}
	return target, nil
}

func (s *Server) handleRepositoryUpload(w http.ResponseWriter, r *http.Request) {
	if !s.requireRepositoryMutation(w, r) {
		return
	}
	root, err := sourceCodeBaseRoot()
	if err != nil {
		writeRepositoryJSON(w, http.StatusBadRequest, repositoryMutationResponse{Error: err.Error()})
		return
	}
	// Leave a little room for multipart headers while enforcing the actual ZIP
	// byte limit below.  The body is never accepted unboundedly.
	r.Body = http.MaxBytesReader(w, r.Body, maxRepositoryArchiveBytes+(4<<20))
	if err := r.ParseMultipartForm(4 << 20); err != nil {
		writeRepositoryJSON(w, http.StatusBadRequest, repositoryMutationResponse{Error: "无法读取 ZIP 上传：" + err.Error()})
		return
	}
	file, header, err := r.FormFile("archive")
	if err != nil {
		writeRepositoryJSON(w, http.StatusBadRequest, repositoryMutationResponse{Error: "请选择一个 ZIP 文件"})
		return
	}
	defer file.Close()

	s.repositoryMu.Lock()
	defer s.repositoryMu.Unlock()
	archivePath := filepath.Join(root, ".vulnfounder-upload-"+randomRepositorySuffix()+".zip")
	archiveFile, err := os.OpenFile(archivePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		writeRepositoryJSON(w, http.StatusInternalServerError, repositoryMutationResponse{Error: "无法创建临时上传文件"})
		return
	}
	n, copyErr := io.Copy(archiveFile, io.LimitReader(file, maxRepositoryArchiveBytes+1))
	closeErr := archiveFile.Close()
	if copyErr != nil || closeErr != nil || n > maxRepositoryArchiveBytes {
		_ = os.Remove(archivePath)
		writeRepositoryJSON(w, http.StatusBadRequest, repositoryMutationResponse{Error: "ZIP 文件过大或读取失败，压缩包上限为 256 MiB"})
		return
	}
	defer os.Remove(archivePath)

	zipReader, err := zip.OpenReader(archivePath)
	if err != nil {
		writeRepositoryJSON(w, http.StatusBadRequest, repositoryMutationResponse{Error: "上传文件不是有效 ZIP：" + err.Error()})
		return
	}
	defer zipReader.Close()

	type selectedEntry struct {
		file  *zip.File
		clean string
		dir   bool
	}
	entries := make([]selectedEntry, 0, len(zipReader.File))
	topRoots := make(map[string]struct{})
	hasRootFiles := false
	fileCount := 0
	for _, entry := range zipReader.File {
		clean, dir, nameErr := normalizeArchiveEntryName(entry.Name)
		if nameErr != nil {
			writeRepositoryJSON(w, http.StatusBadRequest, repositoryMutationResponse{Error: "ZIP 包含不安全路径：" + entry.Name})
			return
		}
		if clean == "" {
			continue
		}
		dir = dir || entry.Mode().IsDir()
		if entry.Mode()&os.ModeSymlink != 0 || (!dir && !entry.Mode().IsRegular()) {
			writeRepositoryJSON(w, http.StatusBadRequest, repositoryMutationResponse{Error: "ZIP 不允许包含符号链接或特殊文件：" + entry.Name})
			return
		}
		parts := strings.Split(clean, "/")
		topRoots[parts[0]] = struct{}{}
		if len(parts) == 1 && !dir {
			hasRootFiles = true
		}
		if !dir {
			fileCount++
			if fileCount > maxRepositoryFiles {
				writeRepositoryJSON(w, http.StatusBadRequest, repositoryMutationResponse{Error: "ZIP 文件数量超过安全上限"})
				return
			}
		}
		entries = append(entries, selectedEntry{file: entry, clean: clean, dir: dir})
	}
	if fileCount == 0 {
		writeRepositoryJSON(w, http.StatusBadRequest, repositoryMutationResponse{Error: "ZIP 中没有可提取的普通文件"})
		return
	}

	requestedName := strings.TrimSpace(r.FormValue("name"))
	stripRoot := len(topRoots) == 1 && !hasRootFiles
	if requestedName == "" {
		if stripRoot {
			for rootName := range topRoots {
				requestedName = rootName
			}
		} else {
			base := filepath.Base(strings.TrimSpace(header.Filename))
			requestedName = strings.TrimSuffix(base, filepath.Ext(base))
		}
	}
	dest, cleanName, nameErr := managedRepositoryPath(root, requestedName)
	if nameErr != nil {
		writeRepositoryJSON(w, http.StatusBadRequest, repositoryMutationResponse{Error: nameErr.Error()})
		return
	}
	if _, statErr := os.Lstat(dest); statErr == nil {
		writeRepositoryJSON(w, http.StatusConflict, repositoryMutationResponse{Error: "同名仓库已存在，请更换名称或先删除旧仓库"})
		return
	} else if !os.IsNotExist(statErr) {
		writeRepositoryJSON(w, http.StatusInternalServerError, repositoryMutationResponse{Error: "无法检查目标仓库"})
		return
	}

	staging, err := os.MkdirTemp(root, ".vulnfounder-staging-")
	if err != nil {
		writeRepositoryJSON(w, http.StatusInternalServerError, repositoryMutationResponse{Error: "无法创建解压临时目录"})
		return
	}
	defer os.RemoveAll(staging)
	extractRoot := filepath.Join(staging, cleanName)
	if err := os.MkdirAll(extractRoot, 0700); err != nil {
		writeRepositoryJSON(w, http.StatusInternalServerError, repositoryMutationResponse{Error: "无法准备解压目录"})
		return
	}
	seenTargets := make(map[string]struct{})
	var expandedBytes int64
	for _, selected := range entries {
		relative := selected.clean
		if stripRoot {
			parts := strings.Split(relative, "/")
			if len(parts) == 1 {
				continue
			}
			relative = strings.Join(parts[1:], "/")
		}
		if relative == "" {
			continue
		}
		target, targetErr := archiveTarget(extractRoot, relative)
		if targetErr != nil {
			writeRepositoryJSON(w, http.StatusBadRequest, repositoryMutationResponse{Error: targetErr.Error()})
			return
		}
		if _, duplicate := seenTargets[target]; duplicate {
			writeRepositoryJSON(w, http.StatusBadRequest, repositoryMutationResponse{Error: "ZIP 包含重复文件路径：" + relative})
			return
		}
		seenTargets[target] = struct{}{}
		if selected.dir {
			if err := os.MkdirAll(target, 0700); err != nil {
				writeRepositoryJSON(w, http.StatusBadRequest, repositoryMutationResponse{Error: "无法创建 ZIP 目录：" + relative})
				return
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			writeRepositoryJSON(w, http.StatusInternalServerError, repositoryMutationResponse{Error: "无法准备 ZIP 文件目录"})
			return
		}
		out, createErr := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, safeRepositoryFileMode(selected.file.Mode().Perm()))
		if createErr != nil {
			writeRepositoryJSON(w, http.StatusBadRequest, repositoryMutationResponse{Error: "无法写入 ZIP 文件：" + relative})
			return
		}
		in, openErr := selected.file.Open()
		if openErr != nil {
			_ = out.Close()
			writeRepositoryJSON(w, http.StatusBadRequest, repositoryMutationResponse{Error: "无法读取 ZIP 文件：" + relative})
			return
		}
		limited := io.LimitReader(in, maxRepositoryExpandedBytes-expandedBytes+1)
		written, writeErr := io.Copy(out, limited)
		_ = in.Close()
		_ = out.Close()
		if writeErr != nil || written > maxRepositoryExpandedBytes-expandedBytes {
			writeRepositoryJSON(w, http.StatusBadRequest, repositoryMutationResponse{Error: "ZIP 解压内容超过安全上限"})
			return
		}
		expandedBytes += written
	}
	marker := filepath.Join(extractRoot, repositoryMarkerFile)
	if err := os.WriteFile(marker, []byte("managed by VulnFounder\n"), 0600); err != nil {
		writeRepositoryJSON(w, http.StatusInternalServerError, repositoryMutationResponse{Error: "无法写入仓库管理标记"})
		return
	}
	if err := os.Rename(extractRoot, dest); err != nil {
		writeRepositoryJSON(w, http.StatusInternalServerError, repositoryMutationResponse{Error: "无法提交新仓库：" + err.Error()})
		return
	}
	item, err := summarizeManagedRepository(root, cleanName)
	if err != nil {
		_ = os.RemoveAll(dest)
		writeRepositoryJSON(w, http.StatusInternalServerError, repositoryMutationResponse{Error: "仓库已写入但无法读取摘要：" + err.Error()})
		return
	}
	writeRepositoryJSON(w, http.StatusCreated, repositoryMutationResponse{Repository: &item})
}

func safeRepositoryFileMode(mode os.FileMode) os.FileMode {
	mode &= 0777
	if mode == 0 {
		return 0600
	}
	// Do not let an uploaded archive create an executable setuid/setgid file.
	return mode &^ (os.ModeSetuid | os.ModeSetgid | os.ModeSticky)
}

func (s *Server) repositoryInUse(repoPath string) bool {
	for _, job := range s.mgr.all() {
		job.mu.Lock()
		active := job.Status == StatusRunning && filepath.Clean(job.Repo) == filepath.Clean(repoPath)
		job.mu.Unlock()
		if active {
			return true
		}
	}
	return false
}

func (s *Server) handleRepositoryDelete(w http.ResponseWriter, r *http.Request) {
	if !s.requireRepositoryMutation(w, r) {
		return
	}
	root, err := sourceCodeBaseRoot()
	if err != nil {
		writeRepositoryJSON(w, http.StatusBadRequest, repositoryMutationResponse{Error: err.Error()})
		return
	}
	s.repositoryMu.Lock()
	defer s.repositoryMu.Unlock()
	dest, name, pathErr := managedRepositoryPath(root, r.PathValue("name"))
	if pathErr != nil {
		writeRepositoryJSON(w, http.StatusBadRequest, repositoryMutationResponse{Error: pathErr.Error()})
		return
	}
	info, statErr := os.Lstat(dest)
	if os.IsNotExist(statErr) {
		writeRepositoryJSON(w, http.StatusNotFound, repositoryMutationResponse{Error: "仓库不存在"})
		return
	}
	if statErr != nil {
		writeRepositoryJSON(w, http.StatusInternalServerError, repositoryMutationResponse{Error: "无法读取仓库"})
		return
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		writeRepositoryJSON(w, http.StatusBadRequest, repositoryMutationResponse{Error: "目标不是可管理的仓库目录"})
		return
	}
	if s.repositoryInUse(dest) {
		writeRepositoryJSON(w, http.StatusConflict, repositoryMutationResponse{Error: "仓库正在被运行中的扫描使用，暂不能删除"})
		return
	}
	if err := os.RemoveAll(dest); err != nil {
		writeRepositoryJSON(w, http.StatusInternalServerError, repositoryMutationResponse{Error: "删除仓库失败：" + err.Error()})
		return
	}
	writeRepositoryJSON(w, http.StatusOK, repositoryMutationResponse{Deleted: name})
}
