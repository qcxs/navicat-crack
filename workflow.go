package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

const (
	dllName = "libcc.dll"
	bakName = "libcc.dll.bak"
)

// dirCandidate 是自动检测到的安装目录及其来源说明。
type dirCandidate struct {
	Path   string
	Source string
}

// installState 描述某个安装目录当前已完成到哪一步，用于重复执行时自动跳过。
type installState struct {
	Dir          string
	DLLPath      string
	BackupPath   string
	DLLExists    bool
	BackupExists bool
	Legacy       bool   // 存在旧方案的 .pkey 节
	Supported    bool   // 成功定位到单字节补丁位置
	Patched      bool   // 补丁字节已是 0x54
	PatchOffset  int    // 补丁文件偏移
	PatchRVA     uint32 // 补丁 RVA
	LocateMethod string // known-hash / auto
	BuildVersion string // 已知版本号
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

func analyzeDir(dir string) *installState {
	st := &installState{Dir: dir}
	st.DLLPath = filepath.Join(dir, dllName)
	st.BackupPath = filepath.Join(dir, bakName)
	st.DLLExists = fileExists(st.DLLPath)
	st.BackupExists = fileExists(st.BackupPath)

	if st.DLLExists {
		if data, err := os.ReadFile(st.DLLPath); err == nil {
			st.inspect(data)
		}
	}
	return st
}

func (st *installState) inspect(data []byte) {
	if pe, err := parsePE(data); err == nil {
		if pe.findSection(".pkey") != nil {
			st.Legacy = true
		}
	}
	site, err := locatePatchSite(data)
	if err != nil || site == nil {
		return
	}
	st.Supported = true
	st.PatchOffset = site.FileOffset
	st.PatchRVA = site.RVA
	st.LocateMethod = site.Method
	st.BuildVersion = site.Version
	st.Patched = site.FileOffset < len(data) && data[site.FileOffset] == 0x54
}

// applyPatch 按“备份 → 定位 → 单字节补丁”执行，每一步都会检测是否已完成并跳过。
func applyPatch(dir string, logf func(string)) error {
	st := analyzeDir(dir)
	if !st.DLLExists && !st.BackupExists {
		return fmt.Errorf("目录中没有找到 %s，请确认选择的是 Navicat 安装目录", dllName)
	}
	if st.DLLExists && st.Legacy {
		return fmt.Errorf("检测到旧方案 .pkey 补丁，请删除 %s 并把 %s 改回 %s 后重新执行", dllName, bakName, dllName)
	}

	// 步骤 1：备份
	if st.BackupExists {
		logf("[跳过] 备份文件已存在：" + bakName)
	} else {
		if st.Patched {
			return fmt.Errorf("libcc.dll 已打过补丁但缺少备份文件，无法安全继续。请重新安装 Navicat 后再试")
		}
		if err := copyFile(st.DLLPath, st.BackupPath); err != nil {
			return fmt.Errorf("备份 %s 失败：%w", dllName, err)
		}
		logf("[完成] 已备份为 " + bakName)
		st.BackupExists = true
	}

	// 主文件缺失时先从备份恢复
	if !st.DLLExists {
		if err := copyFile(st.BackupPath, st.DLLPath); err != nil {
			return fmt.Errorf("由备份恢复 %s 失败：%w", dllName, err)
		}
		logf("[完成] 已由备份恢复 " + dllName)
		st = analyzeDir(dir)
	}

	// 步骤 2：定位并写单字节补丁
	if !st.Supported {
		return fmt.Errorf("无法定位该版本的补丁位置，未做任何修改（当前仅支持已核对的版本）")
	}
	if st.Legacy {
		return fmt.Errorf("检测到旧方案 .pkey 补丁，请先恢复原版文件")
	}
	if st.Patched {
		logf("[跳过] 单字节补丁已应用")
		return nil
	}

	data, err := os.ReadFile(st.DLLPath)
	if err != nil {
		return fmt.Errorf("读取 %s 失败：%w", dllName, err)
	}
	if st.PatchOffset <= 0 || st.PatchOffset >= len(data) || data[st.PatchOffset] != 0x53 {
		return fmt.Errorf("补丁位置校验失败，未修改")
	}
	data[st.PatchOffset] = 0x54
	if err := writeFileAtomic(st.DLLPath, data); err != nil {
		return fmt.Errorf("写入 %s 失败（请以管理员身份运行）：%w", dllName, err)
	}

	check, err := os.ReadFile(st.DLLPath)
	if err != nil || len(check) != len(data) || check[st.PatchOffset] != 0x54 {
		return fmt.Errorf("补丁写入后校验失败，请使用备份恢复")
	}
	logf(fmt.Sprintf("[完成] 已写入单字节补丁（文件偏移 0x%X，RVA 0x%X，定位方式：%s）",
		st.PatchOffset, st.PatchRVA, locateMethodName(st.LocateMethod)))
	return nil
}

func locateMethodName(method string) string {
	switch method {
	case "known-hash":
		return "已知版本"
	case "auto":
		return "自动定位"
	default:
		return "未知"
	}
}

func writeFileAtomic(path string, data []byte) error {
	tmp := filepath.Join(filepath.Dir(path), ".navicat-patch.tmp")
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// navicatRunning 检查是否有 Navicat 进程占用 DLL。
func navicatRunning() bool {
	cmd := exec.Command("tasklist", "/FI", "IMAGENAME eq Navicat.exe", "/NH")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	out, err := cmd.Output()
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(string(out)), "navicat.exe")
}

func isInstallDir(dir string) bool {
	return fileExists(filepath.Join(dir, dllName)) || fileExists(filepath.Join(dir, "navicat.exe"))
}

// findCandidateDirs 扫描常见安装位置，返回包含 libcc.dll 的目录及其来源。
func findCandidateDirs() []dirCandidate {
	seen := make(map[string]bool)
	var out []dirCandidate
	add := func(dir, source string) {
		dir = filepath.Clean(dir)
		key := strings.ToLower(dir)
		if seen[key] || !isInstallDir(dir) {
			return
		}
		seen[key] = true
		out = append(out, dirCandidate{Path: dir, Source: source})
	}

	if exe, err := os.Executable(); err == nil {
		add(filepath.Dir(exe), "程序所在目录")
	}
	if cwd, err := os.Getwd(); err == nil {
		add(cwd, "当前目录")
	}

	for _, c := range shortcutCandidates() {
		add(c.Path, c.Source)
	}

	for _, root := range driveRoots() {
		add(root, "盘根目录")
		scanDriveRoot(root, func(dir string) { add(dir, "盘根目录") })
		for _, base := range []string{"Program Files", "Program Files (x86)"} {
			scanProgramFiles(filepath.Join(root, base), func(dir string) { add(dir, "默认安装路径") })
		}
	}
	for _, env := range []string{"ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"} {
		if pf := os.Getenv(env); pf != "" {
			scanProgramFiles(pf, func(dir string) { add(dir, "默认安装路径") })
		}
	}
	return out
}

// scanDriveRoot 扫描盘符根目录下的 Navicat / PremiumSoft 目录（部分用户习惯装在盘根）。
func scanDriveRoot(root string, add func(string)) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := strings.ToLower(e.Name())
		if strings.Contains(name, "navicat") || strings.HasPrefix(name, "premiumsoft") {
			add(filepath.Join(root, e.Name()))
		}
	}
}

// scanProgramFiles 扫描 Program Files 下的 PremiumSoft 与 Navicat 目录。
func scanProgramFiles(pf string, add func(string)) {
	if entries, err := os.ReadDir(filepath.Join(pf, "PremiumSoft")); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				add(filepath.Join(pf, "PremiumSoft", e.Name()))
			}
		}
	}
	entries, err := os.ReadDir(pf)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := strings.ToLower(e.Name())
		if strings.HasPrefix(name, "navicat") || strings.HasPrefix(name, "premiumsoft") {
			add(filepath.Join(pf, e.Name()))
		}
	}
}

func driveRoots() []string {
	var roots []string
	for c := 'C'; c <= 'Z'; c++ {
		root := string(c) + `:\`
		if st, err := os.Stat(root); err == nil && st.IsDir() {
			roots = append(roots, root)
		}
	}
	return roots
}
