package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
)

const (
	idCombo      = 1001
	idBrowse     = 1002
	idDetect     = 1003
	idCheck      = 1004
	idPatch      = 1005
	idNetPanel   = 1006
	idStatus     = 1008
	idLog        = 1009
	idActGen     = 1010
	idActCopy    = 1011
	idActCopyKey = 1012
	idActLaunch  = 1013
	idActRefresh = 1014
)

// SS_ETCHEDHORZ / SS_ETCHEDVERT，用于绘制分隔线
const (
	ssEtchedHorz = 0x00000010
	ssEtchedVert = 0x00000011
)

// defaultOfflineKey 为默认的离线激活密钥（本身也是一个合法的 16 位序列号）
const defaultOfflineKey = "NAVMIKCHCWNIHS3Q"

var currentOfflineKey = defaultOfflineKey

const mainClassName = "NavicatCrackToolMainWnd"

var (
	hwndMain   uintptr
	hCombo     uintptr
	hStatusBox uintptr
	hLogBox    uintptr
	uiFont     uintptr
	uiFontBold uintptr
	dpiScale   = 1.0
	logBuf     strings.Builder
	mainProc   uintptr
	dirSources = make(map[string]string)
	hDirSource uintptr
)

func main() {
	runtime.LockOSThread()

	if !isAdmin() {
		msgBox(0, "本程序需要以管理员身份运行。\n\n"+
			"原因：需要写入 Navicat 安装目录下的 libcc.dll。\n\n"+
			"请关闭本程序后，右键 navicat-crack.exe，\n"+
			"选择「以管理员身份运行」再试。", "需要管理员权限", mbIconWarn)
		return
	}

	initDPI()
	uiFont = createFont("Microsoft YaHei UI", 9, 400)
	uiFontBold = createFont("Microsoft YaHei UI", 10, 700)
	pCoInitializeEx.Call(0, 2) // COINIT_APARTMENTTHREADED，供文件夹选择框使用

	mainProc = syscall.NewCallback(mainWndProc)
	if err := registerClass(mainClassName, mainProc, 16); err != nil {
		msgBox(0, "注册窗口类失败："+err.Error(), "启动失败", mbIconError)
		return
	}

	style := uint32(wsCaption | wsSysMenu | wsMinimizeBox | wsClipChildren)
	ww, wh := adjustSize(sc(1080), sc(540), style)
	x, y := centeredPos(ww, wh)
	hwndMain = createWindow(mainClassName, "Navicat 17.3.x 激活工具", style, x, y, ww, wh, 0, 0)
	if hwndMain == 0 {
		msgBox(0, "创建窗口失败", "启动失败", mbIconError)
		return
	}
	pShowWindow.Call(hwndMain, swShow)
	pUpdateWindow.Call(hwndMain)
	runMessageLoop()
}

func initDPI() {
	pSetProcessDPIAware.Call()
	if hdc, _, _ := pGetDC.Call(0); hdc != 0 {
		if v, _, _ := pGetDeviceCaps.Call(hdc, logPixelsX); v > 0 {
			dpiScale = float64(v) / 96.0
		}
		pReleaseDC.Call(0, hdc)
	}
	if dpiScale < 1 {
		dpiScale = 1
	}
}

func sc(v int32) int32 {
	return int32(float64(v)*dpiScale + 0.5)
}

func mainWndProc(hwnd, msg, wParam, lParam uintptr) (ret uintptr) {
	defer func() {
		if r := recover(); r != nil {
			appendLog(fmt.Sprintf("[内部错误] %v", r))
		}
	}()

	switch msg {
	case wmCreate:
		hwndMain = hwnd
		buildMainUI(hwnd)
		doInitialDetect()
		return 0
	case wmCommand:
		id := int(wParam & 0xffff)
		code := int((wParam >> 16) & 0xffff)
		switch id {
		case idBrowse:
			onBrowse()
		case idDetect:
			onDetect()
		case idCheck:
			runAnalyze()
		case idPatch:
			onPatch()
		case idActGen:
			onGenerateActivation(hwnd)
		case idActCopy:
			onCopyActivation(hwnd)
		case idActCopyKey:
			onCopyOfflineKey(hwnd)
		case idActRefresh:
			onRefreshOfflineKey(hwnd)
		case idActLaunch:
			launchNavicat(hwnd)
		case idNetPanel:
			onOpenNetworkPanel()
		case idCombo:
			if code == cbnSelChange {
				updateDirSourceLabel()
				runAnalyze()
			} else if code == cbnEditChange {
				updateDirSourceLabel()
			}
		}
		return 0
	case wmDestroy:
		pPostQuitMessage.Call(0)
		return 0
	}
	r, _, _ := pDefWindowProcW.Call(hwnd, msg, wParam, lParam)
	return r
}

func buildMainUI(hwnd uintptr) {
	// ---- 左侧：安装目录 ----
	h := mkLabel(hwnd, "安装目录", 16, 14, 80, 20)
	setWindowFont(h, uiFontBold)
	hDirSource = mkLabel(hwnd, "（未检测）", 96, 14, 600, 20)
	hCombo = createWindow("COMBOBOX", "", wsChild|wsVisible|wsTabStop|wsVScroll|
		cbsDropDown|cbsAutoHScroll|cbsHasStrings, sc(16), sc(36), sc(480), sc(220), hwnd, idCombo)
	setWindowFont(hCombo, uiFont)
	pSendMessageW.Call(hCombo, cbSetDroppedWidth, uintptr(sc(760)), 0)
	mkButton(hwnd, "浏览...", idBrowse, 504, 33, 88, 28)
	mkButton(hwnd, "自动检测", idDetect, 600, 33, 104, 28)

	// ---- 右侧：当前状态与日志 ----
	mkLabel(hwnd, "当前状态", 736, 14, 200, 18)
	hStatusBox = createWindow("EDIT", "", wsChild|wsVisible|wsBorder|wsVScroll|
		esMultiline|esAutoVScroll|esReadOnly, sc(736), sc(34), sc(328), sc(160), hwnd, idStatus)
	setWindowFont(hStatusBox, uiFont)

	mkLabel(hwnd, "日志", 736, 208, 100, 18)
	hLogBox = createWindow("EDIT", "", wsChild|wsVisible|wsBorder|wsVScroll|
		esMultiline|esAutoVScroll|esReadOnly, sc(736), sc(228), sc(328), sc(290), hwnd, idLog)
	setWindowFont(hLogBox, uiFont)
	mkVerticalSeparator(hwnd, 724, 14, 500)

	// ---- 第 1 步 ----
	mkStep(hwnd, "第 1 步  检查状态", 72)
	mkHint(hwnd, "确认 libcc.dll 是否可识别、是否已备份、是否已打补丁", 96)
	mkButton(hwnd, "检查状态", idCheck, 576, 70, 128, 28)
	mkSeparator(hwnd, 118)

	// ---- 第 2 步 ----
	step2 := mkLabel(hwnd, "第 2 步  备份并打补丁", 16, 128, 260, 22)
	setWindowFont(step2, uiFontBold)
	mkLabel(hwnd, "自动备份 libcc.dll 并写入单字节补丁（自动定位版本偏移，已完成会跳过）", 16, 152, 420, 18)
	mkButton(hwnd, "备份并打补丁", idPatch, 440, 126, 128, 28)
	mkButton(hwnd, "启动 Navicat", idActLaunch, 576, 126, 128, 28)
	mkSeparator(hwnd, 174)

	// ---- 第 3 步 ----
	step3 := mkLabel(hwnd, "第 3 步  离线激活", 16, 184, 260, 22)
	setWindowFont(step3, uiFontBold)
	mkLabel(hwnd, "激活前请断开网络：", 300, 186, 240, 18)
	mkButton(hwnd, "打开网络连接", idNetPanel, 548, 182, 156, 28)
	mkHint(hwnd, "复制或刷新离线密钥，在 Navicat 中获取请求码，粘贴到下方生成激活码", 212)
	buildActivateSection(hwnd)

	appendLog("提示：建议先断开网络，并关闭所有 Navicat 相关进程。")
	appendLog("如需断网，可点「打开网络连接」，在系统中右键网卡选择禁用。")
	appendLog("请按 第 1 步 → 第 2 步 → 第 3 步 的顺序操作。")
	appendLog("离线激活密钥：" + currentOfflineKey + "（第 3 步可复制或刷新）")
}

func mkLabel(parent uintptr, text string, x, y, w, h int32) uintptr {
	c := createWindow("STATIC", text, wsChild|wsVisible, sc(x), sc(y), sc(w), sc(h), parent, 0)
	setWindowFont(c, uiFont)
	return c
}

func mkStep(parent uintptr, text string, y int32) uintptr {
	c := mkLabel(parent, text, 16, y, 560, 22)
	setWindowFont(c, uiFontBold)
	return c
}

func mkHint(parent uintptr, text string, y int32) uintptr {
	return mkLabel(parent, text, 16, y, 545, 18)
}

func mkSeparator(parent uintptr, y int32) {
	createWindow("STATIC", "", wsChild|wsVisible|ssEtchedHorz,
		sc(16), sc(y), sc(688), sc(2), parent, 0)
}

func mkVerticalSeparator(parent uintptr, x, y, h int32) {
	createWindow("STATIC", "", wsChild|wsVisible|ssEtchedVert,
		sc(x), sc(y), sc(2), sc(h), parent, 0)
}

func mkButton(parent uintptr, text string, id, x, y, w, h int32) uintptr {
	c := createWindow("BUTTON", text, wsChild|wsVisible|wsTabStop, sc(x), sc(y), sc(w), sc(h), parent, uintptr(id))
	setWindowFont(c, uiFont)
	return c
}

func appendLog(s string) {
	if logBuf.Len() > 0 {
		logBuf.WriteString("\r\n")
	}
	logBuf.WriteString(s)
	if hLogBox != 0 {
		setText(hLogBox, logBuf.String())
		scrollToEnd(hLogBox)
		pUpdateWindow.Call(hLogBox) // 立即重绘，便于在耗时操作前看到提示
	}
}

func cleanPath(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, `"`)
	return os.ExpandEnv(s)
}

func resetCombo(items []dirCandidate) {
	dirSources = make(map[string]string)
	pSendMessageW.Call(hCombo, cbResetContent, 0, 0)
	for _, it := range items {
		dirSources[dirKey(it.Path)] = it.Source
		pSendMessageW.Call(hCombo, cbAddString, 0, utf16Ptr(it.Path))
	}
}

func dirKey(dir string) string {
	return strings.ToLower(filepath.Clean(dir))
}

// setComboDir 设置下拉框路径，并在标题旁标注来源。
func setComboDir(dir, source string) {
	if source != "" {
		dirSources[dirKey(dir)] = source
	}
	setText(hCombo, dir)
	updateDirSourceLabel()
}

// updateDirSourceLabel 根据当前路径刷新“安装目录”旁的来源标注。
func updateDirSourceLabel() {
	if hDirSource == 0 {
		return
	}
	dir := selectedDir()
	if dir == "" {
		setText(hDirSource, "（未检测）")
		return
	}
	source := dirSources[dirKey(dir)]
	if source == "" {
		source = "手动输入"
	}
	setText(hDirSource, "（"+source+"）")
}

// selectedDir 返回下拉框当前对应的真实目录。
func selectedDir() string {
	dir := cleanPath(getText(hCombo))
	if dir == "" {
		return ""
	}
	return filepath.Clean(dir)
}

func doInitialDetect() {
	dirs := findCandidateDirs()
	if len(dirs) == 0 {
		setText(hStatusBox, "未能自动检测到 Navicat 安装目录，请点击「浏览...」手动选择。")
		return
	}
	resetCombo(dirs)
	setComboDir(dirs[0].Path, dirs[0].Source)
	if len(dirs) > 1 {
		appendLog(fmt.Sprintf("自动检测到 %d 个候选目录，可在下拉框中选择。", len(dirs)))
	}
	runAnalyze()
}

func onDetect() {
	dirs := findCandidateDirs()
	if len(dirs) == 0 {
		msgBox(hwndMain, "未能自动检测到 Navicat 安装目录，请点击「浏览...」手动选择。", "自动检测", mbIconInfo)
		return
	}
	resetCombo(dirs)
	setComboDir(dirs[0].Path, dirs[0].Source)
	appendLog(fmt.Sprintf("自动检测到 %d 个候选目录。", len(dirs)))
	runAnalyze()
}

func onBrowse() {
	dir := browseForFolder(hwndMain, "请选择 Navicat 安装目录（包含 libcc.dll）")
	if dir == "" {
		return
	}
	setComboDir(dir, "手动选择")
	runAnalyze()
}

// runAnalyze 重新检测当前目录的完成状态并刷新状态区。
func runAnalyze() *installState {
	dir := selectedDir()
	if dir == "" {
		setText(hStatusBox, "请先选择或输入 Navicat 安装目录。")
		return nil
	}
	st := analyzeDir(dir)

	var b strings.Builder
	b.WriteString("安装目录：" + dir + "\r\n")
	if !st.DLLExists {
		b.WriteString("[×] 未找到 libcc.dll，请确认该目录是否正确\r\n")
		if st.BackupExists {
			b.WriteString("[!] 发现备份 libcc.dll.bak，可在执行第 2 步时自动恢复\r\n")
		}
		b.WriteString("\r\n结论：请选择正确的安装目录。")
		setText(hStatusBox, b.String())
		return st
	}
	b.WriteString("[√] 找到 libcc.dll")
	if st.BuildVersion != "" {
		b.WriteString("（" + st.BuildVersion + "）")
	}
	b.WriteString("\r\n")

	if st.BackupExists {
		b.WriteString("[√] 已完成备份（libcc.dll.bak）\r\n")
	} else {
		b.WriteString("[×] 尚未备份，执行第 2 步时自动创建\r\n")
	}

	switch {
	case st.Legacy:
		b.WriteString("[!] 检测到旧方案 .pkey 补丁\r\n")
	case st.Supported && st.Patched:
		b.WriteString(fmt.Sprintf("[√] 已应用单字节补丁（文件偏移 0x%X）\r\n", st.PatchOffset))
	case st.Supported:
		b.WriteString("[×] 尚未应用单字节补丁\r\n")
	default:
		b.WriteString("[!] 未能定位该版本的补丁位置\r\n")
	}

	b.WriteString("\r\n结论：")
	switch {
	case st.Legacy:
		b.WriteString("请删除 libcc.dll，把 libcc.dll.bak 改回 libcc.dll 后重新执行第 2 步。")
	case st.Supported && st.Patched:
		b.WriteString("补丁已应用，可直接执行第 3 步生成激活码。")
	case st.Supported:
		b.WriteString("原版文件可补丁，请执行第 2 步。")
	default:
		b.WriteString("暂不支持该版本，为避免误改未做处理。")
	}
	setText(hStatusBox, b.String())
	return st
}

func onPatch() {
	dir := selectedDir()
	if dir == "" {
		msgBox(hwndMain, "请先选择 Navicat 安装目录。", "提示", mbIconWarn)
		return
	}
	if navicatRunning() {
		appendLog("[中止] 检测到 Navicat 进程仍在运行")
		msgBox(hwndMain, "检测到 Navicat 正在运行，请先完全退出 Navicat 后再执行。", "无法继续", mbIconWarn)
		return
	}
	appendLog("===== 执行：备份并打补丁 =====")
	if err := applyPatch(dir, appendLog); err != nil {
		appendLog("[失败] " + err.Error())
		msgBox(hwndMain, err.Error(), "操作失败", mbIconError)
	} else {
		appendLog("[完成] 步骤处理结束")
	}
	runAnalyze()
}
