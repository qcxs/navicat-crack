package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

var (
	hActReq      uintptr
	hActUser     uintptr
	hActOrg      uintptr
	hActOut      uintptr
	hActKeyLabel uintptr
)

// buildActivateSection 在主窗口内绘制第 3 步（离线激活）所需控件。
func buildActivateSection(hwnd uintptr) {
	hActKeyLabel = mkLabel(hwnd, "离线激活密钥："+currentOfflineKey, 16, 234, 300, 20)
	setWindowFont(hActKeyLabel, uiFontBold)
	mkButton(hwnd, "刷新密钥", idActRefresh, 324, 232, 96, 28)
	mkButton(hwnd, "复制密钥", idActCopyKey, 428, 232, 96, 28)

	mkLabel(hwnd, "离线激活请求码（从 Navicat 激活窗口复制粘贴）：", 16, 266, 520, 18)
	hActReq = createWindow("EDIT", "", wsChild|wsVisible|wsBorder|wsVScroll|
		esMultiline|esAutoVScroll, sc(16), sc(286), sc(688), sc(64), hwnd, 0)
	setWindowFont(hActReq, uiFont)

	mkLabel(hwnd, "用户名", 16, 358, 56, 20)
	hActUser = createWindow("EDIT", "Admin", wsChild|wsVisible|wsBorder|wsTabStop,
		sc(76), sc(356), sc(180), sc(26), hwnd, 0)
	setWindowFont(hActUser, uiFont)

	mkLabel(hwnd, "组织名", 268, 358, 56, 20)
	hActOrg = createWindow("EDIT", "Personal", wsChild|wsVisible|wsBorder|wsTabStop,
		sc(328), sc(356), sc(200), sc(26), hwnd, 0)
	setWindowFont(hActOrg, uiFont)

	mkButton(hwnd, "生成激活码", idActGen, 552, 354, 152, 28)

	mkLabel(hwnd, "激活码结果", 16, 392, 200, 18)
	mkButton(hwnd, "复制激活码", idActCopy, 594, 388, 110, 28)
	hActOut = createWindow("EDIT", "", wsChild|wsVisible|wsBorder|wsVScroll|
		esMultiline|esAutoVScroll|esReadOnly, sc(16), sc(420), sc(688), sc(64), hwnd, 0)
	setWindowFont(hActOut, uiFont)
}

func onCopyOfflineKey(owner uintptr) {
	if setClipboard(owner, currentOfflineKey) {
		msgBox(owner, "离线激活密钥已复制到剪贴板：\n"+currentOfflineKey, "提示", mbIconInfo)
	}
}

// onRefreshOfflineKey 按帖子中的短序列号算法生成一个新的离线激活密钥。
func onRefreshOfflineKey(owner uintptr) {
	key, err := generateOfflineKey()
	if err != nil {
		msgBox(owner, "生成离线激活密钥失败："+err.Error(), "错误", mbIconError)
		return
	}
	currentOfflineKey = key
	setText(hActKeyLabel, "离线激活密钥："+currentOfflineKey)
	setText(hActReq, "")
	setText(hActOut, "")
	appendLog("已生成新的离线激活密钥：" + currentOfflineKey)
	appendLog("请在 Navicat 中使用新密钥重新进行离线激活，再获取请求码。")
	if setClipboard(owner, currentOfflineKey) {
		appendLog("[完成] 新密钥已复制到剪贴板")
	}
}

func onCopyActivation(owner uintptr) {
	txt := strings.TrimSpace(getText(hActOut))
	if txt == "" {
		msgBox(owner, "尚未生成激活码，请先粘贴请求码并点击「生成激活码」。", "提示", mbIconWarn)
		return
	}
	if setClipboard(owner, txt) {
		msgBox(owner, "激活码已复制到剪贴板。", "提示", mbIconInfo)
	}
}

func onGenerateActivation(owner uintptr) {
	dir := selectedDir()
	if dir == "" {
		msgBox(owner, "请先选择 Navicat 安装目录。", "提示", mbIconWarn)
		return
	}
	st := analyzeDir(dir)
	switch {
	case !st.DLLExists:
		msgBox(owner, "该目录中没有 libcc.dll，请确认安装目录。", "无法激活", mbIconWarn)
		return
	case st.Legacy:
		msgBox(owner, "检测到旧方案 .pkey 补丁，请恢复原版文件后重新执行第 2 步。", "无法激活", mbIconWarn)
		return
	case !st.Supported:
		msgBox(owner, "未能定位该版本的补丁位置，暂不支持。", "无法激活", mbIconWarn)
		return
	case !st.Patched:
		msgBox(owner, "libcc.dll 尚未打补丁，请先执行第 2 步。", "无法激活", mbIconWarn)
		return
	}

	req := strings.TrimSpace(getText(hActReq))
	if req == "" {
		msgBox(owner, "请先粘贴离线激活请求码。", "提示", mbIconWarn)
		return
	}

	plain, err := decryptRequest(req)
	if err != nil {
		msgBox(owner, "解密失败，请确认粘贴的是完整的离线激活请求码。\n\n"+err.Error(), "错误", mbIconError)
		return
	}

	var data map[string]any
	dec := json.NewDecoder(bytes.NewReader(plain))
	dec.UseNumber()
	if err := dec.Decode(&data); err != nil {
		msgBox(owner, "解析注册信息失败："+err.Error(), "错误", mbIconError)
		return
	}

	data["N"] = strings.TrimSpace(getText(hActUser))
	data["O"] = strings.TrimSpace(getText(hActOrg))
	data["T"] = time.Now().Unix()

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(data); err != nil {
		msgBox(owner, "序列化注册信息失败："+err.Error(), "错误", mbIconError)
		return
	}
	msg := bytes.TrimRight(buf.Bytes(), "\n")

	reg, err := signActivation(msg)
	if err != nil {
		msgBox(owner, "生成激活码失败："+err.Error(), "错误", mbIconError)
		return
	}
	setText(hActOut, reg)
	scrollToEnd(hActOut)
}

func launchNavicat(owner uintptr) {
	dir := selectedDir()
	if dir == "" {
		msgBox(owner, "请先选择 Navicat 安装目录。", "提示", mbIconWarn)
		return
	}
	exe := filepath.Join(dir, "navicat.exe")
	if !fileExists(exe) {
		msgBox(owner, "安装目录中没有找到 navicat.exe。", "提示", mbIconWarn)
		return
	}
	if err := shellOpen(exe, dir); err != nil {
		msgBox(owner, fmt.Sprintf("启动 Navicat 失败：%v", err), "错误", mbIconError)
	}
}
