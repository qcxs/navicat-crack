package main

import (
	"syscall"
	"unsafe"
)

// ---- Win32 DLL / 函数绑定（纯标准库，无 cgo） ----

var (
	user32   = syscall.NewLazyDLL("user32.dll")
	gdi32    = syscall.NewLazyDLL("gdi32.dll")
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	shell32  = syscall.NewLazyDLL("shell32.dll")
	ole32    = syscall.NewLazyDLL("ole32.dll")
	advapi32 = syscall.NewLazyDLL("advapi32.dll")
)

var (
	pRegisterClassExW     = user32.NewProc("RegisterClassExW")
	pCreateWindowExW      = user32.NewProc("CreateWindowExW")
	pDefWindowProcW       = user32.NewProc("DefWindowProcW")
	pDestroyWindow        = user32.NewProc("DestroyWindow")
	pShowWindow           = user32.NewProc("ShowWindow")
	pUpdateWindow         = user32.NewProc("UpdateWindow")
	pGetMessageW          = user32.NewProc("GetMessageW")
	pTranslateMessage     = user32.NewProc("TranslateMessage")
	pDispatchMessageW     = user32.NewProc("DispatchMessageW")
	pPostQuitMessage      = user32.NewProc("PostQuitMessage")
	pSendMessageW         = user32.NewProc("SendMessageW")
	pSetWindowTextW       = user32.NewProc("SetWindowTextW")
	pGetWindowTextW       = user32.NewProc("GetWindowTextW")
	pGetWindowTextLengthW = user32.NewProc("GetWindowTextLengthW")
	pEnableWindow         = user32.NewProc("EnableWindow")
	pMessageBoxW          = user32.NewProc("MessageBoxW")
	pLoadCursorW          = user32.NewProc("LoadCursorW")
	pSetProcessDPIAware   = user32.NewProc("SetProcessDPIAware")
	pGetDC                = user32.NewProc("GetDC")
	pReleaseDC            = user32.NewProc("ReleaseDC")
	pAdjustWindowRect     = user32.NewProc("AdjustWindowRect")
	pGetSystemMetrics     = user32.NewProc("GetSystemMetrics")
	pSetForegroundWindow  = user32.NewProc("SetForegroundWindow")
	pOpenClipboard        = user32.NewProc("OpenClipboard")
	pEmptyClipboard       = user32.NewProc("EmptyClipboard")
	pSetClipboardData     = user32.NewProc("SetClipboardData")
	pCloseClipboard       = user32.NewProc("CloseClipboard")
)

var (
	pCreateFontW   = gdi32.NewProc("CreateFontW")
	pGetDeviceCaps = gdi32.NewProc("GetDeviceCaps")
)

var (
	pGetModuleHandleW  = kernel32.NewProc("GetModuleHandleW")
	pGlobalAlloc       = kernel32.NewProc("GlobalAlloc")
	pGlobalLock        = kernel32.NewProc("GlobalLock")
	pGlobalUnlock      = kernel32.NewProc("GlobalUnlock")
	pGlobalFree        = kernel32.NewProc("GlobalFree")
	pRtlMoveMemory     = kernel32.NewProc("RtlMoveMemory")
	pCloseHandle       = kernel32.NewProc("CloseHandle")
	pGetCurrentProcess = kernel32.NewProc("GetCurrentProcess")
)

var (
	pOpenProcessToken    = advapi32.NewProc("OpenProcessToken")
	pGetTokenInformation = advapi32.NewProc("GetTokenInformation")
)

var (
	pShellExecuteW = shell32.NewProc("ShellExecuteW")
)

var (
	pCoInitializeEx = ole32.NewProc("CoInitializeEx")
	pCoUninitialize = ole32.NewProc("CoUninitialize")
	pCoTaskMemFree  = ole32.NewProc("CoTaskMemFree")
)

// ---- 常量 ----

const (
	wsChild        = 0x40000000
	wsVisible      = 0x10000000
	wsTabStop      = 0x00010000
	wsBorder       = 0x00800000
	wsVScroll      = 0x00200000
	wsCaption      = 0x00C00000
	wsSysMenu      = 0x00080000
	wsMinimizeBox  = 0x00020000
	wsClipChildren = 0x02000000

	esMultiline   = 0x0004
	esAutoVScroll = 0x0040
	esReadOnly    = 0x0800

	cbsDropDown    = 0x0002
	cbsAutoHScroll = 0x0040
	cbsHasStrings  = 0x0200

	cbAddString       = 0x0143
	cbResetContent    = 0x014B
	cbSetCurSel       = 0x014E
	cbSetDroppedWidth = 0x0160

	wmCreate  = 0x0001
	wmDestroy = 0x0002
	wmClose   = 0x0010
	wmCommand = 0x0111
	wmSetFont = 0x0030

	cbnSelChange  = 1
	cbnEditChange = 5

	emSetSel      = 0x00B1
	emScrollCaret = 0x00B7

	swShow = 5

	mbIconError = 0x00000010
	mbIconWarn  = 0x00000030
	mbIconInfo  = 0x00000040

	logPixelsX = 88
	smCxScreen = 0
	smCyScreen = 1

	gmemMoveable  = 0x0042
	cfUnicodeText = 13
)

// ---- 结构体 ----

type wndClassEx struct {
	cbSize        uint32
	style         uint32
	lpfnWndProc   uintptr
	cbClsExtra    int32
	cbWndExtra    int32
	hInstance     syscall.Handle
	hIcon         syscall.Handle
	hCursor       syscall.Handle
	hbrBackground syscall.Handle
	lpszMenuName  *uint16
	lpszClassName *uint16
	hIconSm       syscall.Handle
}

type msgT struct {
	hwnd    uintptr
	message uint32
	wParam  uintptr
	lParam  uintptr
	time    uint32
	pt      pointT
}

type pointT struct{ x, y int32 }

type rectT struct{ left, top, right, bottom int32 }

// ---- 辅助函数 ----

// classNameKeep 持有一份已注册窗口类名的引用，确保其内存不被回收。
var classNameKeep []*uint16

func utf16Str(s string) *uint16 {
	p, err := syscall.UTF16PtrFromString(s)
	if err != nil {
		return nil
	}
	return p
}

func utf16Ptr(s string) uintptr {
	return uintptr(unsafe.Pointer(utf16Str(s)))
}

func getModuleHandle() syscall.Handle {
	h, _, _ := pGetModuleHandleW.Call(0)
	return syscall.Handle(h)
}

func createWindow(class, text string, style uint32, x, y, w, h int32, parent, id uintptr) uintptr {
	cp := utf16Ptr(class)
	tp := utf16Ptr(text)
	ret, _, _ := pCreateWindowExW.Call(0, cp, tp, uintptr(style),
		uintptr(x), uintptr(y), uintptr(w), uintptr(h),
		parent, id, uintptr(getModuleHandle()), 0)
	return ret
}

func registerClass(name string, proc uintptr, brush uint32) error {
	className := utf16Str(name)
	classNameKeep = append(classNameKeep, className) // 防止类名被 GC 回收
	wc := wndClassEx{
		cbSize:        uint32(unsafe.Sizeof(wndClassEx{})),
		style:         0x0001 | 0x0002, // CS_VREDRAW | CS_HREDRAW
		lpfnWndProc:   proc,
		hInstance:     getModuleHandle(),
		hCursor:       loadCursor(32512), // IDC_ARROW
		hbrBackground: syscall.Handle(brush),
		lpszClassName: className,
	}
	atom, _, err := pRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))
	if atom == 0 {
		return err
	}
	return nil
}

func loadCursor(id uint32) syscall.Handle {
	r, _, _ := pLoadCursorW.Call(0, uintptr(id))
	return syscall.Handle(r)
}

func createFont(face string, pt, weight int32) uintptr {
	height := -int32(float64(pt)*96.0/72.0*dpiScale + 0.5)
	fp := utf16Ptr(face)
	r, _, _ := pCreateFontW.Call(
		uintptr(height), 0, 0, 0, uintptr(weight), 0, 0, 0,
		1, // DEFAULT_CHARSET
		0, 0,
		5, // CLEARTYPE_QUALITY
		0, fp)
	return r
}

func setWindowFont(h, font uintptr) {
	if h == 0 || font == 0 {
		return
	}
	pSendMessageW.Call(h, wmSetFont, font, 1)
}

func setText(h uintptr, s string) {
	if h == 0 {
		return
	}
	pSetWindowTextW.Call(h, utf16Ptr(s))
}

func getText(h uintptr) string {
	n, _, _ := pGetWindowTextLengthW.Call(h)
	if n == 0 {
		return ""
	}
	buf := make([]uint16, n+1)
	pGetWindowTextW.Call(h, uintptr(unsafe.Pointer(&buf[0])), n+1)
	return syscall.UTF16ToString(buf)
}

func scrollToEnd(h uintptr) {
	n, _, _ := pGetWindowTextLengthW.Call(h)
	pSendMessageW.Call(h, emSetSel, n, n)
	pSendMessageW.Call(h, emScrollCaret, 0, 0)
}

func msgBox(owner uintptr, text, title string, flags uint32) {
	tp := utf16Ptr(text)
	cp := utf16Ptr(title)
	pMessageBoxW.Call(owner, tp, cp, uintptr(flags))
}

func adjustSize(clientW, clientH int32, style uint32) (int32, int32) {
	r := rectT{0, 0, clientW, clientH}
	pAdjustWindowRect.Call(uintptr(unsafe.Pointer(&r)), uintptr(style), 0)
	return r.right - r.left, r.bottom - r.top
}

func centeredPos(w, h int32) (int32, int32) {
	sw, _, _ := pGetSystemMetrics.Call(smCxScreen)
	sh, _, _ := pGetSystemMetrics.Call(smCyScreen)
	x := (int32(sw) - w) / 2
	y := (int32(sh) - h) / 2
	if x < 0 {
		x = 0
	}
	if y < 0 {
		y = 0
	}
	return x, y
}

func runMessageLoop() {
	var m msgT
	for {
		r, _, _ := pGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 {
			return
		}
		pTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		pDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
	}
}

func shellOpen(path, dir string) error {
	op := utf16Ptr("open")
	fp := utf16Ptr(path)
	dp := utf16Ptr(dir)
	r, _, err := pShellExecuteW.Call(0, op, fp, 0, dp, swShow)
	if r <= 32 {
		return err
	}
	return nil
}

// isAdmin 通过当前进程令牌判断是否以管理员身份运行。
func isAdmin() bool {
	proc, _, _ := pGetCurrentProcess.Call()
	var token syscall.Handle
	const tokenQuery = 0x0008
	ok, _, _ := pOpenProcessToken.Call(proc, tokenQuery, uintptr(unsafe.Pointer(&token)))
	if ok == 0 {
		return false
	}
	defer pCloseHandle.Call(uintptr(token))

	var elevation struct{ isElevated uint32 }
	var size uint32
	const tokenElevation = 20
	ok, _, _ = pGetTokenInformation.Call(uintptr(token), tokenElevation,
		uintptr(unsafe.Pointer(&elevation)), unsafe.Sizeof(elevation), uintptr(unsafe.Pointer(&size)))
	if ok == 0 {
		return false
	}
	return elevation.isElevated != 0
}

func setClipboard(owner uintptr, text string) bool {
	u, err := syscall.UTF16FromString(text)
	if err != nil {
		return false
	}
	size := uintptr(len(u) * 2)
	h, _, _ := pGlobalAlloc.Call(gmemMoveable, size)
	if h == 0 {
		return false
	}
	ptr, _, _ := pGlobalLock.Call(h)
	if ptr == 0 {
		pGlobalFree.Call(h)
		return false
	}
	pRtlMoveMemory.Call(ptr, uintptr(unsafe.Pointer(&u[0])), size)
	pGlobalUnlock.Call(h)

	if ok, _, _ := pOpenClipboard.Call(owner); ok == 0 {
		pGlobalFree.Call(h)
		return false
	}
	pEmptyClipboard.Call()
	pSetClipboardData.Call(cfUnicodeText, h)
	pCloseClipboard.Call()
	return true
}
