package main

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

const (
	clsctxInprocServer = 1
	fosPickFolders     = 0x00000020
	fosForceFileSystem = 0x00000040
	sigdnFileSysPath   = 0x80058000
)

var (
	clsidFileOpenDialog = syscall.GUID{Data1: 0xDC1C5A9C, Data2: 0xE88A, Data3: 0x4DDE,
		Data4: [8]byte{0xA5, 0xA1, 0x60, 0xF8, 0x2A, 0x20, 0xAE, 0xF7}}
	iidIFileOpenDialog = syscall.GUID{Data1: 0xD57C7288, Data2: 0xD4AD, Data3: 0x4768,
		Data4: [8]byte{0xBE, 0x02, 0x9D, 0x96, 0x95, 0x32, 0xD9, 0x60}}
	clsidShellLink = syscall.GUID{Data1: 0x00021401, Data2: 0x0000, Data3: 0x0000,
		Data4: [8]byte{0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}}
	iidIShellLinkW = syscall.GUID{Data1: 0x000214F9, Data2: 0x0000, Data3: 0x0000,
		Data4: [8]byte{0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}}
	iidIPersistFile = syscall.GUID{Data1: 0x0000010B, Data2: 0x0000, Data3: 0x0000,
		Data4: [8]byte{0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}}

	pCoCreateInstance = ole32.NewProc("CoCreateInstance")
)

func comCall(obj unsafe.Pointer, index int, args ...uintptr) uintptr {
	vtbl := *(*unsafe.Pointer)(obj)
	fn := *(*uintptr)(unsafe.Add(vtbl, uintptr(index)*unsafe.Sizeof(uintptr(0))))
	r, _, _ := syscall.SyscallN(fn, append([]uintptr{uintptr(obj)}, args...)...)
	return r
}

func comRelease(obj unsafe.Pointer) {
	if obj != nil {
		comCall(obj, 2)
	}
}

func coCreate(clsid, iid *syscall.GUID, out unsafe.Pointer) int32 {
	r, _, _ := pCoCreateInstance.Call(
		uintptr(unsafe.Pointer(clsid)), 0, clsctxInprocServer,
		uintptr(unsafe.Pointer(iid)), uintptr(out))
	return int32(r)
}

// browseForFolder 使用 IFileOpenDialog（资源管理器风格）选择文件夹。
func browseForFolder(owner uintptr, title string) string {
	var dlg unsafe.Pointer
	if hr := coCreate(&clsidFileOpenDialog, &iidIFileOpenDialog, unsafe.Pointer(&dlg)); hr < 0 || dlg == nil {
		return ""
	}
	defer comRelease(dlg)

	var options uint32
	if hr := int32(comCall(dlg, 10, uintptr(unsafe.Pointer(&options)))); hr < 0 {
		return ""
	}
	options |= fosPickFolders | fosForceFileSystem
	comCall(dlg, 9, uintptr(options)) // SetOptions
	if t := utf16Str(title); t != nil {
		comCall(dlg, 17, uintptr(unsafe.Pointer(t))) // SetTitle
	}
	if hr := int32(comCall(dlg, 3, owner)); hr < 0 { // Show
		return ""
	}

	var item unsafe.Pointer
	if hr := int32(comCall(dlg, 20, uintptr(unsafe.Pointer(&item)))); hr < 0 || item == nil {
		return ""
	}
	defer comRelease(item)

	var psz *uint16
	if hr := int32(comCall(item, 5, uintptr(sigdnFileSysPath), uintptr(unsafe.Pointer(&psz)))); hr < 0 || psz == nil {
		return ""
	}
	defer pCoTaskMemFree.Call(uintptr(unsafe.Pointer(psz)))
	return utf16ZToString(psz)
}

// utf16ZToString 读取以 NUL 结尾的 UTF-16 字符串。
func utf16ZToString(p *uint16) string {
	if p == nil {
		return ""
	}
	var chars []uint16
	for q := unsafe.Pointer(p); *(*uint16)(q) != 0; q = unsafe.Add(q, unsafe.Sizeof(uint16(0))) {
		chars = append(chars, *(*uint16)(q))
	}
	return syscall.UTF16ToString(chars)
}

// resolveShortcut 解析 .lnk 快捷方式的目标路径。
func resolveShortcut(path string) (string, bool) {
	var link unsafe.Pointer
	if hr := coCreate(&clsidShellLink, &iidIShellLinkW, unsafe.Pointer(&link)); hr < 0 || link == nil {
		return "", false
	}
	defer comRelease(link)

	var persist unsafe.Pointer
	if hr := int32(comCall(link, 0, uintptr(unsafe.Pointer(&iidIPersistFile)),
		uintptr(unsafe.Pointer(&persist)))); hr < 0 || persist == nil {
		return "", false
	}
	defer comRelease(persist)

	p := utf16Str(path)
	if p == nil {
		return "", false
	}
	if hr := int32(comCall(persist, 5, uintptr(unsafe.Pointer(p)), 0)); hr < 0 {
		return "", false
	}

	buf := make([]uint16, syscall.MAX_PATH*2)
	if hr := int32(comCall(link, 3, uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)), 0, 0)); hr < 0 {
		return "", false
	}
	target := syscall.UTF16ToString(buf)
	return target, target != ""
}

// shortcutCandidates 从桌面和开始菜单的快捷方式反查安装目录。
func shortcutCandidates() []dirCandidate {
	type root struct {
		path   string
		source string
	}
	var roots []root
	if p := os.Getenv("USERPROFILE"); p != "" {
		roots = append(roots, root{filepath.Join(p, "Desktop"), "桌面快捷方式"})
	}
	if p := os.Getenv("PUBLIC"); p != "" {
		roots = append(roots, root{filepath.Join(p, "Desktop"), "桌面快捷方式"})
	}
	if p := os.Getenv("APPDATA"); p != "" {
		roots = append(roots, root{filepath.Join(p, "Microsoft", "Windows", "Start Menu", "Programs"), "开始菜单快捷方式"})
	}
	if p := os.Getenv("ProgramData"); p != "" {
		roots = append(roots, root{filepath.Join(p, "Microsoft", "Windows", "Start Menu", "Programs"), "开始菜单快捷方式"})
	}

	var out []dirCandidate
	for _, r := range roots {
		_ = filepath.Walk(r.path, func(path string, info os.FileInfo, err error) error {
			if err != nil || info == nil || info.IsDir() {
				return nil
			}
			if !strings.EqualFold(filepath.Ext(path), ".lnk") {
				return nil
			}
			if !strings.Contains(strings.ToLower(info.Name()), "navicat") {
				return nil
			}
			target, ok := resolveShortcut(path)
			if !ok {
				return nil
			}
			st, err := os.Stat(target)
			if err != nil {
				return nil
			}
			dir := target
			if !st.IsDir() {
				dir = filepath.Dir(target)
			}
			out = append(out, dirCandidate{Path: dir, Source: r.source})
			return nil
		})
	}
	return out
}
