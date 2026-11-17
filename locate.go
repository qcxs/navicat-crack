package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

const rttiName = ".?AVCSRegistrationInfoFetcher_WIN@@"

// 公钥构造函数中追加字符的指令形态：mov dl, imm ; mov rcx, r15 ; call
var (
	appendCallTail = []byte{0x49, 0x8B, 0xCF, 0xE8} // mov rcx,r15; call rel32
	appendR        = []byte{0xB2, 0x52, 0x49, 0x8B, 0xCF, 0xE8}
)

type patchSite struct {
	FileOffset int
	RVA        uint32
	Method     string
	Version    string
}

type knownBuild struct {
	sha256  string
	offset  int
	version string
}

var knownBuilds = []knownBuild{
	// 17.3.6 原版 / 已应用 S->T
	{"fda4d35c0d5d6bac0e39464b71bb29f518fe299502329678e036b7363c135c59", 0x21626C5, "17.3.6"},
	{"2495c9ab7834a2833d4c497fc656579423c2caff23ce463330d27e327b26b684", 0x21626C5, "17.3.6"},
	// 18.0.6 原版 / 已应用 S->T（数据来自公开分析）
	{"d34a8194da9f5a5459ab25a9323df7ec787cdddc90ad58b33bc62d0ca84a7207", 0x27EC415, "18.0.6"},
	{"bfae31129cfc21d84295f667a7efe85ad96d5575211664105b969b228ef192a1", 0x27EC415, "18.0.6"},
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	const hexdigits = "0123456789abcdef"
	out := make([]byte, len(sum)*2)
	for i, b := range sum {
		out[i*2] = hexdigits[b>>4]
		out[i*2+1] = hexdigits[b&15]
	}
	return string(out)
}

// locatePatchSite 定位公钥下标 364 的单字节补丁位置。
// 优先匹配已知版本的完整 SHA-256，失败后使用 RTTI + 虚表 + 特征码自动定位。
func locatePatchSite(data []byte) (*patchSite, error) {
	hash := sha256Hex(data)
	var known *knownBuild
	for i := range knownBuilds {
		if knownBuilds[i].sha256 == hash {
			known = &knownBuilds[i]
			break
		}
	}

	pe, peErr := parsePE(data)
	if known != nil && peErr == nil {
		if siteBytesOK(data, known.offset) {
			rva, _ := pe.rvaFromOffset(known.offset)
			return &patchSite{FileOffset: known.offset, RVA: rva, Method: "known-hash", Version: known.version}, nil
		}
	}
	if peErr != nil {
		return nil, peErr
	}
	return autoLocate(data, pe)
}

func siteBytesOK(data []byte, off int) bool {
	if off <= 0 || off+5 > len(data) {
		return false
	}
	if data[off] != 0x53 && data[off] != 0x54 {
		return false
	}
	if data[off-1] != 0xB2 {
		return false
	}
	return bytes.Equal(data[off+1:off+5], appendCallTail)
}

func autoLocate(data []byte, pe *peFile) (*patchSite, error) {
	nameOff := bytes.Index(data, []byte(rttiName))
	if nameOff < 0 {
		return nil, fmt.Errorf("未找到注册信息类的 RTTI 名称，暂不支持该版本")
	}
	nameRVA, ok := pe.rvaFromOffset(nameOff)
	if !ok || nameRVA < 16 {
		return nil, fmt.Errorf("RTTI 名称地址无效")
	}
	typeDescRVA := nameRVA - 16
	pat := le32(typeDescRVA)

	for pos := 0; pos < len(data); {
		i := bytes.Index(data[pos:], pat)
		if i < 0 {
			break
		}
		i += pos
		colOff := i - 12
		if colOff >= 0 && binary.LittleEndian.Uint32(data[colOff:]) == 1 {
			if site := siteFromLocator(data, pe, colOff); site != nil {
				return site, nil
			}
		}
		pos = i + 1
	}
	return nil, fmt.Errorf("未能定位公钥构造函数，暂不支持该版本")
}

func siteFromLocator(data []byte, pe *peFile, colOff int) *patchSite {
	colRVA, ok := pe.rvaFromOffset(colOff)
	if !ok {
		return nil
	}
	colVA := pe.imageBase + uint64(colRVA)
	pat := le64(colVA)

	for pos := 0; pos < len(data); {
		i := bytes.Index(data[pos:], pat)
		if i < 0 {
			return nil
		}
		i += pos
		vtOff := i + 8
		pos = i + 1
		if vtOff+0x38 > len(data) {
			continue
		}
		slot := binary.LittleEndian.Uint64(data[vtOff+0x30:])
		if slot <= pe.imageBase {
			continue
		}
		fnRVA := uint32(slot - pe.imageBase)
		start, end, ok := pe.functionRange(fnRVA)
		if !ok {
			continue
		}
		if site := findAppendSite(data, pe, start, end); site != nil {
			return site
		}
	}
	return nil
}

// findAppendSite 在公钥构造函数内查找“先追加 R、再追加 S/T”的位置。
func findAppendSite(data []byte, pe *peFile, start, end uint32) *patchSite {
	startOff, ok1 := pe.offsetFromRVA(start)
	endOff, ok2 := pe.offsetFromRVA(end - 1)
	if !ok1 || !ok2 {
		return nil
	}
	endOff++
	if endOff > len(data) {
		endOff = len(data)
	}

	var candidates []int
	for i := startOff; i+5 < endOff; i++ {
		if data[i] != 0xB2 || (data[i+1] != 0x53 && data[i+1] != 0x54) {
			continue
		}
		if !bytes.Equal(data[i+2:i+6], appendCallTail) {
			continue
		}
		lower := i - 40
		if lower < startOff {
			lower = startOff
		}
		if !bytes.Contains(data[lower:i], appendR) {
			continue
		}
		if !tailContextOK(data, i, startOff) {
			continue
		}
		candidates = append(candidates, i+1)
	}
	if len(candidates) != 1 {
		return nil
	}
	off := candidates[0]
	rva, ok := pe.rvaFromOffset(off)
	if !ok {
		return nil
	}
	return &patchSite{FileOffset: off, RVA: rva, Method: "auto", Version: ""}
}

// tailContextOK 检查目标附近是否存在 "Wa"(0x6157) 立即数或下标 0xC6 自引用，
// 用于确认找到的是同一把内嵌公钥的尾部。
func tailContextOK(data []byte, appendOff, lowerBound int) bool {
	lower := appendOff - 320
	if lower < lowerBound {
		lower = lowerBound
	}
	if lower < 0 {
		lower = 0
	}
	window := data[lower:appendOff]
	for i := 0; i+6 < len(window); i++ {
		// mov word ptr [rbp+disp8], 6157h  -> "Wa"
		if window[i] == 0x66 && window[i+1] == 0xC7 && window[i+4] == 0x57 && window[i+5] == 0x61 {
			return true
		}
	}
	// mov edx, 0xC6 ; ... ; call operator[]（字符自引用）
	if bytes.Contains(window, []byte{0xBA, 0xC6, 0x00, 0x00, 0x00}) {
		return true
	}
	return false
}

func le32(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}

func le64(v uint64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, v)
	return b
}
