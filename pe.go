package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"
)

type peSection struct {
	name             string
	virtualSize      uint32
	virtualAddress   uint32
	sizeOfRawData    uint32
	pointerToRawData uint32
	characteristics  uint32
}

type funcRange struct {
	begin uint32
	end   uint32
}

type peFile struct {
	data               []byte
	peOffset           int
	optOffset          int
	numSections        int
	sectionTableOffset int
	sectionAlignment   uint32
	fileAlignment      uint32
	sizeOfHeaders      uint32
	imageBase          uint64
	sizeOfImage        uint32
	sections           []peSection
	pdata              []funcRange
	pdataLoaded        bool
}

func parsePE(data []byte) (*peFile, error) {
	if len(data) < 0x40 || data[0] != 'M' || data[1] != 'Z' {
		return nil, fmt.Errorf("不是有效的 PE 文件")
	}
	peOff := int(binary.LittleEndian.Uint32(data[0x3c:]))
	if peOff < 0 || peOff+24 > len(data) || string(data[peOff:peOff+4]) != "PE\x00\x00" {
		return nil, fmt.Errorf("不是有效的 PE 文件")
	}
	coff := data[peOff+4:]
	numSections := int(binary.LittleEndian.Uint16(coff[2:]))
	optSize := int(binary.LittleEndian.Uint16(coff[16:]))
	optOff := peOff + 24
	if optOff+optSize > len(data) || optSize < 64 {
		return nil, fmt.Errorf("PE 可选头越界")
	}
	magic := binary.LittleEndian.Uint16(data[optOff:])
	if magic != 0x10b && magic != 0x20b {
		return nil, fmt.Errorf("不支持的 PE 格式")
	}

	pe := &peFile{
		data:               data,
		peOffset:           peOff,
		optOffset:          optOff,
		numSections:        numSections,
		sectionTableOffset: optOff + optSize,
		sectionAlignment:   binary.LittleEndian.Uint32(data[optOff+32:]),
		fileAlignment:      binary.LittleEndian.Uint32(data[optOff+36:]),
		sizeOfHeaders:      binary.LittleEndian.Uint32(data[optOff+60:]),
		sizeOfImage:        binary.LittleEndian.Uint32(data[optOff+56:]),
	}
	if magic == 0x20b {
		pe.imageBase = binary.LittleEndian.Uint64(data[optOff+24:])
	} else {
		pe.imageBase = uint64(binary.LittleEndian.Uint32(data[optOff+28:]))
	}
	if pe.sectionAlignment == 0 || pe.fileAlignment == 0 {
		return nil, fmt.Errorf("PE 对齐参数无效")
	}

	for i := 0; i < numSections; i++ {
		off := pe.sectionTableOffset + i*40
		if off+40 > len(data) {
			return nil, fmt.Errorf("PE 节表越界")
		}
		pe.sections = append(pe.sections, peSection{
			name:             string(bytes.TrimRight(data[off:off+8], "\x00")),
			virtualSize:      binary.LittleEndian.Uint32(data[off+8:]),
			virtualAddress:   binary.LittleEndian.Uint32(data[off+12:]),
			sizeOfRawData:    binary.LittleEndian.Uint32(data[off+16:]),
			pointerToRawData: binary.LittleEndian.Uint32(data[off+20:]),
			characteristics:  binary.LittleEndian.Uint32(data[off+36:]),
		})
	}
	return pe, nil
}

func (pe *peFile) findSection(name string) *peSection {
	for i := range pe.sections {
		if pe.sections[i].name == name {
			return &pe.sections[i]
		}
	}
	return nil
}

// sectionData 返回该节在文件中的实际内容（按 VirtualSize 截断）
func (pe *peFile) sectionData(s *peSection) []byte {
	size := s.virtualSize
	if s.sizeOfRawData < size {
		size = s.sizeOfRawData
	}
	start := int(s.pointerToRawData)
	if start < 0 || start+int(size) > len(pe.data) {
		return nil
	}
	return pe.data[start : start+int(size)]
}

func (pe *peFile) rvaFromOffset(off int) (uint32, bool) {
	if off < 0 || off > len(pe.data) {
		return 0, false
	}
	for i := range pe.sections {
		s := &pe.sections[i]
		if s.sizeOfRawData == 0 {
			continue
		}
		if uint32(off) >= s.pointerToRawData && uint32(off) < s.pointerToRawData+s.sizeOfRawData {
			return s.virtualAddress + uint32(off) - s.pointerToRawData, true
		}
	}
	return 0, false
}

func (pe *peFile) offsetFromRVA(rva uint32) (int, bool) {
	for i := range pe.sections {
		s := &pe.sections[i]
		if s.sizeOfRawData == 0 {
			continue
		}
		if rva >= s.virtualAddress && rva < s.virtualAddress+s.sizeOfRawData {
			return int(s.pointerToRawData + rva - s.virtualAddress), true
		}
	}
	return 0, false
}

// functionRange 通过 .pdata 查询包含该 RVA 的函数范围。
func (pe *peFile) functionRange(rva uint32) (uint32, uint32, bool) {
	if !pe.pdataLoaded {
		pe.pdataLoaded = true
		if sec := pe.findSection(".pdata"); sec != nil {
			d := pe.sectionData(sec)
			for i := 0; i+12 <= len(d); i += 12 {
				b := binary.LittleEndian.Uint32(d[i:])
				e := binary.LittleEndian.Uint32(d[i+4:])
				if b != 0 && e > b {
					pe.pdata = append(pe.pdata, funcRange{begin: b, end: e})
				}
			}
			sort.Slice(pe.pdata, func(i, j int) bool { return pe.pdata[i].begin < pe.pdata[j].begin })
		}
	}
	idx := sort.Search(len(pe.pdata), func(i int) bool { return pe.pdata[i].begin > rva }) - 1
	if idx >= 0 && rva < pe.pdata[idx].end {
		return pe.pdata[idx].begin, pe.pdata[idx].end, true
	}
	return 0, 0, false
}
