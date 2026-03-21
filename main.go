package main

// Test items: https://drive.google.com/drive/folders/1_TtBnqGhBP7Ss-FFxzW18fjrFbFRl86x

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

type FirmwareFile struct {
	//StartHeader    *StartHeader
	//FirmwareHeader *FirmwareHeader

	Live    *FirmwareSection
	Upgrade *FirmwareSection
	MBR     []byte

	MainFS *SquashFS
}

type FirmwareSection struct {
	Header *StartHeader
	Meta   *MetaDataBlock
}

type StartHeader struct {
	Magic            uint32   // 0x00, 4 bytes
	Signature        [48]byte // 0x04, 48 bytes
	Padding          uint32   // 0x34, 4 bytes (00 00 00 00)
	Anchor           [8]byte  // 0x38, 8 bytes (DE AD BE EF DE AD BE EF)
	FirmwareHeader   uint32   // 0x40, 4 bytes (00 00 04 0C)
	UnknownB         uint32   // 0x44, 4 bytes (00 00 75 30)
	Flags            uint32   // 0x48, 4 bytes (00 00 00 00)
	FileSystemHeader uint32   // 0x4C, 4 bytes (02 7D 88 F9)
	FileEnd          uint32   // 0x50, 4 bytes, FileEnd for the Start Header
	NullPad          [56]byte // 0x54, 56 bytes
}

type TLV struct {
	Tag    uint32
	Length uint32
	Value  []byte
}

type MetaDataBlock struct {
	BlockType uint32
	TLVs      []TLV
	Start     uint32
	End       uint32

	// Compact TLV block fields
	IsCompact bool
	DataA     []byte

	SubBlocks []*MetaDataBlock
}

type FirmwareHeader struct {
	Magic       uint32
	Signature   [48]byte
	Padding     uint32
	Anchor      [8]byte // 0x38, 8 bytes (DE AD BE EF DE AD BE EF)
	UnknownA    uint32
	UnknownB    uint32
	UnknownC    uint32
	KernelStart uint32
	UnknownE    uint32
	NullPad     [56]byte
}

type MappedFile struct {
	data   []byte
	handle windows.Handle
	mapObj windows.Handle
}

func openMapped(path string) (*MappedFile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	size, err := f.Seek(0, 2)
	if err != nil {
		return nil, err
	}
	if size == 0 {
		return nil, fmt.Errorf("file is empty: %s", path)
	}

	handle := windows.Handle(f.Fd())

	mapObj, err := windows.CreateFileMapping(
		handle,
		nil,
		windows.PAGE_READONLY,
		0, 0,
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("CreateFileMapping: %w", err)
	}

	addr, err := windows.MapViewOfFile(
		mapObj,
		windows.FILE_MAP_READ,
		0, 0,
		0,
	)
	if err != nil {
		windows.CloseHandle(mapObj)
		return nil, fmt.Errorf("MapViewOfFile: %w", err)
	}

	data := unsafe.Slice((*byte)(unsafe.Pointer(addr)), size)

	return &MappedFile{
		data:   data,
		handle: windows.Handle(addr),
		mapObj: mapObj,
	}, nil
}

func (m *MappedFile) Close() error {
	err1 := windows.UnmapViewOfFile(uintptr(m.handle))
	err2 := windows.CloseHandle(m.mapObj)
	m.data = nil
	if err1 != nil {
		return err1
	}
	return err2
}

func (m *MappedFile) Data() []byte {
	return m.data
}

func fill[structure any](data []byte, offset uint64, order binary.ByteOrder) *structure {
	r := bytes.NewReader(data[offset:])
	var v structure
	_ = binary.Read(r, order, &v)
	return &v
}

func parseMetaData(start uint32, end uint32, data []byte) *MetaDataBlock {
	block := MetaDataBlock{
		Start:     start,
		End:       start,
		BlockType: binary.BigEndian.Uint32(data[start : start+0x4]),
		TLVs:      []TLV{},
		SubBlocks: []*MetaDataBlock{},
	}
	block.End += 0x4

	for block.End < end {
		tag := binary.BigEndian.Uint32(data[block.End : block.End+0x4])
		tlvLen := binary.BigEndian.Uint32(data[block.End+0x4 : block.End+0x8])
		block.End += 0x8

		tlv := TLV{
			Tag:    tag,
			Length: tlvLen,
			Value:  data[block.End : block.End+tlvLen],
		}
		block.TLVs = append(block.TLVs, tlv)
		block.End += tlvLen

		// align if not multiple of 4
		if block.End%0x4 != 0 {
			block.End += 0x4 - block.End%0x4
		}

		if bytes.Equal(data[block.End:block.End+0x4], []byte{0x00, 0x00, 0x00, 0x0C}) {
			break
		}
	}

	compactBlock := MetaDataBlock{
		Start:     block.End,
		End:       block.End,
		BlockType: binary.BigEndian.Uint32(data[block.End : block.End+0x4]),
		IsCompact: true,
		TLVs:      []TLV{},
	}
	compactBlock.End += 0x4

	compactBlock.DataA = data[compactBlock.End : compactBlock.End+0x13]
	compactBlock.End += 0x13

	var compactBlockEnd = []byte{0x0C, 0x00, 0x01, 0x41, 0xEB}

	for compactBlock.End < end {
		tag := uint32(data[compactBlock.End])
		tlvLen := uint32(binary.BigEndian.Uint16(data[compactBlock.End+0x1 : compactBlock.End+0x3]))
		compactBlock.End += 0x3

		tlv := TLV{
			Tag:    tag,
			Length: tlvLen,
			Value:  data[compactBlock.End : compactBlock.End+tlvLen],
		}

		compactBlock.TLVs = append(compactBlock.TLVs, tlv)
		compactBlock.End += tlvLen

		if bytes.Equal(data[compactBlock.End:compactBlock.End+0x5], compactBlockEnd) {
			// this is a correction. I don't know what these 5 bytes do, but they are
			// consistent and always before the firmware so...
			compactBlock.End += 0x5
			break
		}
	}

	block.SubBlocks = append(block.SubBlocks, &compactBlock)
	block.End = compactBlock.End

	return &block
}

func printFirmwareFile(file *FirmwareFile) {
	fmt.Println("\n=== Firmware File ===")

	fmt.Println("\n--- Start Header ---")
	fmt.Printf("  Magic:             0x%08X\n", file.Live.Header.Magic)
	fmt.Printf("  Firmware Header:   0x%08X\n", file.Live.Header.FirmwareHeader)
	fmt.Printf("  UnknownB:          0x%08X\n", file.Live.Header.UnknownB)
	fmt.Printf("  Flags:             0x%08X\n", file.Live.Header.Flags)
	fmt.Printf("  File System:       0x%08X\n", file.Live.Header.FileSystemHeader)
	fmt.Printf("  File End:          0x%08X\n", file.Live.Header.FileEnd)

	fmt.Println("\n--- Firmware Header ---")
	fmt.Printf("  Magic:             0x%08X\n", file.Upgrade.Header.Magic)
	fmt.Printf("  UnknownA:          0x%08X\n", file.Upgrade.Header.FirmwareHeader)
	fmt.Printf("  UnknownB:          0x%08X\n", file.Upgrade.Header.UnknownB)
	fmt.Printf("  UnknownC:          0x%08X\n", file.Upgrade.Header.Flags)
	fmt.Printf("  KernelStart:       0x%08X\n", file.Upgrade.Header.FileSystemHeader)
	fmt.Printf("  UnknownE:          0x%08X\n", file.Upgrade.Header.FileEnd)

	fmt.Println("\n--- Squashfs Header ---")
	fmt.Printf("  Magic:             0x%08X\n", file.MainFS.Header.Magic)
	fmt.Printf("  Inodes:            %d\n", file.MainFS.Header.InodeCount)
	fmt.Printf("  Modified:          %s\n", time.Unix(int64(file.MainFS.Header.ModificationTime), 0))
	fmt.Printf("  Block Size:        %d bytes\n", file.MainFS.Header.BlockSize)
	fmt.Printf("  Fragments:         %d\n", file.MainFS.Header.FragmentEntryCount)
	fmt.Printf("  Compression:       %d (4=XZ)\n", file.MainFS.Header.CompressionID)
	fmt.Printf("  Flags:             0x%04X\n", file.MainFS.Header.Flags)
	fmt.Printf("  Version:           %d.%d\n", file.MainFS.Header.VersionMajor, file.MainFS.Header.VersionMinor)
	fmt.Printf("  Root Inode:        0x%X\n", file.MainFS.Header.RootInodeRef)
	fmt.Printf("  Bytes Used:        0x%X (%d MB)\n", file.MainFS.Header.BytesUsed, file.MainFS.Header.BytesUsed/1024/1024)
	fmt.Printf("  Inode Table:       0x%X\n", uint32(file.MainFS.Header.InodeTableStart))
	fmt.Printf("  Dir Table:         0x%X\n", uint32(file.MainFS.Header.DirectoryTableStart))
	fmt.Printf("  Fragment Table:    0x%X\n", uint32(file.MainFS.Header.FragmentTableStart))
	fmt.Printf("  Export Table:      0x%X\n", uint32(file.MainFS.Header.ExportTableStart))
	fmt.Printf("  ID Table:          0x%X\n", uint32(file.MainFS.Header.IDTableStart))

	fmt.Println("\n--- Inodes ---")
	for _, pair := range file.MainFS.Inodes {
		fmt.Printf("  [%2d] Type: %d  Perms: 0%04o  Modified: %s\n",
			pair.Header.InodeNumber,
			pair.Header.InodeType,
			pair.Header.Permissions,
			time.Unix(int64(pair.Header.ModifiedTime), 0),
		)
		switch body := pair.Body.(type) {
		case *ExtendedFile:
			fmt.Printf("       File    Size: %d bytes  Blocks: %d  Fragment: 0x%X\n",
				body.FileSize, len(body.BlockSizes), body.FragmentBlockIndex)
			fmt.Printf("Inode %d: BlocksStart=0x%X\n", pair.Header.InodeNumber, pair.Body.(*ExtendedFile).BlocksStart)

		case *ExtendedDirectory:
			fmt.Printf("       Dir     Size: %d  Children: %d  Parent: %d\n",
				body.FileSize, body.HardLinkCount-2, body.ParentInodeNumber)
		}
	}

	fmt.Println("\n--- Directories ---")
	for _, dir := range file.MainFS.Directories {
		fmt.Printf("  Block 0x%X  InodeRef: %d  Entries: %d\n",
			dir.Header.Start, dir.Header.InodeNumber, dir.Header.Count+1)
		for _, entry := range dir.Entry {
			fmt.Printf("    [type %d] %s  offset=0x%X  inodeOff=%d\n",
				entry.Type, entry.Name, entry.Offset, entry.InodeOffset)
		}
	}

	fmt.Println("\n--- Fragments ---")
	for i, frag := range file.MainFS.Fragments {
		compressed := (frag.Size & 0x1000000) == 0
		size := frag.Size & 0xFFFFFF
		fmt.Printf("  [%d] Start: 0x%X  Size: 0x%X  Compressed: %v\n", i, frag.Start, size, compressed)
	}

	fmt.Println("\n--- Export Table ---")
	for i, ref := range file.MainFS.ExportTable.Refs {
		fmt.Printf("  Inode %2d: block=0x%X  offset=0x%X  raw=0x%016X\n",
			i+1, ref.BlockOffset, ref.IntraOffset, file.MainFS.ExportTable.Raw[i])
	}

	fmt.Println("\n--- ID Table ---")
	if file.MainFS.IDTable != nil {
		for i, id := range file.MainFS.IDTable.IDs {
			fmt.Printf("  [%d] ID: %d\n", i, id)
		}
	} else {
		fmt.Println("  (not parsed)")
	}

	fmt.Println("\n--- Xattr Table ---")
	if file.MainFS.XattrTable != nil {
		var prefixes = map[uint16]string{0: "user.", 1: "trusted.", 2: "security."}

		fmt.Printf("  Xattr Table Start: 0x%X\n", file.MainFS.XattrTable.IDTable.XattrTableStart)
		fmt.Printf("  Xattr IDs:         %d\n", file.MainFS.XattrTable.IDTable.XattrIds)

		fmt.Println("\n  Lookup Table:")
		for i, lookup := range file.MainFS.XattrTable.LookupTable {
			fmt.Printf("    [%d] XattrRef: 0x%016X  Count: %d  Size: %d\n",
				i, lookup.XattrRef, lookup.Count, lookup.Size)
		}

		fmt.Println("\n  Entries:")
		for i, entries := range file.MainFS.XattrTable.Entries {
			fmt.Printf("    Inode xattr set [%d]:\n", i)
			for j, entry := range entries {
				prefix := prefixes[entry.Key.Type&0xFF]
				outOfLine := ""
				if entry.OutOfLine {
					outOfLine = " (out-of-line)"
				}
				fmt.Printf("      [%d] %s%s = %s%s\n",
					j, prefix, entry.Key.Name, entry.Value.Value, outOfLine)
			}
		}
	} else {
		fmt.Println("  (not parsed)")
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: parser <path-to-firmware>")
		os.Exit(1)
	}

	debug.SetMemoryLimit(8 * 1024 * 1024 * 1024) // 8 GiB
	debug.SetGCPercent(20)

	filePath := os.Args[1]

	mapped, err := openMapped(filePath)
	if err != nil {
		fmt.Printf("Error mapping file: %v\n", err)
		os.Exit(1)
	}
	defer mapped.Close()
	data := mapped.Data()

	// ===========================================
	//                  DAY 1
	// ===========================================

	// I don't know go... BUT I can have AI help me and I have taught lots of programming so this shouldn't be
	// too much of a hurdle.

	// After note: AI Helped a lot with the small differences between languages where I know what I wanted in
	// one language but not in go. Very fun language overall so far (Speaking from day 4)

	// Only started 3 hours after the interview, so 8pm. Finished the day at 12am

	// Where all the parsed results will live
	file := FirmwareFile{
		Live:    &FirmwareSection{},
		Upgrade: &FirmwareSection{},
	}

	file.Live.Header = fill[StartHeader](data, 0x0, binary.BigEndian) // End @ 0x8C
	startHeaderSize := uint32(binary.Size(StartHeader{}))

	metaDataBlockA := parseMetaData(startHeaderSize, file.Live.Header.FirmwareHeader, data)

	file.Upgrade.Header = fill[StartHeader](data, uint64(file.Live.Header.FirmwareHeader), binary.BigEndian)
	firmwareHeaderASize := uint32(binary.Size(FirmwareHeader{}))

	parseMetaData(metaDataBlockA.End+firmwareHeaderASize, 0x80E, data)

	// another header, most likely a firmware header too, just slightly different
	// because it has a message
	//firmwareHeaderB := parseFirmwareHeader(startHeader.FirmwareHeader, data)
	//firmwareHeaderBSize := uint32(binary.Size(firmwareHeaderA))

	//i = 0xA00 // Next block, skipping mass nulls

	// ===========================================
	//                  DAY 2
	// ===========================================

	// Had School + Work so i had like 3 hours :/
	// Lots of figuring out what everything outside the first few thousand bytes were
	// Lots of tunnel visioning hence only finding SquashFS halfway through the day
	// Then did research and organization to then have SquashFS docs and clean code for next day

	// ===========================================
	//                  DAY 3
	// ===========================================

	// Started the day at 5pm, AI was able to greatly speed up the reversing since I had the Squashfs docs.
	// Then all I needed to do was read the docs, create the corresponding structs, and then have AI do some of the more
	// menial refactoring for similar parts (saved me an hour)

	// Finish Squashfs Parsing

	file.MainFS, err = parseSquashFS(data, uint64(file.Live.Header.FileSystemHeader))
	if err != nil {
		fmt.Printf("parseSquashFS error: %v\n", err)
		os.Exit(1)
	}

	// ===========================================
	//                  DAY 4
	// ===========================================

	// Getting the files
	fileOutputPath := filepath.Join(filepath.Dir(filePath), "output")
	//if err := extractRecursive(data, uint64(file.StartHeader.FileSystemHeader), fileOutputPath, 0); err != nil {
	//	fmt.Printf("Extraction error: %v\n", err)
	//	os.Exit(1)
	//}

	if err := extractFiles(file.MainFS, data, fileOutputPath); err != nil {
		fmt.Printf("extractFiles error: %v\n", err)
		os.Exit(1)
	}

	// ==============================================

	printFirmwareFile(&file)
	mapped.Close()
	data = nil
	file.MainFS = nil

	entries, err := os.ReadDir(fileOutputPath)
	if err != nil {
		fmt.Printf("ReadDir error: %v\n", err)
		os.Exit(1)
	}

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".pkg" {
			continue
		}
		pkgPath := filepath.Join(fileOutputPath, entry.Name())
		fmt.Printf("\n[Level 2] %s\n", entry.Name())

		pkgMapped, err := openMapped(pkgPath)
		fmt.Printf("\n[Level 2] %s\n", entry.Name())

		pkgData := pkgMapped.Data()
		if err != nil {
			fmt.Printf("  WARNING: could not read %s: %v\n", entry.Name(), err)
			continue
		}

		if uint64(len(pkgData)) < uint64(binary.Size(StartHeader{})) {
			fmt.Printf("  WARNING: %s too small for StartHeader\n", entry.Name())
			pkgMapped.Close()
			continue
		}

		pkgStartHeader := fill[StartHeader](pkgData, 0, binary.BigEndian)
		pkgFSBase := uint64(pkgStartHeader.FileSystemHeader)

		if pkgFSBase+4 > uint64(len(pkgData)) {
			fmt.Printf("  WARNING: %s fsBase 0x%X out of bounds\n", entry.Name(), pkgFSBase)
			pkgMapped.Close()
			continue
		}

		if binary.LittleEndian.Uint32(pkgData[pkgFSBase:pkgFSBase+4]) != 0x73717368 {
			fmt.Printf("  WARNING: %s no SquashFS magic at 0x%X\n", entry.Name(), pkgFSBase)
			pkgMapped.Close()
			continue
		}

		pkgSquash, err := parseSquashFS(pkgData, pkgFSBase)
		if err != nil {
			fmt.Printf("  WARNING: parseSquashFS failed for %s: %v\n", entry.Name(), err)
			pkgMapped.Close()
			continue
		}

		childOut := filepath.Join(fileOutputPath, entry.Name()+"_extracted")
		if err := extractFiles(pkgSquash, pkgData, childOut); err != nil {
			fmt.Printf("  WARNING: extractFiles failed for %s: %v\n", entry.Name(), err)
		} else {
			fmt.Printf("  Done -> %s\n", childOut)
		}

		pkgMapped.Close()
		pkgData = nil
		pkgSquash = nil
	}

	// ===========================================
	//                  DAY 5
	// ===========================================

	// Going back to the initial headers now that i know how it's actually structured from the
	//experience from unpacking the other .pkg files.

	// Live Start Header
	// Backup Start Header
	// Bootloader
	// Kernel
	// FileSystem

	// Hopefully this should also be pretty easy like day 3 and kinda like day 4 since i already know the info,
	// I just need to code it
}
