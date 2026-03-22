package main

// Test items: https://drive.google.com/drive/folders/1_TtBnqGhBP7Ss-FFxzW18fjrFbFRl86x

import (
	"bytes"
	//"compress/gzip"
	"encoding/binary"
	"fmt"
	//"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"time"
	"unsafe"

	//"github.com/ulikunitz/xz"
	"golang.org/x/sys/windows"
)

type FirmwareFile struct {
	Live       *LiveHeader
	Upgrade    *UpgradeHeader
	MBR        *MBR
	Kernel     *Kernel
	Initramfs  *Initramfs
	EHFrame    *EHFrame
	FileSystem *SquashFS
}

type LiveHeader struct {
	Magic            uint32   // 0x00, 4 bytes
	Signature        [48]byte // 0x04, 48 bytes
	Padding          uint32   // 0x34, 4 bytes (00 00 00 00)
	Anchor           [8]byte  // 0x38, 8 bytes (DE AD BE EF DE AD BE EF)
	UpgradeHeader    uint32   // 0x40, 4 bytes (00 00 04 0C)
	UnknownB         uint32   // 0x44, 4 bytes (00 00 75 30)
	Flags            uint32   // 0x48, 4 bytes (00 00 00 00)
	FileSystemHeader uint32   // 0x4C, 4 bytes (02 7D 88 F9)
	FileEnd          uint32   // 0x50, 4 bytes, FileEnd for the Start Header
	NullPad          [56]byte // 0x54, 56 bytes
	MetaData         *MetaDataBlock
}

type UpgradeHeader struct {
	Magic            uint32
	Signature        [48]byte
	Padding          uint32
	Anchor           [8]byte
	MasterBootRecord uint32
	UnknownB         uint32
	Flags            uint32
	Initramfs        uint32
	FileSystemHeader uint32 // Upgrade header offset
	NullPad          [56]byte
	MetaData         *MetaDataBlock
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

type MBR struct {
	BootCode       [446]byte
	PartitionTable [4]PartitionEntry
	BootSignature  [2]byte
}

type PartitionEntry struct {
	Status      uint8
	CHSFirst    [3]byte
	Type        uint8
	CHSLast     [3]byte
	LBAStart    uint32
	SectorCount uint32
}

// https://www.kernel.org/doc/html/v6.1/x86/boot.html#the-real-mode-kernel-header
type KernelHeader struct {
	Jump                uint16 // 0x200 - EB 66
	Magic               uint32 // 0x202 - HdrS
	Version             uint16 // 0x206
	RealmodeSwtch       uint32 // 0x208
	StartSysSeg         uint16 // 0x20C
	KernelVersion       uint16 // 0x20E
	TypeOfLoader        uint8  // 0x210
	LoadFlags           uint8  // 0x211
	SetupMoveSize       uint16 // 0x212
	Code32Start         uint32 // 0x214
	RamdiskImage        uint32 // 0x218
	RamdiskSize         uint32 // 0x21C
	BooSectKludge       uint32 // 0x220 - DO NOT USE
	HeapEndPtr          uint16 // 0x224
	ExtLoaderVer        uint8  // 0x226
	ExtLoaderType       uint8  // 0x227
	CmdLinePtr          uint32 // 0x228
	InitrdAddrMax       uint32 // 0x22C
	KernelAlignment     uint32 // 0x230
	RelocatableKernel   uint8  // 0x234
	MinAlignment        uint8  // 0x235
	XLoadFlags          uint16 // 0x236
	CmdlineSize         uint32 // 0x238
	HardwareSubarch     uint32 // 0x23C
	HardwareSubarchData uint64 // 0x240
	PayloadOffset       uint32 // 0x248
	PayloadLength       uint32 // 0x24C
	SetupData           uint64 // 0x250
	PrefAddress         uint64 // 0x258
	InitSize            uint32 // 0x260
	HandoverOffset      uint32 // 0x264
}

type Kernel struct {
	//Preamble [0x1F1]byte // everything before the header
	Header *KernelHeader
	Data   []byte
}

type Initramfs struct {
	Data  []byte
	Start uint64
	End   uint64
}

type CpioEntry struct {
	Name string
	Mode uint32
	Size uint64
	Data []byte
}

type EHFrame struct {
	Data  []byte
	Start uint64
	End   uint64
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

func parseLiveHeader(data []byte, offset uint64) *LiveHeader {
	r := bytes.NewReader(data[offset:])
	hdr := &LiveHeader{}

	binary.Read(r, binary.BigEndian, &hdr.Magic)
	binary.Read(r, binary.BigEndian, &hdr.Signature)
	binary.Read(r, binary.BigEndian, &hdr.Padding)
	binary.Read(r, binary.BigEndian, &hdr.Anchor)
	binary.Read(r, binary.BigEndian, &hdr.UpgradeHeader)
	binary.Read(r, binary.BigEndian, &hdr.UnknownB)
	binary.Read(r, binary.BigEndian, &hdr.Flags)
	binary.Read(r, binary.BigEndian, &hdr.FileSystemHeader)
	binary.Read(r, binary.BigEndian, &hdr.FileEnd)
	binary.Read(r, binary.BigEndian, &hdr.NullPad)

	hdr.MetaData = parseMetaData(0x8C, hdr.UpgradeHeader, data)

	return hdr
}

func parseUpgradeHeader(file *FirmwareFile, data []byte, offset uint64) *UpgradeHeader {
	r := bytes.NewReader(data[offset:])
	hdr := &UpgradeHeader{}

	binary.Read(r, binary.BigEndian, &hdr.Magic)
	binary.Read(r, binary.BigEndian, &hdr.Signature)
	binary.Read(r, binary.BigEndian, &hdr.Padding)
	binary.Read(r, binary.BigEndian, &hdr.Anchor)
	binary.Read(r, binary.BigEndian, &hdr.MasterBootRecord)
	binary.Read(r, binary.BigEndian, &hdr.UnknownB)
	binary.Read(r, binary.BigEndian, &hdr.Flags)
	binary.Read(r, binary.BigEndian, &hdr.Initramfs)
	binary.Read(r, binary.BigEndian, &hdr.FileSystemHeader)
	binary.Read(r, binary.BigEndian, &hdr.NullPad)

	// Header is 0x8C long (or 0x90 if you count the 00 00 00 0C, though idk what that's for)
	hdr.MetaData = parseMetaData(file.Live.MetaData.End+0x8C, file.Live.MetaData.End+0x8C+hdr.MasterBootRecord, data)

	return hdr
}

//func detectCompression(data []byte) string {
//	switch {
//	case len(data) >= 2 && data[0] == 0x1F && data[1] == 0x8B:
//		return "gzip"
//	case len(data) >= 6 && data[0] == 0xFD && string(data[1:6]) == "7zXZ\x00":
//		return "xz"
//	case len(data) >= 4 && data[0] == 0x02 && data[1] == 0x21 && data[2] == 0x4C && data[3] == 0x18:
//		return "lz4"
//	case len(data) >= 3 && data[0] == 0x5D && data[1] == 0x00 && data[2] == 0x00:
//		return "lzma"
//	case len(data) >= 4 && string(data[0:4]) == "\x28\xB5\x2F\xFD":
//		return "zstd"
//	default:
//		return "unknown"
//	}
//}
//
//func parseInitramfs(data []byte, start, end uint64) (*Initramfs, error) {
//	raw := data[start:end]
//	compression := detectCompression(raw)
//	fmt.Printf("  Initramfs compression: %s\n", compression)
//
//	var reader io.Reader
//	switch compression {
//	case "gzip":
//		r, err := gzip.NewReader(bytes.NewReader(raw))
//		if err != nil {
//			return nil, fmt.Errorf("gzip reader: %w", err)
//		}
//		defer r.Close()
//		reader = r
//	case "xz":
//		r, err := xz.NewReader(bytes.NewReader(raw))
//		if err != nil {
//			return nil, fmt.Errorf("xz reader: %w", err)
//		}
//		reader = r
//	default:
//		return nil, fmt.Errorf("unsupported compression: %s", compression)
//	}
//
//	decompressed, err := io.ReadAll(reader)
//	if err != nil {
//		return nil, fmt.Errorf("decompression failed: %w", err)
//	}
//
//	return &Initramfs{
//		Data:  decompressed,
//		Start: start,
//		End:   end,
//	}, nil
//}
//
//func parseCpio(data []byte) ([]CpioEntry, error) {
//	var entries []CpioEntry
//	offset := 0
//
//	for offset+110 <= len(data) {
//		magic := string(data[offset : offset+6])
//		if magic == "TRAILER" {
//			break
//		}
//		if magic != "070701" && magic != "070702" {
//			return nil, fmt.Errorf("invalid cpio magic at 0x%X: %q", offset, magic)
//		}
//
//		// CPIO newc header is 110 bytes, all fields are 8-char hex ASCII
//		parseHex := func(s []byte) uint32 {
//			var v uint32
//			fmt.Sscanf(string(s), "%x", &v)
//			return v
//		}
//
//		h := data[offset:]
//		mode := parseHex(h[14:22])
//		fileSize := uint64(parseHex(h[54:62]))
//		nameSize := uint32(parseHex(h[94:102]))
//		offset += 110
//
//		// Name
//		name := string(data[offset : offset+int(nameSize)-1]) // strip null terminator
//		offset += int(nameSize)
//		// Align to 4 bytes
//		if offset%4 != 0 {
//			offset += 4 - offset%4
//		}
//
//		if name == "TRAILER!!!" {
//			break
//		}
//
//		// Data
//		fileData := make([]byte, fileSize)
//		copy(fileData, data[offset:offset+int(fileSize)])
//		offset += int(fileSize)
//		// Align to 4 bytes
//		if offset%4 != 0 {
//			offset += 4 - offset%4
//		}
//
//		entries = append(entries, CpioEntry{
//			Name: name,
//			Mode: mode,
//			Size: fileSize,
//			Data: fileData,
//		})
//	}
//
//	return entries, nil
//}

func extractInitramfs(data []byte, start, end uint64, outputPath string) error {
	raw := data[start:end]

	outFile := outputPath + "\\initramfs.cpio"
	if err := os.WriteFile(outFile, raw, 0644); err != nil {
		return fmt.Errorf("write initramfs: %w", err)
	}

	fmt.Printf("  Initramfs written to %s (%d KB)\n", outFile, len(raw)/1024)
	return nil
}

func printFirmwareFile(file *FirmwareFile) {
	// AI generated

	fmt.Println("\n=== Firmware File ===")

	fmt.Println("\n--- Live Start Header ---")
	fmt.Printf("  Magic:             0x%08X\n", file.Live.Magic)
	fmt.Printf("  Firmware Header:   0x%08X\n", file.Live.UpgradeHeader)
	fmt.Printf("  UnknownB:          0x%08X\n", file.Live.UnknownB)
	fmt.Printf("  Flags:             0x%08X\n", file.Live.Flags)
	fmt.Printf("  File System:       0x%08X\n", file.Live.FileSystemHeader)
	fmt.Printf("  File End:          0x%08X\n", file.Live.FileEnd)

	fmt.Println("\n--- Upgrade Header ---")
	fmt.Printf("  Magic:             0x%08X\n", file.Upgrade.Magic)
	fmt.Printf("  MBR:               0x%08X\n", file.Upgrade.MasterBootRecord)
	fmt.Printf("  UnknownB:          0x%08X\n", file.Upgrade.UnknownB)
	fmt.Printf("  UnknownC:          0x%08X\n", file.Upgrade.Flags)
	fmt.Printf("  Initramfs:       0x%08X\n", file.Upgrade.Initramfs)
	fmt.Printf("  File System:       0x%08X\n", file.Upgrade.FileSystemHeader)

	fmt.Println("\n--- MBR ---")
	fmt.Printf("  Boot Signature:    0x%X\n", file.MBR.BootSignature)
	for i, entry := range file.MBR.PartitionTable {
		fmt.Printf("  Partition %d:\n", i)
		fmt.Printf("    Status:          0x%02X (%s)\n", entry.Status, func() string {
			if entry.Status == 0x80 {
				return "bootable"
			}
			return "not bootable"
		}())
		fmt.Printf("    Type:            0x%02X\n", entry.Type)
		fmt.Printf("    LBA Start:       0x%08X (%d)\n", entry.LBAStart, entry.LBAStart)
		fmt.Printf("    Sector Count:    0x%08X (%d)\n", entry.SectorCount, entry.SectorCount)
		fmt.Printf("    CHS First:       %02X %02X %02X\n", entry.CHSFirst[0], entry.CHSFirst[1], entry.CHSFirst[2])
		fmt.Printf("    CHS Last:        %02X %02X %02X\n", entry.CHSLast[0], entry.CHSLast[1], entry.CHSLast[2])
	}

	fmt.Println("\n--- Kernel ---")
	fmt.Printf("  Jump:                %02X %02X\n", file.Kernel.Header.Jump&0xFF, file.Kernel.Header.Jump>>8)
	fmt.Printf("  Magic:               0x%08X\n", file.Kernel.Header.Magic)
	fmt.Printf("  Boot Protocol:       %d.%d\n", file.Kernel.Header.Version>>8, file.Kernel.Header.Version&0xFF)
	fmt.Printf("  Type Of Loader:      0x%02X\n", file.Kernel.Header.TypeOfLoader)
	fmt.Printf("  Load Flags:          0x%02X\n", file.Kernel.Header.LoadFlags)
	fmt.Printf("  Setup Move Size:     0x%04X\n", file.Kernel.Header.SetupMoveSize)
	fmt.Printf("  Code32 Start:        0x%08X\n", file.Kernel.Header.Code32Start)
	fmt.Printf("  Ramdisk Image:       0x%08X\n", file.Kernel.Header.RamdiskImage)
	fmt.Printf("  Ramdisk Size:        0x%08X\n", file.Kernel.Header.RamdiskSize)
	fmt.Printf("  Heap End Ptr:        0x%04X\n", file.Kernel.Header.HeapEndPtr)
	fmt.Printf("  Cmdline Ptr:         0x%08X\n", file.Kernel.Header.CmdLinePtr)
	fmt.Printf("  Initrd Addr Max:     0x%08X\n", file.Kernel.Header.InitrdAddrMax)
	fmt.Printf("  Kernel Alignment:    0x%08X\n", file.Kernel.Header.KernelAlignment)
	fmt.Printf("  Relocatable:         %v\n", file.Kernel.Header.RelocatableKernel != 0)
	fmt.Printf("  Min Alignment:       0x%02X\n", file.Kernel.Header.MinAlignment)
	fmt.Printf("  XLoad Flags:         0x%04X\n", file.Kernel.Header.XLoadFlags)
	fmt.Printf("  Cmdline Size:        %d\n", file.Kernel.Header.CmdlineSize)
	fmt.Printf("  Hardware Subarch:    0x%08X\n", file.Kernel.Header.HardwareSubarch)
	fmt.Printf("  HW Subarch Data:     0x%016X\n", file.Kernel.Header.HardwareSubarchData)
	fmt.Printf("  Payload Offset:      0x%08X\n", file.Kernel.Header.PayloadOffset)
	fmt.Printf("  Payload Length:      0x%08X (%d KB)\n", file.Kernel.Header.PayloadLength, file.Kernel.Header.PayloadLength/1024)
	fmt.Printf("  Setup Data:          0x%016X\n", file.Kernel.Header.SetupData)
	fmt.Printf("  Pref Address:        0x%016X\n", file.Kernel.Header.PrefAddress)
	fmt.Printf("  Init Size:           0x%08X (%d MB)\n", file.Kernel.Header.InitSize, file.Kernel.Header.InitSize/1024/1024)
	fmt.Printf("  Handover Offset:     0x%08X\n", file.Kernel.Header.HandoverOffset)
	fmt.Printf("  Kernel Version Ptr:  0x%04X\n", file.Kernel.Header.KernelVersion)
	fmt.Printf("  Data Size:           0x%X (%d KB)\n", len(file.Kernel.Data), len(file.Kernel.Data)/1024)

	fmt.Println("\n--- Squashfs Header ---")
	fmt.Printf("  Magic:             0x%08X\n", file.FileSystem.Header.Magic)
	fmt.Printf("  Inodes:            %d\n", file.FileSystem.Header.InodeCount)
	fmt.Printf("  Modified:          %s\n", time.Unix(int64(file.FileSystem.Header.ModificationTime), 0))
	fmt.Printf("  Block Size:        %d bytes\n", file.FileSystem.Header.BlockSize)
	fmt.Printf("  Fragments:         %d\n", file.FileSystem.Header.FragmentEntryCount)
	fmt.Printf("  Compression:       %d (4=XZ)\n", file.FileSystem.Header.CompressionID)
	fmt.Printf("  Flags:             0x%04X\n", file.FileSystem.Header.Flags)
	fmt.Printf("  Version:           %d.%d\n", file.FileSystem.Header.VersionMajor, file.FileSystem.Header.VersionMinor)
	fmt.Printf("  Root Inode:        0x%X\n", file.FileSystem.Header.RootInodeRef)
	fmt.Printf("  Bytes Used:        0x%X (%d MB)\n", file.FileSystem.Header.BytesUsed, file.FileSystem.Header.BytesUsed/1024/1024)
	fmt.Printf("  Inode Table:       0x%X\n", uint32(file.FileSystem.Header.InodeTableStart))
	fmt.Printf("  Dir Table:         0x%X\n", uint32(file.FileSystem.Header.DirectoryTableStart))
	fmt.Printf("  Fragment Table:    0x%X\n", uint32(file.FileSystem.Header.FragmentTableStart))
	fmt.Printf("  Export Table:      0x%X\n", uint32(file.FileSystem.Header.ExportTableStart))
	fmt.Printf("  ID Table:          0x%X\n", uint32(file.FileSystem.Header.IDTableStart))

	fmt.Println("\n--- Inodes ---")
	for _, pair := range file.FileSystem.Inodes {
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
	for _, dir := range file.FileSystem.Directories {
		fmt.Printf("  Block 0x%X  InodeRef: %d  Entries: %d\n",
			dir.Header.Start, dir.Header.InodeNumber, dir.Header.Count+1)
		for _, entry := range dir.Entry {
			fmt.Printf("    [type %d] %s  offset=0x%X  inodeOff=%d\n",
				entry.Type, entry.Name, entry.Offset, entry.InodeOffset)
		}
	}

	fmt.Println("\n--- Fragments ---")
	for i, frag := range file.FileSystem.Fragments {
		compressed := (frag.Size & 0x1000000) == 0
		size := frag.Size & 0xFFFFFF
		fmt.Printf("  [%d] Start: 0x%X  Size: 0x%X  Compressed: %v\n", i, frag.Start, size, compressed)
	}

	fmt.Println("\n--- Export Table ---")
	for i, ref := range file.FileSystem.ExportTable.Refs {
		fmt.Printf("  Inode %2d: block=0x%X  offset=0x%X  raw=0x%016X\n",
			i+1, ref.BlockOffset, ref.IntraOffset, file.FileSystem.ExportTable.Raw[i])
	}

	fmt.Println("\n--- ID Table ---")
	if file.FileSystem.IDTable != nil {
		for i, id := range file.FileSystem.IDTable.IDs {
			fmt.Printf("  [%d] ID: %d\n", i, id)
		}
	} else {
		fmt.Println("  (not parsed)")
	}

	fmt.Println("\n--- Xattr Table ---")
	if file.FileSystem.XattrTable != nil {
		var prefixes = map[uint16]string{0: "user.", 1: "trusted.", 2: "security."}

		fmt.Printf("  Xattr Table Start: 0x%X\n", file.FileSystem.XattrTable.IDTable.XattrTableStart)
		fmt.Printf("  Xattr IDs:         %d\n", file.FileSystem.XattrTable.IDTable.XattrIds)

		fmt.Println("\n  Lookup Table:")
		for i, lookup := range file.FileSystem.XattrTable.LookupTable {
			fmt.Printf("    [%d] XattrRef: 0x%016X  Count: %d  Size: %d\n",
				i, lookup.XattrRef, lookup.Count, lookup.Size)
		}

		fmt.Println("\n  Entries:")
		for i, entries := range file.FileSystem.XattrTable.Entries {
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
		Live:    &LiveHeader{},
		Upgrade: &UpgradeHeader{},
	}

	file.Live = parseLiveHeader(data, 0x0)
	file.Upgrade = parseUpgradeHeader(&file, data, uint64(file.Live.UpgradeHeader))

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

	file.FileSystem, err = parseSquashFS(data, uint64(file.Live.FileSystemHeader))
	if err != nil {
		fmt.Printf("parseSquashFS error: %v\n", err)
		os.Exit(1)
	}

	// ===========================================
	//                  DAY 4
	// ===========================================

	// Getting the files

	//fileOutputPath := filepath.Join(filepath.Dir(filePath), "output")
	//if err := extractFiles(file.FileSystem, data, fileOutputPath); err != nil {
	//	fmt.Printf("extractFiles error: %v\n", err)
	//	os.Exit(1)
	//}

	// ==============================================

	//mapped.Close()
	//data = nil
	//file.FileSystem = nil

	//entries, err := os.ReadDir(fileOutputPath)
	//if err != nil {
	//	fmt.Printf("ReadDir error: %v\n", err)
	//	os.Exit(1)
	//}
	//
	//for _, entry := range entries {
	//	if entry.IsDir() || filepath.Ext(entry.Name()) != ".pkg" {
	//		continue
	//	}
	//	pkgPath := filepath.Join(fileOutputPath, entry.Name())
	//	fmt.Printf("\n[Level 2] %s\n", entry.Name())
	//
	//	pkgMapped, err := openMapped(pkgPath)
	//	fmt.Printf("\n[Level 2] %s\n", entry.Name())
	//
	//	pkgData := pkgMapped.Data()
	//	if err != nil {
	//		fmt.Printf("  WARNING: could not read %s: %v\n", entry.Name(), err)
	//		continue
	//	}
	//
	//	if uint64(len(pkgData)) < uint64(binary.Size(LiveHeader{})) {
	//		fmt.Printf("  WARNING: %s too small for LiveHeader\n", entry.Name())
	//		pkgMapped.Close()
	//		continue
	//	}
	//
	//	pkgStartHeader := fill[LiveHeader](pkgData, 0, binary.BigEndian)
	//	pkgFSBase := uint64(pkgStartHeader.FileSystemHeader)
	//
	//	if pkgFSBase+4 > uint64(len(pkgData)) {
	//		fmt.Printf("  WARNING: %s fsBase 0x%X out of bounds\n", entry.Name(), pkgFSBase)
	//		pkgMapped.Close()
	//		continue
	//	}
	//
	//	if binary.LittleEndian.Uint32(pkgData[pkgFSBase:pkgFSBase+4]) != 0x73717368 {
	//		fmt.Printf("  WARNING: %s no SquashFS magic at 0x%X\n", entry.Name(), pkgFSBase)
	//		pkgMapped.Close()
	//		continue
	//	}
	//
	//	pkgSquash, err := parseSquashFS(pkgData, pkgFSBase)
	//	if err != nil {
	//		fmt.Printf("  WARNING: parseSquashFS failed for %s: %v\n", entry.Name(), err)
	//		pkgMapped.Close()
	//		continue
	//	}
	//
	//	childOut := filepath.Join(fileOutputPath, entry.Name()+"_extracted")
	//	if err := extractFiles(pkgSquash, pkgData, childOut); err != nil {
	//		fmt.Printf("  WARNING: extractFiles failed for %s: %v\n", entry.Name(), err)
	//	} else {
	//		fmt.Printf("  Done -> %s\n", childOut)
	//	}
	//
	//	pkgMapped.Close()
	//	pkgData = nil
	//	pkgSquash = nil
	//}

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

	// OOOOOOOO, this looks very applicable
	// https://www.kernel.org/doc/html/v6.1/x86/boot.html#memory-layout

	// An MBR is only 512 bytes long
	mbrStart := uint64(file.Upgrade.MetaData.End)
	file.MBR = fill[MBR](data, mbrStart, binary.LittleEndian)
	kernelStart := mbrStart + 0x200

	file.Kernel = &Kernel{
		Header: fill[KernelHeader](data, kernelStart, binary.LittleEndian),
		Data:   data[kernelStart+0x1F1+uint64(binary.Size(KernelHeader{})) : file.Live.UpgradeHeader+file.Upgrade.Initramfs],
	}

	printFirmwareFile(&file)

	kernelPayloadStart := kernelStart + uint64(file.Kernel.Header.PayloadOffset)
	kernelPayloadEnd := kernelPayloadStart + uint64(file.Kernel.Header.PayloadLength)

	initramfsStart := uint64(file.Live.UpgradeHeader + file.Upgrade.Initramfs)
	initramfsEnd := uint64(file.Live.FileSystemHeader)

	file.Initramfs = &Initramfs{
		Data:  data[initramfsStart:initramfsEnd],
		Start: initramfsStart,
		End:   initramfsEnd,
	}

	file.EHFrame = &EHFrame{
		Data:  data[initramfsEnd:file.Live.FileSystemHeader],
		Start: initramfsEnd,
		End:   uint64(file.Live.FileSystemHeader),
	}

	initramfsOut := filepath.Join(filepath.Dir(filePath), "output")
	if err := extractInitramfs(data, initramfsStart, initramfsEnd, initramfsOut); err != nil {
		fmt.Printf("extractInitramfs error: %v\n", err)
	}

	regions := []struct {
		name  string
		start uint64
		end   uint64
	}{
		{"Live Header", 0, uint64(file.Live.UpgradeHeader)},
		{"Upgrade Header", uint64(file.Live.UpgradeHeader), uint64(file.Upgrade.MetaData.End)},
		{"MBR", uint64(file.Upgrade.MetaData.End), mbrStart + 0x200},
		{"Kernel Setup", kernelStart, kernelPayloadStart},
		{"Kernel Payload", kernelPayloadStart, kernelPayloadEnd},
		{"Unknown", kernelPayloadEnd, uint64(file.Live.UpgradeHeader + file.Upgrade.Initramfs)},
		{"Initramfs", uint64(file.Live.UpgradeHeader + file.Upgrade.Initramfs), uint64(file.Live.FileSystemHeader)},
		{"SquashFS", uint64(file.Live.FileSystemHeader), uint64(file.Live.FileEnd)},
	}

	for _, r := range regions {
		fmt.Printf("  %-20s [0x%08X - 0x%08X] (%d MB)\n",
			r.name, r.start, r.end, (r.end-r.start)/1024/1024)
	}

	// PayloadOffset is relative to the end of the setup sectors
	// Actual payload start = setup_end + PayloadOffset
	// Where setup_end = (setup_sects + 1) * 512

	//setupSects := data[0x1F1] // byte just before the header
	//setupEnd := (uint32(setupSects) + 1) * 512
	//
	//payloadStart := setupEnd + file.Kernel.Header.PayloadOffset
	//payloadEnd := payloadStart + file.Kernel.Header.PayloadLength
	//
	//fmt.Printf("0x%08X\n", payloadStart)
	//fmt.Printf("0x%08X\n", payloadEnd)
}
