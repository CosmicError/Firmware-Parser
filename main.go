package main

// Test items: https://drive.google.com/drive/folders/1_TtBnqGhBP7Ss-FFxzW18fjrFbFRl86x

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/ulikunitz/xz"
)

type FirmwareFile struct {
	StartHeader    *StartHeader
	FirmwareHeader *FirmwareHeader

	// SquashFS
	// Start: 0x027DCEB8
	SquashFSHeader *SquashFSHeader
	Inodes         []InodePair
	Directories    []DirectoryPair
	Fragments      []FragmentBlockEntry
	ExportTable    *ExportTable
	IDTable        *IDTable
	XattrTable     *XattrTable
	// End: 0x311B2EB8
}

type InodePair struct {
	Header *InodeHeader
	Body   interface{} // *ExtendedFile or *ExtendedDirectory etc
}

type DirectoryPair struct {
	Header *DirectoryHeader
	Index  *DirectoryIndex
	Entry  []DirectoryEntry
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

// SquashFSHeader https://dr-emann.github.io/squashfs/
type SquashFSHeader struct {
	Magic               uint32
	InodeCount          uint32
	ModificationTime    uint32
	BlockSize           uint32
	FragmentEntryCount  uint32
	CompressionID       uint16
	BlockLog            uint16
	Flags               uint16
	IDCount             uint16
	VersionMajor        uint16
	VersionMinor        uint16
	RootInodeRef        uint64
	BytesUsed           uint64
	IDTableStart        uint64
	XattrIDTableStart   uint64 // Absolute Position (Add StartHeader.FileSystemHeader)
	InodeTableStart     uint64 // Relative Position
	DirectoryTableStart uint64 // Relative Position
	FragmentTableStart  uint64 // Absolute Position (Add StartHeader.FileSystemHeader)
	ExportTableStart    uint64 // Absolute Position (Add StartHeader.FileSystemHeader)
}

type InodeHeader struct {
	InodeType    uint16
	Permissions  uint16
	UIDIdx       uint16
	GIDIdx       uint16
	ModifiedTime uint32
	InodeNumber  uint32
}

type ExtendedFile struct {
	BlocksStart        uint64
	FileSize           uint64
	Sparse             uint64
	HardLinkCount      uint32
	FragmentBlockIndex uint32
	BlockOffset        uint32
	XattrIdx           uint32
	BlockSizes         []uint32
}

type DirIndex struct {
	Index    uint32
	Start    uint32
	NameSize uint32
	Name     []uint8 // Name follows: u8[NameSize + 1]
}

type ExtendedDirectory struct {
	HardLinkCount     uint32
	FileSize          uint32
	DirBlockStart     uint32
	ParentInodeNumber uint32
	IndexCount        uint16
	BlockOffset       uint16
	XattrIdx          uint32
	Index             []DirIndex
}

type DirectoryHeader struct {
	Count       uint32
	Start       uint32
	InodeNumber uint32
}

type DirectoryEntry struct {
	Offset      uint16
	InodeOffset int16
	Type        uint16
	NameSize    uint16
	Name        []uint8
}

type DirectoryIndex struct {
	Index    uint32
	Start    uint32
	NameSize uint32
	Name     []uint8
}

type FragmentBlockEntry struct {
	Start  uint64
	Size   uint32
	Unused uint32
}

type InodeRef struct {
	BlockOffset uint32 // offset from SquashFSHeader.InodeTableStart to the metadata block (2 byte header included)
	IntraOffset uint16 // offset within the decompressed metadata block
}

type ExportTable struct {
	Raw  []uint64
	Refs []InodeRef
}

type IDTable struct {
	IDs []uint32
}

type XattrKeyEntry struct {
	Type     uint16
	NameSize uint16
	Name     []uint8 // NameSize - strlen(prefix)
}

type XattrValueEntry struct {
	ValueSize uint32
	Value     []uint8 // ValueSize as the length
}

type XattrEntry struct {
	Key       XattrKeyEntry
	Value     XattrValueEntry
	OutOfLine bool // true if type had 0x0100 flag set
}

type XattrLookupTable struct {
	XattrRef uint64
	Count    uint32
	Size     uint32
}

type XattrIDTable struct {
	XattrTableStart uint64 // The absolute position of the first metadata block holding the key/value pairs.
	XattrIds        uint32
	Unused          uint32   // Not used
	Table           []uint64 // Stores absolute locations of each metadata block of the XattrLookupTable
}

type XattrTable struct {
	IDTable     XattrIDTable
	LookupTable []XattrLookupTable
	Entries     [][]XattrEntry // outer index = lookup table index, inner = key/value pairs for that inode
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

func readSquashFSMetadataBlocks(start uint64, end uint64, data []byte) []byte {
	var result []byte // Our pool of uncompressed data we return
	offset := start

	for offset < end {
		// these headers are only 16 bits long (2 bytes)
		header := binary.LittleEndian.Uint16(data[offset : offset+2])
		dataSize := uint64(header & 0x7FFF)
		compressed := (header & 0x8000) == 0
		offset += 2

		blockData := data[offset : offset+dataSize]

		if compressed {
			xzReader, err := xz.NewReader(bytes.NewReader(blockData))
			if err != nil {
				fmt.Printf("xz reader error: %v\n", err)
				return result
			}

			decompressed, err := io.ReadAll(xzReader)
			if err != nil {
				fmt.Printf("xz decompress error: %v\n", err)
				return result
			}

			result = append(result, decompressed...)
		} else {
			result = append(result, blockData...)
		}

		offset += dataSize
	}

	return result
}

func parseExtendedFile(offset uint64, blockSize uint32, data []byte) (*ExtendedFile, uint64) {
	r := bytes.NewReader(data[offset:])

	var blocksStart uint64
	var fileSize uint64
	var sparse uint64
	var hardLinkCount uint32
	var fragmentBlockIndex uint32
	var blockOffset uint32
	var xattrIdx uint32

	binary.Read(r, binary.LittleEndian, &blocksStart)
	binary.Read(r, binary.LittleEndian, &fileSize)
	binary.Read(r, binary.LittleEndian, &sparse)
	binary.Read(r, binary.LittleEndian, &hardLinkCount)
	binary.Read(r, binary.LittleEndian, &fragmentBlockIndex)
	binary.Read(r, binary.LittleEndian, &blockOffset)
	binary.Read(r, binary.LittleEndian, &xattrIdx)

	var blockCount uint64
	if fragmentBlockIndex == 0xFFFFFFFF {
		blockCount = (fileSize + uint64(blockSize) - 1) / uint64(blockSize)
	} else {
		blockCount = fileSize / uint64(blockSize)
	}

	blockSizes := make([]uint32, blockCount)
	binary.Read(r, binary.LittleEndian, &blockSizes)

	hdr := ExtendedFile{
		BlocksStart:        blocksStart,
		FileSize:           fileSize,
		Sparse:             sparse,
		HardLinkCount:      hardLinkCount,
		FragmentBlockIndex: fragmentBlockIndex,
		BlockOffset:        blockOffset,
		XattrIdx:           xattrIdx,
		BlockSizes:         blockSizes,
	}

	consumed := 40 + blockCount*4

	return &hdr, consumed
}

func parseExtendedDirectory(offset uint64, data []byte) (*ExtendedDirectory, uint64) {
	r := bytes.NewReader(data[offset:])

	var hardLinkCount uint32
	var fileSize uint32
	var dirBlockStart uint32
	var parentInodeNumber uint32
	var indexCount uint16
	var blockOffset uint16
	var xattrIdx uint32

	binary.Read(r, binary.LittleEndian, &hardLinkCount)
	binary.Read(r, binary.LittleEndian, &fileSize)
	binary.Read(r, binary.LittleEndian, &dirBlockStart)
	binary.Read(r, binary.LittleEndian, &parentInodeNumber)
	binary.Read(r, binary.LittleEndian, &indexCount)
	binary.Read(r, binary.LittleEndian, &blockOffset)
	binary.Read(r, binary.LittleEndian, &xattrIdx)

	consumed := uint64(24)

	var indexes []DirIndex
	for i := uint16(0); i < indexCount; i++ {
		var index uint32
		var start uint32
		var nameSize uint32

		binary.Read(r, binary.LittleEndian, &index)
		binary.Read(r, binary.LittleEndian, &start)
		binary.Read(r, binary.LittleEndian, &nameSize)

		name := make([]uint8, nameSize+1)
		binary.Read(r, binary.LittleEndian, &name)

		indexes = append(indexes, DirIndex{
			Index:    index,
			Start:    start,
			NameSize: nameSize,
			Name:     name,
		})

		consumed += 12 + uint64(nameSize+1)
	}

	hdr := ExtendedDirectory{
		HardLinkCount:     hardLinkCount,
		FileSize:          fileSize,
		DirBlockStart:     dirBlockStart,
		ParentInodeNumber: parentInodeNumber,
		IndexCount:        indexCount,
		BlockOffset:       blockOffset,
		XattrIdx:          xattrIdx,
		Index:             indexes,
	}

	return &hdr, consumed
}

func parseDirectoryHeader(offset uint64, data []byte) *DirectoryHeader {
	r := bytes.NewReader(data[offset:])

	var hdr DirectoryHeader
	binary.Read(r, binary.LittleEndian, &hdr.Count)
	binary.Read(r, binary.LittleEndian, &hdr.Start)
	binary.Read(r, binary.LittleEndian, &hdr.InodeNumber)

	return &hdr
}

func parseDirectoryEntry(offset uint64, data []byte) (*DirectoryEntry, uint64) {
	r := bytes.NewReader(data[offset:])

	var entry DirectoryEntry
	binary.Read(r, binary.LittleEndian, &entry.Offset)
	binary.Read(r, binary.LittleEndian, &entry.InodeOffset)
	binary.Read(r, binary.LittleEndian, &entry.Type)
	binary.Read(r, binary.LittleEndian, &entry.NameSize)

	entry.Name = make([]uint8, entry.NameSize+1)
	binary.Read(r, binary.LittleEndian, &entry.Name)

	return &entry, 8 + uint64(entry.NameSize+1)
}

func parseFragmentBlockEntry(offset uint64, data []byte) *FragmentBlockEntry {
	r := bytes.NewReader(data[offset:])

	var entry FragmentBlockEntry
	binary.Read(r, binary.LittleEndian, &entry.Start)
	binary.Read(r, binary.LittleEndian, &entry.Size)
	binary.Read(r, binary.LittleEndian, &entry.Unused)

	return &entry
}

func printFirmwareFile(file *FirmwareFile) {
	fmt.Println("\n=== Firmware File ===")

	fmt.Println("\n--- Start Header ---")
	fmt.Printf("  Magic:             0x%08X\n", file.StartHeader.Magic)
	fmt.Printf("  Firmware Header:   0x%08X\n", file.StartHeader.FirmwareHeader)
	fmt.Printf("  UnknownB:          0x%08X\n", file.StartHeader.UnknownB)
	fmt.Printf("  Flags:             0x%08X\n", file.StartHeader.Flags)
	fmt.Printf("  File System:       0x%08X\n", file.StartHeader.FileSystemHeader)
	fmt.Printf("  File End:          0x%08X\n", file.StartHeader.FileEnd)

	fmt.Println("\n--- Firmware Header ---")
	fmt.Printf("  Magic:             0x%08X\n", file.FirmwareHeader.Magic)
	fmt.Printf("  UnknownA:          0x%08X\n", file.FirmwareHeader.UnknownA)
	fmt.Printf("  UnknownB:          0x%08X\n", file.FirmwareHeader.UnknownB)
	fmt.Printf("  UnknownC:          0x%08X\n", file.FirmwareHeader.UnknownC)
	fmt.Printf("  KernelStart:          0x%08X\n", file.FirmwareHeader.KernelStart)
	fmt.Printf("  UnknownE:          0x%08X\n", file.FirmwareHeader.UnknownE)

	fmt.Println("\n--- Squashfs Header ---")
	fmt.Printf("  Magic:             0x%08X\n", file.SquashFSHeader.Magic)
	fmt.Printf("  Inodes:            %d\n", file.SquashFSHeader.InodeCount)
	fmt.Printf("  Modified:          %s\n", time.Unix(int64(file.SquashFSHeader.ModificationTime), 0))
	fmt.Printf("  Block Size:        %d bytes\n", file.SquashFSHeader.BlockSize)
	fmt.Printf("  Fragments:         %d\n", file.SquashFSHeader.FragmentEntryCount)
	fmt.Printf("  Compression:       %d (4=XZ)\n", file.SquashFSHeader.CompressionID)
	fmt.Printf("  Flags:             0x%04X\n", file.SquashFSHeader.Flags)
	fmt.Printf("  Version:           %d.%d\n", file.SquashFSHeader.VersionMajor, file.SquashFSHeader.VersionMinor)
	fmt.Printf("  Root Inode:        0x%X\n", file.SquashFSHeader.RootInodeRef)
	fmt.Printf("  Bytes Used:        0x%X (%d MB)\n", file.SquashFSHeader.BytesUsed, file.SquashFSHeader.BytesUsed/1024/1024)
	fmt.Printf("  Inode Table:       0x%X\n", uint32(file.SquashFSHeader.InodeTableStart))
	fmt.Printf("  Dir Table:         0x%X\n", uint32(file.SquashFSHeader.DirectoryTableStart))
	fmt.Printf("  Fragment Table:    0x%X\n", uint32(file.SquashFSHeader.FragmentTableStart))
	fmt.Printf("  Export Table:      0x%X\n", uint32(file.SquashFSHeader.ExportTableStart))
	fmt.Printf("  ID Table:          0x%X\n", uint32(file.SquashFSHeader.IDTableStart))

	fmt.Println("\n--- Inodes ---")
	for _, pair := range file.Inodes {
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
	for _, dir := range file.Directories {
		fmt.Printf("  Block 0x%X  InodeRef: %d  Entries: %d\n",
			dir.Header.Start, dir.Header.InodeNumber, dir.Header.Count+1)
		for _, entry := range dir.Entry {
			fmt.Printf("    [type %d] %s  offset=0x%X  inodeOff=%d\n",
				entry.Type, entry.Name, entry.Offset, entry.InodeOffset)
		}
	}

	fmt.Println("\n--- Fragments ---")
	for i, frag := range file.Fragments {
		compressed := (frag.Size & 0x1000000) == 0
		size := frag.Size & 0xFFFFFF
		fmt.Printf("  [%d] Start: 0x%X  Size: 0x%X  Compressed: %v\n", i, frag.Start, size, compressed)
	}

	fmt.Println("\n--- Export Table ---")
	for i, ref := range file.ExportTable.Refs {
		fmt.Printf("  Inode %2d: block=0x%X  offset=0x%X  raw=0x%016X\n",
			i+1, ref.BlockOffset, ref.IntraOffset, file.ExportTable.Raw[i])
	}

	fmt.Println("\n--- ID Table ---")
	if file.IDTable != nil {
		for i, id := range file.IDTable.IDs {
			fmt.Printf("  [%d] ID: %d\n", i, id)
		}
	} else {
		fmt.Println("  (not parsed)")
	}

	fmt.Println("\n--- Xattr Table ---")
	if file.XattrTable != nil {
		var prefixes = map[uint16]string{0: "user.", 1: "trusted.", 2: "security."}

		fmt.Printf("  Xattr Table Start: 0x%X\n", file.XattrTable.IDTable.XattrTableStart)
		fmt.Printf("  Xattr IDs:         %d\n", file.XattrTable.IDTable.XattrIds)

		fmt.Println("\n  Lookup Table:")
		for i, lookup := range file.XattrTable.LookupTable {
			fmt.Printf("    [%d] XattrRef: 0x%016X  Count: %d  Size: %d\n",
				i, lookup.XattrRef, lookup.Count, lookup.Size)
		}

		fmt.Println("\n  Entries:")
		for i, entries := range file.XattrTable.Entries {
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

	filePath := os.Args[1]
	data, err := os.ReadFile(filePath)

	if err != nil {
		fmt.Printf("Error reading file: %v\n", err)
		os.Exit(1)
	}

	// ===========================================
	//                  DAY 1
	// ===========================================

	// I don't know go... BUT I can have AI help me and I have taught lots of programming so this shouldn't be
	// too much of a hurdle.

	// After note: AI Helped a lot with the small differences between languages where I know what I wanted in
	// one language but not in go. Very fun language overall so far (Speaking from day 4)

	// Only started 3 hours after the interview, so 8pm. Finished the day at 12am

	// Where all the parsed results will live
	file := FirmwareFile{}

	file.StartHeader = fill[StartHeader](data, 0x0, binary.BigEndian) // End @ 0x8C
	startHeaderSize := uint32(binary.Size(StartHeader{}))

	metaDataBlockA := parseMetaData(startHeaderSize, file.StartHeader.FirmwareHeader, data)

	file.FirmwareHeader = fill[FirmwareHeader](data, uint64(file.StartHeader.FirmwareHeader), binary.BigEndian)
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

	file.SquashFSHeader = fill[SquashFSHeader](data, uint64(file.StartHeader.FileSystemHeader), binary.LittleEndian)

	// ===========================================
	//                  DAY 3
	// ===========================================

	// Started the day at 5pm, AI was able to greatly speed up the reversing since I had the Squashfs docs.
	// Then all I needed to do was read the docs, create the corresponding structs, and then have AI do some of the more
	// menial refactoring for similar parts (saved me an hour)

	// Finish Squashfs Parsing

	inodeTableStart := uint64(file.StartHeader.FileSystemHeader) + file.SquashFSHeader.InodeTableStart
	dirTableStart := uint64(file.StartHeader.FileSystemHeader) + file.SquashFSHeader.DirectoryTableStart

	inodeData := readSquashFSMetadataBlocks(inodeTableStart, dirTableStart, data)

	offset := uint64(0)
	for i := uint64(0); i < uint64(file.SquashFSHeader.InodeCount); i++ {
		inodeHeader := fill[InodeHeader](inodeData, offset, binary.LittleEndian)
		offset += 16 // uint64(binary.Size(InodeHeader{}))

		switch inodeHeader.InodeType {
		case 8:
			extFile, consumed := parseExtendedDirectory(offset, inodeData)
			offset += consumed

			file.Inodes = append(file.Inodes, InodePair{Header: inodeHeader, Body: extFile})
		case 9:
			extDir, consumed := parseExtendedFile(offset, file.SquashFSHeader.BlockSize, inodeData)
			offset += consumed

			file.Inodes = append(file.Inodes, InodePair{Header: inodeHeader, Body: extDir})
		}
	}

	fragTableStart := uint64(file.StartHeader.FileSystemHeader) + file.SquashFSHeader.FragmentTableStart

	dirData := readSquashFSMetadataBlocks(dirTableStart, fragTableStart, data)

	var extDir *ExtendedDirectory
	for _, inode := range file.Inodes {
		if dir, ok := inode.Body.(*ExtendedDirectory); ok {
			extDir = dir
			break
		}
	}

	if extDir == nil {
		fmt.Println("No extended directory found")
		return
	}

	dirSize := uint64(extDir.FileSize - 3) // spec says FileSize includes 3 extra bytes for virtual . and ..

	// Although we know DirectoryIndex exists, I don't currently need it when parsing file 6 (the ISO we are REing)
	offset = uint64(0)
	for offset < dirSize {
		dirHdr := parseDirectoryHeader(offset, dirData)
		offset += 12 // uint64(binary.Size(DirectoryHeader{}))

		pair := DirectoryPair{
			Header: dirHdr,
			Entry:  []DirectoryEntry{},
		}

		for i := uint32(0); i <= dirHdr.Count; i++ {
			entry, consumed := parseDirectoryEntry(offset, dirData)
			offset += consumed

			pair.Entry = append(pair.Entry, *entry)
		}

		file.Directories = append(file.Directories, pair)
	}

	fragBlockOffset := binary.LittleEndian.Uint64(data[fragTableStart:fragTableStart+8]) + uint64(file.StartHeader.FileSystemHeader)
	fragBlockHeader := binary.LittleEndian.Uint16(data[fragBlockOffset : fragBlockOffset+2])
	fragBlockSize := uint64(fragBlockHeader & 0x7FFF)

	fragData := readSquashFSMetadataBlocks(fragBlockOffset, fragBlockOffset+2+fragBlockSize, data)

	offset = uint64(0)
	for i := uint32(0); i < file.SquashFSHeader.FragmentEntryCount; i++ {
		entry := parseFragmentBlockEntry(offset, fragData)
		offset += 16 // uint64(binary.Size(FragmentBlockEntry{}))
		file.Fragments = append(file.Fragments, *entry)
	}

	exportTableStart := uint64(file.StartHeader.FileSystemHeader) + file.SquashFSHeader.ExportTableStart
	exportBlockOffset := binary.LittleEndian.Uint64(data[exportTableStart:exportTableStart+8]) + uint64(file.StartHeader.FileSystemHeader)
	exportBlockHeader := binary.LittleEndian.Uint16(data[exportBlockOffset : exportBlockOffset+2])
	exportBlockSize := uint64(exportBlockHeader & 0x7FFF)

	exportData := data[exportBlockOffset+2 : exportBlockOffset+2+exportBlockSize]

	file.ExportTable = &ExportTable{}
	for i := 0; i < int(file.SquashFSHeader.InodeCount); i++ {
		inodeRef := binary.LittleEndian.Uint64(exportData[i*8 : i*8+8])
		blockOffset := uint32((inodeRef >> 16) & 0xFFFFFFFF)
		intraOffset := uint16(inodeRef & 0xFFFF)

		file.ExportTable.Raw = append(file.ExportTable.Raw, inodeRef)
		file.ExportTable.Refs = append(file.ExportTable.Refs, InodeRef{
			BlockOffset: blockOffset,
			IntraOffset: intraOffset,
		})
	}

	idTableStart := uint64(file.StartHeader.FileSystemHeader) + file.SquashFSHeader.IDTableStart

	idBlockOffset := binary.LittleEndian.Uint64(data[idTableStart : idTableStart+8])
	idBlockOffset += uint64(file.StartHeader.FileSystemHeader)
	idBlockHeader := binary.LittleEndian.Uint16(data[idBlockOffset : idBlockOffset+2])
	idBlockSize := uint64(idBlockHeader & 0x7FFF)

	idData := data[idBlockOffset+2 : idBlockOffset+2+idBlockSize]

	file.IDTable = &IDTable{}
	for i := 0; i < int(file.SquashFSHeader.IDCount); i++ {
		id := binary.LittleEndian.Uint32(idData[i*4 : i*4+4])
		file.IDTable.IDs = append(file.IDTable.IDs, id)
	}

	xattrTableStart := uint64(file.StartHeader.FileSystemHeader) + file.SquashFSHeader.XattrIDTableStart

	// Parse XattrIDTable
	xattrIDTable := XattrIDTable{
		XattrTableStart: binary.LittleEndian.Uint64(data[xattrTableStart : xattrTableStart+8]),
		XattrIds:        binary.LittleEndian.Uint32(data[xattrTableStart+8 : xattrTableStart+12]),
		Unused:          binary.LittleEndian.Uint32(data[xattrTableStart+12 : xattrTableStart+16]),
	}
	xattrIDTable.XattrTableStart += uint64(file.StartHeader.FileSystemHeader)

	tableBlockCount := (int(xattrIDTable.XattrIds) + 511) / 512
	for i := 0; i < tableBlockCount; i++ {
		ptr := binary.LittleEndian.Uint64(data[xattrTableStart+16+uint64(i*8) : xattrTableStart+16+uint64(i*8)+8])
		ptr += uint64(file.StartHeader.FileSystemHeader)
		xattrIDTable.Table = append(xattrIDTable.Table, ptr)
	}

	// Parse XattrLookupTable entries
	lookupBlockHeader := binary.LittleEndian.Uint16(data[xattrIDTable.Table[0] : xattrIDTable.Table[0]+2])
	lookupBlockSize := uint64(lookupBlockHeader & 0x7FFF)
	lookupData := data[xattrIDTable.Table[0]+2 : xattrIDTable.Table[0]+2+lookupBlockSize]

	var lookupTable []XattrLookupTable
	for i := 0; i < int(xattrIDTable.XattrIds); i++ {
		lookupTable = append(lookupTable, XattrLookupTable{
			XattrRef: binary.LittleEndian.Uint64(lookupData[i*16 : i*16+8]),
			Count:    binary.LittleEndian.Uint32(lookupData[i*16+8 : i*16+12]),
			Size:     binary.LittleEndian.Uint32(lookupData[i*16+12 : i*16+16]),
		})
	}

	// Parse KV metadata block
	kvBlockHeader := binary.LittleEndian.Uint16(data[xattrIDTable.XattrTableStart : xattrIDTable.XattrTableStart+2])
	kvBlockSize := uint64(kvBlockHeader & 0x7FFF)
	kvData := data[xattrIDTable.XattrTableStart+2 : xattrIDTable.XattrTableStart+2+kvBlockSize]

	file.XattrTable = &XattrTable{
		IDTable:     xattrIDTable,
		LookupTable: lookupTable,
	}

	for _, lookup := range lookupTable {
		kvOffset := lookup.XattrRef & 0xFFFF
		pos := kvOffset

		var entries []XattrEntry
		for j := uint32(0); j < lookup.Count; j++ {
			keyType := binary.LittleEndian.Uint16(kvData[pos : pos+2])
			nameSize := binary.LittleEndian.Uint16(kvData[pos+2 : pos+4])
			pos += 4

			key := XattrKeyEntry{
				Type:     keyType,
				NameSize: nameSize,
				Name:     kvData[pos : pos+uint64(nameSize)],
			}
			pos += uint64(nameSize)

			valueSize := binary.LittleEndian.Uint32(kvData[pos : pos+4])
			pos += 4

			value := XattrValueEntry{
				ValueSize: valueSize,
				Value:     kvData[pos : pos+uint64(valueSize)],
			}
			pos += uint64(valueSize)

			outOfLine := (keyType & 0x0100) != 0
			entries = append(entries, XattrEntry{
				Key:       key,
				Value:     value,
				OutOfLine: outOfLine,
			})
		}

		file.XattrTable.Entries = append(file.XattrTable.Entries, entries)
	}

	// ===========================================
	//                  DAY 4
	// ===========================================

	// Getting the files

	printFirmwareFile(&file)
}
