package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/ulikunitz/xz"
)

type SquashFS struct {
	Base        uint64 // absolute offset into data[] where this SquashFS starts
	Header      *SquashFSHeader
	Inodes      []InodePair
	InodeMap    map[uint32]*ExtendedFile
	Directories []DirectoryPair
	NameMap     map[uint32]string
	ParentMap   map[uint32]uint32
	Fragments   []FragmentBlockEntry
	ExportTable *ExportTable
	IDTable     *IDTable
	XattrTable  *XattrTable
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
	XattrIDTableStart   uint64 // Absolute Position (Add SquashFS.Base)
	InodeTableStart     uint64 // Relative Position
	DirectoryTableStart uint64 // Relative Position
	FragmentTableStart  uint64 // Absolute Position (Add SquashFS.Base)
	ExportTableStart    uint64 // Absolute Position (Add SquashFS.Base)
}

type InodeHeader struct {
	InodeType    uint16
	Permissions  uint16
	UIDIdx       uint16
	GIDIdx       uint16
	ModifiedTime uint32
	InodeNumber  uint32
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

type BasicFile struct {
	BlocksStart        uint32
	FragmentBlockIndex uint32
	BlockOffset        uint32
	FileSize           uint32
	BlockSizes         []uint32
}

type BasicDirectory struct {
	DirBlockStart uint32
	HardLinkCount uint32
	FileSize      uint16
	BlockOffset   uint16
	ParentInode   uint32
}

type BasicSymlink struct {
	HardLinkCount uint32
	TargetSize    uint32
	Target        []uint8
}

type ExtendedSymlink struct {
	HardLinkCount uint32
	TargetSize    uint32
	TargetPath    []uint8
	XattrIdx      uint32
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

func readSquashFSMetadataBlocks(start uint64, end uint64, data []byte) []byte {
	var result []byte // Our pool of uncompressed data we return
	offset := start

	if start > end {
		fmt.Printf("  [meta] invalid range: start=0x%X > end=0x%X\n", start, end)
		return result
	}

	for offset < end {
		if offset+2 > uint64(len(data)) {
			fmt.Printf("  [meta] out of bounds at offset=0x%X end=0x%X len=0x%X\n",
				offset, end, len(data))
			break
		}

		// these headers are only 16 bits long (2 bytes)
		header := binary.LittleEndian.Uint16(data[offset : offset+2])
		dataSize := uint64(header & 0x7FFF)
		compressed := (header & 0x8000) == 0
		offset += 2

		if dataSize == 0 || offset+dataSize > uint64(len(data)) {
			fmt.Printf("  [meta] bad block: dataSize=0x%X at offset=0x%X\n", dataSize, offset-2)
			break
		}

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

func parseBasicFile(offset uint64, blockSize uint32, data []byte) (*BasicFile, uint64) {
	r := bytes.NewReader(data[offset:])

	var f BasicFile
	binary.Read(r, binary.LittleEndian, &f.BlocksStart)
	binary.Read(r, binary.LittleEndian, &f.FragmentBlockIndex)
	binary.Read(r, binary.LittleEndian, &f.BlockOffset)
	binary.Read(r, binary.LittleEndian, &f.FileSize)

	var blockCount uint64
	if f.FragmentBlockIndex == 0xFFFFFFFF {
		blockCount = (uint64(f.FileSize) + uint64(blockSize) - 1) / uint64(blockSize)
	} else {
		blockCount = uint64(f.FileSize) / uint64(blockSize)
	}

	f.BlockSizes = make([]uint32, blockCount)
	binary.Read(r, binary.LittleEndian, &f.BlockSizes)

	return &f, 16 + blockCount*4
}

func parseBasicSymlink(offset uint64, data []byte) (*BasicSymlink, uint64) {
	r := bytes.NewReader(data[offset:])

	var s BasicSymlink
	binary.Read(r, binary.LittleEndian, &s.HardLinkCount)
	binary.Read(r, binary.LittleEndian, &s.TargetSize)

	s.Target = make([]uint8, s.TargetSize)
	binary.Read(r, binary.LittleEndian, &s.Target)

	return &s, 8 + uint64(s.TargetSize)
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

// inodeData should start at the start of the Inodes like readSquashFSMetadataBlocks(inodeTableStart, dirTableStart, data)
func decodeInodes(squash *SquashFS, inodeData []byte) {
	offset := uint64(0)
	for i := uint64(0); i < uint64(squash.Header.InodeCount); i++ {
		inodeHeader := fill[InodeHeader](inodeData, offset, binary.LittleEndian)
		offset += 16 // uint64(binary.Size(InodeHeader{}))

		switch inodeHeader.InodeType {
		case 1: // Basic Directory
			extDir := fill[BasicDirectory](inodeData, offset, binary.LittleEndian)
			offset += 16 // uint64(binary.Size(BasicDirectory{}))

			squash.Inodes = append(squash.Inodes, InodePair{Header: inodeHeader, Body: extDir})

		case 2: // Basic File
			extDir, consumed := parseBasicFile(offset, squash.Header.BlockSize, inodeData)
			offset += consumed

			squash.Inodes = append(squash.Inodes, InodePair{Header: inodeHeader, Body: extDir})

		case 3: // Basic Symlink
			extDir, consumed := parseBasicSymlink(offset, inodeData)
			offset += consumed

			squash.Inodes = append(squash.Inodes, InodePair{Header: inodeHeader, Body: extDir})

		case 8: // Extended Directory
			extFile, consumed := parseExtendedDirectory(offset, inodeData)
			offset += consumed

			squash.Inodes = append(squash.Inodes, InodePair{Header: inodeHeader, Body: extFile})

		case 9: // Extended File
			extDir, consumed := parseExtendedFile(offset, squash.Header.BlockSize, inodeData)
			offset += consumed

			squash.Inodes = append(squash.Inodes, InodePair{Header: inodeHeader, Body: extDir})

		case 10: // Extended Symlink
			r := bytes.NewReader(inodeData[offset:])
			var s ExtendedSymlink
			binary.Read(r, binary.LittleEndian, &s.HardLinkCount)
			binary.Read(r, binary.LittleEndian, &s.TargetSize)

			s.TargetPath = make([]uint8, s.TargetSize)

			binary.Read(r, binary.LittleEndian, &s.TargetPath)
			binary.Read(r, binary.LittleEndian, &s.XattrIdx)
			offset += 12 + uint64(s.TargetSize)
			squash.Inodes = append(squash.Inodes, InodePair{Header: inodeHeader, Body: &s})

		default:
			fmt.Printf(
				"  [inodes] WARNING: unknown inode type %d at offset=0x%X inode=%d, stopping\n",
				inodeHeader.InodeType, offset-16, i,
			)
		}
	}

	for _, pair := range squash.Inodes {
		if ext, ok := pair.Body.(*ExtendedFile); ok {
			squash.InodeMap[pair.Header.InodeNumber] = ext
		}
	}
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

func decodeDirectories(squash *SquashFS, dirData []byte) {
	dirSize := uint64(len(dirData))
	for _, inode := range squash.Inodes {
		switch body := inode.Body.(type) {
		case *ExtendedDirectory:
			if body.FileSize > 3 {
				dirSize = uint64(body.FileSize - 3) // spec says FileSize includes 3 extra bytes for virtual . and ..
			}
		case *BasicDirectory:
			if body.FileSize > 3 {
				dirSize = uint64(body.FileSize - 3) // spec says FileSize includes 3 extra bytes for virtual . and ..
			}
		}
		break // still just using the first directory inode as the bound
	}

	// Although we know DirectoryIndex exists, I don't currently need it when parsing file 6 (the ISO we are REing)
	offset := uint64(0)
	for offset+12 <= uint64(len(dirData)) {
		dirHdr := parseDirectoryHeader(offset, dirData)
		offset += 12 // uint64(binary.Size(DirectoryHeader{}))

		if dirHdr.Count > 256 {
			break
		}

		pair := DirectoryPair{
			Header: dirHdr,
			Entry:  []DirectoryEntry{},
		}

		for i := uint32(0); i <= dirHdr.Count; i++ {
			if offset+8 > uint64(len(dirData)) {
				break
			}

			entry, consumed := parseDirectoryEntry(offset, dirData)
			offset += consumed

			pair.Entry = append(pair.Entry, *entry)
		}

		squash.Directories = append(squash.Directories, pair)

		if offset >= dirSize {
			break
		}
	}

	// Build filename map from directory entries (inodeNumber -> name)
	for _, dir := range squash.Directories {
		for _, entry := range dir.Entry {
			inodeNum := uint32(int32(dir.Header.InodeNumber) + int32(entry.InodeOffset))
			squash.NameMap[inodeNum] = string(entry.Name)
		}
	}

	// Build ParentMap by matching directory inodes to their directory table entries
	// via DirBlockStart + BlockOffset, then linking each child entry to that dir inode
	for i := range squash.Inodes {
		pair := &squash.Inodes[i]
		dirInodeNum := pair.Header.InodeNumber

		var dirBlockStart uint32
		var blockOffset uint16
		switch body := pair.Body.(type) {
		case *BasicDirectory:
			dirBlockStart = body.DirBlockStart
			blockOffset = body.BlockOffset
		case *ExtendedDirectory:
			dirBlockStart = body.DirBlockStart
			blockOffset = body.BlockOffset
		default:
			continue
		}

		for _, dir := range squash.Directories {
			if dir.Header.Start != dirBlockStart {
				continue
			}
			for _, entry := range dir.Entry {
				if entry.Offset < blockOffset {
					continue
				}
				childInodeNum := uint32(
					int32(dir.Header.InodeNumber) + int32(entry.InodeOffset),
				)
				squash.ParentMap[childInodeNum] = dirInodeNum
			}
		}
	}
}

func parseFragmentBlockEntry(offset uint64, data []byte) *FragmentBlockEntry {
	r := bytes.NewReader(data[offset:])

	var entry FragmentBlockEntry
	binary.Read(r, binary.LittleEndian, &entry.Start)
	binary.Read(r, binary.LittleEndian, &entry.Size)
	binary.Read(r, binary.LittleEndian, &entry.Unused)

	return &entry
}

func decodeFragments(squash *SquashFS, fragData []byte) {
	offset := uint64(0)
	for i := uint32(0); i < squash.Header.FragmentEntryCount; i++ {
		entry := parseFragmentBlockEntry(offset, fragData)
		offset += 16 // uint64(binary.Size(FragmentBlockEntry{}))
		squash.Fragments = append(squash.Fragments, *entry)
	}
}

func decodeExportTable(squash *SquashFS, exportData []byte) {
	squash.ExportTable = &ExportTable{}

	maxEntries := len(exportData) / 8
	count := int(squash.Header.InodeCount)
	if count > maxEntries {
		fmt.Printf(
			"  [export] WARNING: InodeCount=%d but exportData only has %d entries, clamping\n",
			count, maxEntries,
		)
		count = maxEntries
	}

	for i := 0; i < count; i++ {
		inodeRef := binary.LittleEndian.Uint64(exportData[i*8 : i*8+8])
		blockOffset := uint32((inodeRef >> 16) & 0xFFFFFFFF)
		intraOffset := uint16(inodeRef & 0xFFFF)

		squash.ExportTable.Raw = append(squash.ExportTable.Raw, inodeRef)
		squash.ExportTable.Refs = append(squash.ExportTable.Refs, InodeRef{
			BlockOffset: blockOffset,
			IntraOffset: intraOffset,
		})
	}
}

func decodeIDTable(squash *SquashFS, idData []byte) {
	squash.IDTable = &IDTable{}
	for i := 0; i < int(squash.Header.IDCount); i++ {
		id := binary.LittleEndian.Uint32(idData[i*4 : i*4+4])
		squash.IDTable.IDs = append(squash.IDTable.IDs, id)
	}
}

// Here, data is just the entire byte array, not relative to any position
func decodeXattrTable(squash *SquashFS, data []byte, xattrTableStart uint64) {
	xattrIDTable := XattrIDTable{
		XattrTableStart: binary.LittleEndian.Uint64(data[xattrTableStart : xattrTableStart+8]),
		XattrIds:        binary.LittleEndian.Uint32(data[xattrTableStart+8 : xattrTableStart+12]),
		Unused:          binary.LittleEndian.Uint32(data[xattrTableStart+12 : xattrTableStart+16]),
	}
	xattrIDTable.XattrTableStart += squash.Base

	tableBlockCount := (int(xattrIDTable.XattrIds) + 511) / 512
	for i := 0; i < tableBlockCount; i++ {
		ptr := binary.LittleEndian.Uint64(data[xattrTableStart+16+uint64(i*8) : xattrTableStart+16+uint64(i*8)+8])
		ptr += squash.Base
		xattrIDTable.Table = append(xattrIDTable.Table, ptr)
	}

	lookupData := readSquashFSMetadataBlocks(
		xattrIDTable.Table[0],
		xattrIDTable.Table[len(xattrIDTable.Table)-1]+2+8192, // at most one 8KiB block past last pointer
		data,
	)

	var lookupTable []XattrLookupTable
	for i := 0; i < int(xattrIDTable.XattrIds); i++ {
		base := i * 16
		lookupTable = append(lookupTable, XattrLookupTable{
			XattrRef: binary.LittleEndian.Uint64(lookupData[base : base+8]),
			Count:    binary.LittleEndian.Uint32(lookupData[base+8 : base+12]),
			Size:     binary.LittleEndian.Uint32(lookupData[base+12 : base+16]),
		})
	}

	fmt.Printf("  [xattr] XattrTableStart=0x%X Table[0]=0x%X xattrTableStart=0x%X\n",
		xattrIDTable.XattrTableStart,
		xattrIDTable.Table[0],
		xattrTableStart,
	)

	kvData := readSquashFSMetadataBlocks(
		xattrIDTable.XattrTableStart,
		xattrIDTable.Table[0], // end at the lookup table, not the ID table header
		data,
	)

	squash.XattrTable = &XattrTable{
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

			if pos+uint64(nameSize) > uint64(len(kvData)) {
				fmt.Printf("  [xattr] out of bounds reading key name at pos=0x%X nameSize=%d len=%d\n",
					pos, nameSize, len(kvData))
				break
			}

			key := XattrKeyEntry{
				Type:     keyType,
				NameSize: nameSize,
				Name:     kvData[pos : pos+uint64(nameSize)],
			}
			pos += uint64(nameSize)

			if pos+4 > uint64(len(kvData)) {
				fmt.Printf("  [xattr] out of bounds reading value size at pos=0x%X\n", pos)
				break
			}
			valueSize := binary.LittleEndian.Uint32(kvData[pos : pos+4])
			pos += 4

			if pos+uint64(valueSize) > uint64(len(kvData)) {
				fmt.Printf("  [xattr] out of bounds reading value at pos=0x%X valueSize=%d len=%d\n",
					pos, valueSize, len(kvData))
				break
			}
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

		squash.XattrTable.Entries = append(squash.XattrTable.Entries, entries)
	}
}

func extractFiles(squash *SquashFS, data []byte, outputDir string) error {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output dir: %w", err)
	}

	// Find root inode number via RootInodeRef
	rootBlockOffset := uint32((squash.Header.RootInodeRef >> 16) & 0xFFFFFFFF)
	rootIntraOffset := uint16(squash.Header.RootInodeRef & 0xFFFF)
	rootInode := uint32(1) // fallback

	if squash.ExportTable != nil {
		for i := range squash.Inodes {
			pair := &squash.Inodes[i]
			idx := int(pair.Header.InodeNumber) - 1
			if idx < 0 || idx >= len(squash.ExportTable.Refs) {
				continue
			}
			ref := squash.ExportTable.Refs[idx]
			if ref.BlockOffset == rootBlockOffset && ref.IntraOffset == rootIntraOffset {
				rootInode = pair.Header.InodeNumber
				break
			}
		}
	}

	fsBase := squash.Base

	for _, pair := range squash.Inodes {

		inodeNum := pair.Header.InodeNumber

		// Build full relative path by walking ParentMap up to root
		var parts []string
		visited := make(map[uint32]bool)
		cur := inodeNum
		for cur != rootInode {
			if visited[cur] {
				break
			}
			visited[cur] = true
			name, ok := squash.NameMap[cur]
			if !ok {
				name = fmt.Sprintf("inode_%d", cur)
			}
			parts = append(parts, name)
			parent, ok := squash.ParentMap[cur]
			if !ok || parent == cur {
				break
			}
			cur = parent
		}

		for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
			parts[i], parts[j] = parts[j], parts[i]
		}

		relPath := filepath.Join(parts...)
		if relPath == "" {
			continue
		}
		outPath := filepath.Join(outputDir, relPath)

		switch body := pair.Body.(type) {
		case *ExtendedFile:
			if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
				return fmt.Errorf("failed to create dirs for %s: %w", relPath, err)
			}
			fmt.Printf("Extracting %s (%d bytes)...\n", relPath, body.FileSize)

			outFile, err := os.Create(outPath)
			if err != nil {
				return fmt.Errorf("failed to create %s: %w", relPath, err)
			}

			written := uint64(0)
			blockOffset := fsBase + body.BlocksStart

			// Write full data blocks
			for _, blockSize := range body.BlockSizes {
				if written >= body.FileSize {
					break
				}

				uncompressed := (blockSize & (1 << 24)) != 0
				size := uint64(blockSize & 0xFFFFFF)

				var blockData []byte

				if size == 0 {
					blockData = make([]byte, squash.Header.BlockSize)
				} else if uncompressed {
					blockData = data[blockOffset : blockOffset+size]
				} else {
					xzReader, err := xz.NewReader(bytes.NewReader(data[blockOffset : blockOffset+size]))
					if err != nil {
						outFile.Close()
						return fmt.Errorf("xz reader error for %s: %w", relPath, err)
					}
					blockData, err = io.ReadAll(xzReader)
					if err != nil {
						outFile.Close()
						return fmt.Errorf("xz decompress error for %s: %w", relPath, err)
					}
				}

				// Don't write past FileSize
				remaining := body.FileSize - written
				if uint64(len(blockData)) > remaining {
					blockData = blockData[:remaining]
				}

				if _, err := outFile.Write(blockData); err != nil {
					outFile.Close()
					return fmt.Errorf("write error for %s: %w", relPath, err)
				}

				written += uint64(len(blockData))
				blockOffset += size
			}

			// Write fragment tail if present
			if body.FragmentBlockIndex != 0xFFFFFFFF && written < body.FileSize {
				frag := squash.Fragments[body.FragmentBlockIndex]
				fragUncompressed := (frag.Size & (1 << 24)) != 0
				fragSize := uint64(frag.Size & 0xFFFFFF)
				fragStart := frag.Start + fsBase

				var fragData []byte
				if fragUncompressed {
					fragData = data[fragStart : fragStart+fragSize]
				} else {
					xzReader, err := xz.NewReader(bytes.NewReader(data[fragStart : fragStart+fragSize]))
					if err != nil {
						outFile.Close()
						return fmt.Errorf("xz reader error for fragment %s: %w", relPath, err)
					}
					fragData, err = io.ReadAll(xzReader)
					if err != nil {
						outFile.Close()
						return fmt.Errorf("xz decompress error for fragment %s: %w", relPath, err)
					}
				}

				fragSlice := fragData[body.BlockOffset:]
				remaining := body.FileSize - written
				if uint64(len(fragSlice)) > remaining {
					fragSlice = fragSlice[:remaining]
				}

				if _, err := outFile.Write(fragSlice); err != nil {
					outFile.Close()
					return fmt.Errorf("write error for fragment %s: %w", relPath, err)
				}
			}

			outFile.Close()
			fmt.Printf("  Done: %s\n", outPath)

		case *BasicFile:
			if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
				return fmt.Errorf("failed to create dirs for %s: %w", relPath, err)
			}
			fmt.Printf("Extracting basic file %s (%d bytes)...\n", relPath, body.FileSize)

			outFile, err := os.Create(outPath)
			if err != nil {
				return fmt.Errorf("failed to create %s: %w", relPath, err)
			}

			written := uint32(0)
			blockOffset := fsBase + uint64(body.BlocksStart)

			for _, blockSize := range body.BlockSizes {
				if written >= body.FileSize {
					break
				}

				uncompressed := (blockSize & (1 << 24)) != 0
				size := uint64(blockSize & 0xFFFFFF)

				var blockData []byte
				if size == 0 {
					blockData = make([]byte, squash.Header.BlockSize)
				} else if uncompressed {
					blockData = data[blockOffset : blockOffset+size]
				} else {
					xzReader, err := xz.NewReader(
						bytes.NewReader(data[blockOffset : blockOffset+size]),
					)
					if err != nil {
						outFile.Close()
						return fmt.Errorf("xz reader error for %s: %w", relPath, err)
					}
					blockData, err = io.ReadAll(xzReader)
					if err != nil {
						outFile.Close()
						return fmt.Errorf("xz decompress error for %s: %w", relPath, err)
					}
				}

				remaining := uint64(body.FileSize - written)
				if uint64(len(blockData)) > remaining {
					blockData = blockData[:remaining]
				}

				if _, err := outFile.Write(blockData); err != nil {
					outFile.Close()
					return fmt.Errorf("write error for %s: %w", relPath, err)
				}

				written += uint32(len(blockData))
				blockOffset += size
			}

			if body.FragmentBlockIndex != 0xFFFFFFFF && written < body.FileSize {
				frag := squash.Fragments[body.FragmentBlockIndex]
				fragUncompressed := (frag.Size & (1 << 24)) != 0
				fragSize := uint64(frag.Size & 0xFFFFFF)
				fragStart := frag.Start + fsBase

				var fragData []byte
				if fragUncompressed {
					fragData = data[fragStart : fragStart+fragSize]
				} else {
					xzReader, err := xz.NewReader(
						bytes.NewReader(data[fragStart : fragStart+fragSize]),
					)
					if err != nil {
						outFile.Close()
						return fmt.Errorf("xz reader error for fragment %s: %w", relPath, err)
					}
					fragData, err = io.ReadAll(xzReader)
					if err != nil {
						outFile.Close()
						return fmt.Errorf("xz decompress error for fragment %s: %w", relPath, err)
					}
				}

				fragSlice := fragData[body.BlockOffset:]
				remaining := uint64(body.FileSize - written)
				if uint64(len(fragSlice)) > remaining {
					fragSlice = fragSlice[:remaining]
				}

				if _, err := outFile.Write(fragSlice); err != nil {
					outFile.Close()
					return fmt.Errorf("write error for fragment %s: %w", relPath, err)
				}
			}

			outFile.Close()
			fmt.Printf("  Done: %s\n", outPath)

		case *BasicSymlink:
			fmt.Printf("Extracting symlink %s -> %s\n", relPath, string(body.Target))

			if err := os.Symlink(string(body.Target), outPath); err != nil {
				// Don't fatal — symlinks may already exist or target may be missing
				fmt.Printf("  WARNING: symlink failed for %s: %v\n", relPath, err)
			}

		case *ExtendedSymlink:
			fmt.Printf("Extracting extended symlink %s -> %s\n", relPath, string(body.TargetPath))
			if err := os.Symlink(string(body.TargetPath), outPath); err != nil {
				fmt.Printf("  WARNING: symlink failed for %s: %v\n", relPath, err)
			}

		case *BasicDirectory, *ExtendedDirectory:
			if err := os.MkdirAll(outPath, 0755); err != nil {
				return fmt.Errorf("failed to create directory %s: %w", outPath, err)
			}

		default:
			fmt.Printf("  Skipping inode %d (%s): unsupported type %T\n",
				inodeNum, relPath, pair.Body)
		}
	}

	return nil
}

func parseSquashFS(data []byte, fsBase uint64) (*SquashFS, error) {
	squash := &SquashFS{
		Base:      fsBase,
		InodeMap:  make(map[uint32]*ExtendedFile),
		NameMap:   make(map[uint32]string),
		ParentMap: make(map[uint32]uint32),
	}

	squash.Header = fill[SquashFSHeader](data, squash.Base, binary.LittleEndian)

	fmt.Printf("  [sqfs raw] InodeTableStart=0x%X DirTableStart=0x%X FragTableStart=0x%X\n",
		squash.Header.InodeTableStart,
		squash.Header.DirectoryTableStart,
		squash.Header.FragmentTableStart,
	)
	fmt.Printf("  [sqfs raw] ExportTableStart=0x%X IDTableStart=0x%X XattrTableStart=0x%X\n",
		squash.Header.ExportTableStart,
		squash.Header.IDTableStart,
		squash.Header.XattrIDTableStart,
	)
	fmt.Printf("  [sqfs raw] base=0x%X dataLen=0x%X\n",
		squash.Base, uint64(len(data)),
	)

	fmt.Printf("  [sqfs header] base=0x%X compression=%d flags=0x%04X inodes=%d\n",
		squash.Base,
		squash.Header.CompressionID,
		squash.Header.Flags,
		squash.Header.InodeCount,
	)
	fmt.Printf("  [sqfs tables] inodeTable=0x%X dirTable=0x%X fragTable=0x%X\n",
		squash.Header.InodeTableStart, squash.Header.DirectoryTableStart, squash.Header.FragmentTableStart,
	)

	if squash.Header.Magic != 0x73717368 {
		return nil, fmt.Errorf("not a squashfs image at 0x%X (magic=0x%08X)",
			squash.Base, squash.Header.Magic)
	}

	inodeTableStart := squash.Base + squash.Header.InodeTableStart
	dirTableStart := squash.Base + squash.Header.DirectoryTableStart
	fragTableStart := squash.Base + squash.Header.FragmentTableStart
	exportTableStart := squash.Base + squash.Header.ExportTableStart
	idTableStart := squash.Base + squash.Header.IDTableStart
	xattrTableStart := squash.Base + squash.Header.XattrIDTableStart

	//fragBlockOffset := binary.LittleEndian.Uint64(data[fragTableStart:fragTableStart+8]) + squash.Base
	//fragBlockHeader := binary.LittleEndian.Uint16(data[fragBlockOffset : fragBlockOffset+2])
	//fragBlockSize := uint64(fragBlockHeader & 0x7FFF)

	fragPtrCount := int(squash.Header.FragmentEntryCount+511) / 512
	var fragBlockOffsets []uint64
	for i := 0; i < fragPtrCount; i++ {
		ptr := binary.LittleEndian.Uint64(
			data[fragTableStart+uint64(i*8):fragTableStart+uint64(i*8)+8],
		) + fsBase
		fragBlockOffsets = append(fragBlockOffsets, ptr)
	}

	var fragData []byte
	for i, ptr := range fragBlockOffsets {
		var end uint64
		if i+1 < len(fragBlockOffsets) {
			end = fragBlockOffsets[i+1]
		} else {
			// Last block: read header to get its size
			hdr := binary.LittleEndian.Uint16(data[ptr : ptr+2])
			end = ptr + 2 + uint64(hdr&0x7FFF)
		}
		fragData = append(fragData, readSquashFSMetadataBlocks(ptr, end, data)...)
	}

	exportPtrCount := (int(squash.Header.InodeCount) + 1023) / 1024
	var exportBlockOffsets []uint64
	for i := 0; i < exportPtrCount; i++ {
		ptr := binary.LittleEndian.Uint64(
			data[exportTableStart+uint64(i*8):exportTableStart+uint64(i*8)+8],
		) + fsBase
		exportBlockOffsets = append(exportBlockOffsets, ptr)
	}

	var exportData []byte
	for i, ptr := range exportBlockOffsets {
		var end uint64
		if i+1 < len(exportBlockOffsets) {
			end = exportBlockOffsets[i+1]
		} else {
			hdr := binary.LittleEndian.Uint16(data[ptr : ptr+2])
			end = ptr + 2 + uint64(hdr&0x7FFF)
		}
		exportData = append(exportData, readSquashFSMetadataBlocks(ptr, end, data)...)
	}

	idPtrCount := (int(squash.Header.IDCount) + 2047) / 2048
	var idBlockOffsets []uint64
	for i := 0; i < idPtrCount; i++ {
		ptr := binary.LittleEndian.Uint64(
			data[idTableStart+uint64(i*8):idTableStart+uint64(i*8)+8],
		) + fsBase
		idBlockOffsets = append(idBlockOffsets, ptr)
	}

	var idData []byte
	for i, ptr := range idBlockOffsets {
		var end uint64
		if i+1 < len(idBlockOffsets) {
			end = idBlockOffsets[i+1]
		} else {
			hdr := binary.LittleEndian.Uint16(data[ptr : ptr+2])
			end = ptr + 2 + uint64(hdr&0x7FFF)
		}
		idData = append(idData, readSquashFSMetadataBlocks(ptr, end, data)...)
	}

	//exportBlockOffset := binary.LittleEndian.Uint64(data[exportTableStart:exportTableStart+8]) + squash.Base
	//idBlockOffset := binary.LittleEndian.Uint64(data[idTableStart:idTableStart+8]) + squash.Base

	inodeData := readSquashFSMetadataBlocks(inodeTableStart, dirTableStart, data)
	dirData := readSquashFSMetadataBlocks(dirTableStart, fragTableStart, data)
	//fragData := readSquashFSMetadataBlocks(fragBlockOffset, fragBlockOffset+2+fragBlockSize, data) // Something is wrong? I didn;t change this like i changed export and id
	//exportData := readSquashFSMetadataBlocks(exportBlockOffset, idTableStart, data)
	//idData := readSquashFSMetadataBlocks(idBlockOffset, xattrTableStart, data)

	decodeInodes(squash, inodeData)

	decodeDirectories(squash, dirData)

	decodeFragments(squash, fragData)

	decodeExportTable(squash, exportData)

	decodeIDTable(squash, idData)

	decodeXattrTable(squash, data, xattrTableStart)

	return squash, nil
}
