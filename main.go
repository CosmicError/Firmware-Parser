package main

// Test items: https://drive.google.com/drive/folders/1_TtBnqGhBP7Ss-FFxzW18fjrFbFRl86x

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"time"
)

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

type FirmwareHeader struct {
	Magic     uint32   // 0x00, 4 bytes
	Signature [48]byte // 0x04, 48 bytes
	Padding   uint32   // 0x34, 4 bytes (00 00 00 00)
	Anchor    [8]byte  // 0x38, 8 bytes (DE AD BE EF DE AD BE EF)
	UnknownA  uint32   // 0x40, 4 bytes (00 00 04 0C)
	UnknownB  uint32   // 0x44, 4 bytes (00 00 75 30)
	UnknownC  uint32   // 0x48, 4 bytes (00 00 00 00)
	UnknownD  uint32   // 0x4C, 4 bytes (02 7D 88 F9)
	UnknownE  uint32   // 0x50, 4 bytes, FileEnd for the Start Header
	NullPad   [56]byte // 0x54, 56 bytes
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
	XattrIDTableStart   uint64
	InodeTableStart     uint64
	DirectoryTableStart uint64
	FragmentTableStart  uint64
	ExportTableStart    uint64
}

type TLV struct {
	Tag    uint32
	Length uint32
	Value  []byte
}

//type TLVBlock struct {
//	Start     uint32
//	BlockType uint32
//	TLVs      []TLV
//	End       uint32
//}
//
//type UnknownBlock struct {
//	BlockType uint32
//	DataA     []byte
//	TLVs      []TLV
//}

type MetaDataBlock struct {
	BlockType uint32
	TLVs      []TLV
	Start     uint32
	End       uint32

	// Compact block fields
	IsCompact bool
	DataA     []byte

	// Sub blocks
	SubBlocks []*MetaDataBlock
}

func parseStartHeader(start uint32, data []byte) *StartHeader {
	r := bytes.NewReader(data[start:])
	var hdr StartHeader
	_ = binary.Read(r, binary.BigEndian, &hdr)

	fmt.Println("=== Start Header ===")
	fmt.Printf("Magic:     			0x%08X\n", hdr.Magic)
	fmt.Printf("Signature: 			0x%08X\n", hdr.Signature)
	fmt.Printf("Firmware Header: 	0x%08X\n", hdr.FirmwareHeader)
	fmt.Printf("UnknownB:			0x%08X\n", hdr.UnknownB)
	fmt.Printf("Flags: 				0x%08X\n", hdr.Flags)
	fmt.Printf("File System: 		0x%08X\n", hdr.FileSystemHeader)
	fmt.Printf("File End:			0x%08X\n", hdr.FileEnd)

	return &hdr
}

func parseSquashFSHeader(start uint32, data []byte) *SquashFSHeader {

	r := bytes.NewReader(data[start:])
	var hdr SquashFSHeader
	_ = binary.Read(r, binary.LittleEndian, &hdr)

	fmt.Println("\n=== SquashFS Header ===")
	fmt.Printf("Magic:          0x%08X\n", hdr.Magic)
	fmt.Printf("Inodes:         %d\n", hdr.InodeCount)
	fmt.Printf("Modified:       %s\n", time.Unix(int64(hdr.ModificationTime), 0))
	fmt.Printf("Block Size:     %d bytes\n", hdr.BlockSize)
	fmt.Printf("Fragments:      %d\n", hdr.FragmentEntryCount)
	fmt.Printf("Compression:    %d (4=XZ)\n", hdr.CompressionID)
	fmt.Printf("Block Log:      %d\n", hdr.BlockLog)
	fmt.Printf("Flags:          0x%04X\n", hdr.Flags)
	fmt.Printf("Version:        %d.%d\n", hdr.VersionMajor, hdr.VersionMinor)
	fmt.Printf("Root Inode:     0x%X\n", hdr.RootInodeRef)
	fmt.Printf("Bytes Used:     0x%X (%d MB)\n", hdr.BytesUsed, hdr.BytesUsed/1024/1024)
	fmt.Printf("Inode Table:    0x%X\n", start+uint32(hdr.InodeTableStart))
	fmt.Printf("Dir Table:      0x%X\n", start+uint32(hdr.DirectoryTableStart))
	fmt.Printf("Fragment Table: 0x%X\n", start+uint32(hdr.FragmentTableStart))
	fmt.Printf("Export Table:   0x%X\n", start+uint32(hdr.ExportTableStart))
	fmt.Printf("ID Table:       0x%X\n", start+uint32(hdr.IDTableStart))

	return &hdr
}

func parseFirmwareHeader(start uint32, data []byte) *FirmwareHeader {
	r := bytes.NewReader(data[start:])
	var hdr FirmwareHeader
	_ = binary.Read(r, binary.BigEndian, &hdr)

	fmt.Println("\n=== Firmware Header ===")
	fmt.Printf("Magic:		0x%08X\n", hdr.Magic)
	fmt.Printf("Signature:	0x%08X\n", hdr.Signature)
	fmt.Printf("UnknownA:	0x%08X\n", hdr.UnknownA)
	fmt.Printf("UnknownB:	0x%08X\n", hdr.UnknownB)
	fmt.Printf("UnknownC:	0x%08X\n", hdr.UnknownC)
	fmt.Printf("UnknownD:	0x%08X\n", hdr.UnknownD)
	fmt.Printf("UnknownE:	0x%08X\n", hdr.UnknownE)
	fmt.Printf("NullPad:	0x%08X\n", hdr.NullPad)

	return &hdr
}

//func parseTLVBlock(start uint32, length uint32, data []byte) *TLVBlock {
//	block := TLVBlock{
//		Start:     start,
//		BlockType: binary.BigEndian.Uint32(data[start : start+0x4]),
//		TLVs:      []TLV{},
//		End:       start,
//	}
//
//	// Get the TLV's
//	block.End += 0x4 // skip over the blockType
//	for block.End < start+length {
//		tag := binary.BigEndian.Uint32(data[block.End : block.End+0x4])
//		block.End += 0x4
//		tlvLen := binary.BigEndian.Uint32(data[block.End : block.End+0x4])
//		block.End += 0x4
//
//		tlv := TLV{
//			Tag:    tag,
//			Length: tlvLen,
//			Value:  data[block.End : block.End+tlvLen],
//		}
//
//		block.TLVs = append(block.TLVs, tlv)
//		// move pointer to end of TLV
//		block.End += tlv.Length
//
//
//		if block.End%0x4 != 0 {
//			block.End += 0x4 - block.End%0x4
//		}
//	}
//
//	fmt.Printf("Block Type?: %X\n", block.BlockType)
//	for _, tlv := range block.TLVs {
//		fmt.Printf("Tag: 0x%X  Length: %d  Value: %s\n", tlv.Tag, tlv.Length, tlv.Value)
//	}
//
//	return &block
//}
//
//func parseCompactTLVBlock(start uint32, length uint32, data []byte) uint32 {
//	pointer := start
//
//	block := UnknownBlock{
//		BlockType: binary.BigEndian.Uint32(data[pointer : pointer+0x4]),
//		DataA:     data[pointer+0x4 : start+0x4+0x13],
//		TLVs:      []TLV{},
//	}
//
//	pointer += 0x4 + 0x13 // unknown 13 bytes
//
//	for pointer < start+length {
//		tag := uint32(data[pointer])
//		tlvLen := uint32(binary.BigEndian.Uint16(data[pointer+0x1 : pointer+0x3]))
//
//		tlv := TLV{
//			Tag:    tag,
//			Length: tlvLen,
//			Value:  data[pointer+0x3 : pointer+0x3+tlvLen],
//		}
//
//		block.TLVs = append(block.TLVs, tlv)
//		// move pointer to end of TLV
//		pointer += 0x3 + tlv.Length
//	}
//
//	fmt.Printf("Block Type?: %X\n", block.BlockType)
//	fmt.Println("UnknownData: ")
//	for i, b := range block.DataA {
//		if i%16 == 0 && i != 0 {
//			fmt.Printf("\n")
//		}
//
//		fmt.Printf("%X ", b)
//	}
//	fmt.Printf("\n\n")
//	for _, tlv := range block.TLVs {
//		fmt.Printf("Tag: 0x%X  Length: %d  Value: %s\n", tlv.Tag, tlv.Length, tlv.Value)
//	}
//
//	return pointer
//}

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

		fmt.Printf("Tag: 0x%08X\tLength: 0x%08X\tValue: 0x%s\n", tlv.Tag, tlv.Length, tlv.Value)

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
		//fmt.Printf("pos: 0x%X  bytes: % X\n", compactBlock.End, data[compactBlock.End:compactBlock.End+0x5])

		fmt.Printf("Tag: 0x%08X\tLength: 0x%08X\tValue: 0x%s\n", tlv.Tag, tlv.Length, tlv.Value)

		if bytes.Equal(data[compactBlock.End:compactBlock.End+0x5], compactBlockEnd) {
			// this is a correction. idk what these 5 bytes do, but they are
			// consistent and always before the firmware so...
			compactBlock.End += 0x5
			break
		}
	}

	block.SubBlocks = append(block.SubBlocks, &compactBlock)
	block.End = compactBlock.End

	return &block
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

	startHeader := parseStartHeader(0x0, data) // End @ 0x8C
	startHeaderSize := uint32(binary.Size(StartHeader{}))

	fmt.Println("\n====================")
	metaDataBlockA := parseMetaData(startHeaderSize, startHeader.FirmwareHeader, data)
	parseFirmwareHeader(startHeader.FirmwareHeader, data)
	firmwareHeaderASize := uint32(binary.Size(FirmwareHeader{}))

	//fmt.Printf("0x%08X, 0x%08X\n", metaDataBlockA.End, firmwareHeaderASize)
	fmt.Println("\n====================")
	parseMetaData(metaDataBlockA.End+firmwareHeaderASize, 0x80E, data)

	// another header, most likely a firmware header too, just slightly different
	// because it has a message
	//firmwareHeaderB := parseFirmwareHeader(startHeader.FirmwareHeader, data)
	//firmwareHeaderBSize := uint32(binary.Size(firmwareHeaderA))

	// ok now no more easy headers :(

	parseSquashFSHeader(startHeader.FileSystemHeader, data)

	//i = 0xA00 // Next block, skipping mass nulls

	fmt.Println()
	fmt.Printf("Successfully read %d bytes from %s\n", len(data), filePath)
}
