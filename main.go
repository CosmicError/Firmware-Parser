package main

// Test items: https://drive.google.com/drive/folders/1_TtBnqGhBP7Ss-FFxzW18fjrFbFRl86x

import (
	"bytes"
	"path/filepath"

	"encoding/binary"
	"fmt"
	"os"
	"runtime/debug"
)

type FirmwareFile struct {
	Live       *LiveHeader
	Upgrade    *UpgradeHeader
	MBR        *MBR
	Kernel     *Kernel
	BootStub   []byte
	Initramfs  *Initramfs
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

type TLV struct {
	Tag    uint32
	Length uint32
	Value  []byte
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

type Kernel struct {
	Header *KernelHeader
	Data   []byte
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

type Initramfs struct {
	Data  []byte
	Start uint64
	End   uint64
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
			// consistent and always before the firmware so im assuming they are a sentinel.
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

func extractInitramfs(data []byte, start, end uint64, outputPath string) error {
	raw := data[start:end]

	outFile := outputPath + "\\initramfs.cpio"
	if err := os.WriteFile(outFile, raw, 0644); err != nil {
		return fmt.Errorf("write initramfs: %w", err)
	}

	fmt.Printf("  Initramfs written to %s (%d KB)\n", outFile, len(raw)/1024)
	return nil
}

func main() {
	//===========================================
	//                 DAY 1
	//===========================================
	//
	//I don't know go... BUT I can have AI help me and I have taught lots of programming so this shouldn't be
	//too much of a hurdle.
	//
	//After note: AI Helped a lot with the small differences between languages where I know what I wanted in
	//one language but not in go. Very fun language overall so far (Speaking from day 4)
	//
	//Only started 3 hours after the interview, so 8pm. Finished the day at 12am
	//
	//===========================================
	//                 DAY 2
	//===========================================
	//
	//Had School + Work so i had like 3 hours :/
	//Lots of figuring out what everything outside the first few thousand bytes were
	//Lots of tunnel visioning hence only finding SquashFS halfway through the day
	//Then did research and organization to then have SquashFS docs and clean code for next day
	//
	//===========================================
	//                 DAY 3
	//===========================================
	//
	//Started the day at 5pm, AI was able to greatly speed up the reversing since I had the Squashfs docs.
	//Then all I needed to do was read the docs, create the corresponding structs, and then have AI do some of the more
	//menial refactoring for similar parts (saved me an hour)
	//
	//Finish Squashfs Parsing
	//
	//===========================================
	//                 DAY 4
	//===========================================
	//
	//Getting the files
	//
	//===========================================
	//                 DAY 5
	//===========================================
	//
	//Going back to the initial headers now that i know how it's actually structured from the
	//experience from unpacking the other .pkg files.
	//
	//Live Start Header
	//Backup Start Header
	//Bootloader
	//Kernel
	//FileSystem
	//
	//Hopefully this should also be pretty easy like day 3 and kinda like day 4 since i already know the info,
	//I just need to code it
	//
	//OOOOOOOO, this looks very applicable
	//https://www.kernel.org/doc/html/v6.1/x86/boot.html#memory-layout

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

	// Where all the parsed results will live
	file := FirmwareFile{
		Live:    &LiveHeader{},
		Upgrade: &UpgradeHeader{},
	}

	file.Live = parseLiveHeader(data, 0x0)
	file.Upgrade = parseUpgradeHeader(&file, data, uint64(file.Live.UpgradeHeader))

	// An MBR is only 512 bytes long
	mbrStart := uint64(file.Upgrade.MetaData.End)
	file.MBR = fill[MBR](data, mbrStart, binary.LittleEndian)
	kernelStart := mbrStart + 0x200

	file.Kernel = &Kernel{
		Header: fill[KernelHeader](data, kernelStart, binary.LittleEndian),
		Data:   data[kernelStart+0x1F1+uint64(binary.Size(KernelHeader{})) : file.Live.UpgradeHeader+file.Upgrade.Initramfs],
	}

	kernelPayloadStart := kernelStart + uint64(file.Kernel.Header.PayloadOffset)
	kernelPayloadEnd := kernelPayloadStart + uint64(file.Kernel.Header.PayloadLength)

	initramfsStart := uint64(file.Live.UpgradeHeader + file.Upgrade.Initramfs)
	initramfsEnd := uint64(file.Live.FileSystemHeader)

	file.BootStub = data[kernelPayloadEnd : file.Live.UpgradeHeader+file.Upgrade.Initramfs]

	file.Initramfs = &Initramfs{
		Data:  data[initramfsStart:initramfsEnd],
		Start: initramfsStart,
		End:   initramfsEnd,
	}

	outputPath := filepath.Join(filepath.Dir(filePath), "output")

	if err := extractInitramfs(data, initramfsStart, initramfsEnd, outputPath); err != nil {
		fmt.Printf("extractInitramfs error: %v\n", err)
	}

	file.FileSystem, err = parseSquashFS(data, uint64(file.Live.FileSystemHeader))
	if err != nil {
		fmt.Printf("parseSquashFS error: %v\n", err)
		os.Exit(1)
	}

	if err := extractFiles(file.FileSystem, data, outputPath); err != nil {
		fmt.Printf("extractFiles error: %v\n", err)
		os.Exit(1)
	}

	mapped.Close()

	entries, err := os.ReadDir(outputPath)
	if err != nil {
		fmt.Printf("ReadDir error: %v\n", err)
		os.Exit(1)
	}

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".pkg" {
			continue
		}
		pkgPath := filepath.Join(outputPath, entry.Name())
		fmt.Printf("\n[Level 2] %s\n", entry.Name())

		pkgMapped, err := openMapped(pkgPath)
		fmt.Printf("\n[Level 2] %s\n", entry.Name())

		pkgData := pkgMapped.Data()
		if err != nil {
			fmt.Printf("  WARNING: could not read %s: %v\n", entry.Name(), err)
			continue
		}

		if uint64(len(pkgData)) < 0x8C { // uint64(binary.Size(LiveHeader{}), We added MetaData which has no fixed size so ...
			fmt.Printf("  WARNING: %s too small for LiveHeader\n", entry.Name())
			pkgMapped.Close()
			continue
		}

		pkgStartHeader := parseLiveHeader(pkgData, 0)
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

		childOut := filepath.Join(outputPath, entry.Name()+"_extracted")
		if err := extractFiles(pkgSquash, pkgData, childOut); err != nil {
			fmt.Printf("  WARNING: extractFiles failed for %s: %v\n", entry.Name(), err)
		} else {
			fmt.Printf("  Done -> %s\n", childOut)
		}

		pkgMapped.Close()
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
		{"Kernel Early Boot Stub", kernelPayloadEnd, uint64(file.Live.UpgradeHeader + file.Upgrade.Initramfs)},
		{"Initramfs", uint64(file.Live.UpgradeHeader + file.Upgrade.Initramfs), uint64(file.Live.FileSystemHeader)},
		{"SquashFS", uint64(file.Live.FileSystemHeader), uint64(file.Live.FileEnd)},
	}

	for _, r := range regions {
		fmt.Printf("  %-25s [0x%08X - 0x%08X] (%d MB)\n",
			r.name, r.start, r.end, (r.end-r.start)/1024/1024)
	}

	//printFirmwareFile(&file)
}
