// All the code found in this file was AI generated

package main

import (
	"fmt"
	"os"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

type MappedFile struct {
	data   []byte
	handle windows.Handle
	mapObj windows.Handle
}

func openMapped(path string) (*MappedFile, error) {
	// AI Generated, was mainly focused on reversing the binary and felt I didn't have time to properly learn this
	// method of memory management for this program (allocating more wasn't fixing my problem)
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
	// AI Generated

	err1 := windows.UnmapViewOfFile(uintptr(m.handle))
	err2 := windows.CloseHandle(m.mapObj)
	m.data = nil
	if err1 != nil {
		return err1
	}
	return err2
}

func (m *MappedFile) Data() []byte {
	// AI Generated

	return m.data
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
