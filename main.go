package main

// Test items: https://drive.google.com/drive/folders/1_TtBnqGhBP7Ss-FFxzW18fjrFbFRl86x

import (
	"encoding/binary"
	"fmt"
	"os"
)

type Header struct {
	Magic       []byte
	Signature   []byte
	Padding     []byte
	UnknownData []byte
	UnknownPad  []byte
}

type TLV struct {
	Tag    uint32
	Length uint32
	Value  []byte
}

type TLVBlock struct {
	BlockType uint32
	TLVs      []TLV
}

type UnknownBlock struct {
	BlockType uint32
	Data      []byte
}

func parseHeaderBlock(length int, data []byte) *Header {
	fmt.Println("Header:")

	block := Header{
		Magic:       data[:0x4],
		Signature:   data[0x4:0x34],
		Padding:     data[0x34:0x40],
		UnknownData: data[0x40 : length-0x38],
		UnknownPad:  data[length-0x38 : length],
	}

	fmt.Print("Magic: ")
	for _, b := range block.Magic {
		fmt.Printf("%X ", b)
	}
	fmt.Printf("\n")

	fmt.Println("Signature: ")
	for i, b := range block.Signature {
		if i%16 == 0 && i != 0 {
			fmt.Printf("\n")
		}
		fmt.Printf("%X ", b)
	}
	fmt.Printf("\n")

	fmt.Println("Padding: ")
	for i, b := range block.Padding {
		if i%16 == 0 && i != 0 {
			fmt.Printf("\n")
		}

		fmt.Printf("%X ", b)
	}
	fmt.Printf("\n")

	fmt.Println("UnknownData: ")
	for i, b := range block.UnknownData {
		if i%16 == 0 && i != 0 {
			fmt.Printf("\n")
		}

		fmt.Printf("%X ", b)
	}
	fmt.Printf("\n")

	fmt.Println("UnknownPad: ")
	for i, b := range block.UnknownPad {
		if i%16 == 0 && i != 0 {
			fmt.Printf("\n")
		}

		fmt.Printf("%X ", b)
	}
	fmt.Printf("\n")

	return &block
}

func parseTLVBlock(start int, length int, data []byte) *TLVBlock {
	pointer := start

	block := TLVBlock{
		BlockType: binary.BigEndian.Uint32(data[pointer : pointer+0x4]),
		TLVs:      []TLV{},
	}

	// Get the TLV's
	pointer += 0x4 // skip over the blockType
	for pointer < start+length {
		tag := binary.BigEndian.Uint32(data[pointer : pointer+4])
		length := binary.BigEndian.Uint32(data[pointer+4 : pointer+8])

		tlv := TLV{
			Tag:    tag,
			Length: length,
			Value:  data[pointer+0x8 : pointer+0x8+int(length)],
		}

		block.TLVs = append(block.TLVs, tlv)
		// move pointer to end of TLV
		pointer += 0x8 + int(length)

		// align if not multiple of 4
		if pointer%4 != 0 {
			pointer += 4 - pointer%4
		}
	}

	fmt.Printf("Block Type?: %X\n", block.BlockType)
	for _, tlv := range block.TLVs {
		fmt.Printf("Tag: 0x%X  Length: %d  Value: %s\n", tlv.Tag, tlv.Length, tlv.Value)
	}

	return &block
}

func parseUnknownBlock(start int, length int, data []byte) *UnknownBlock {
	pointer := start

	block := UnknownBlock{
		BlockType: binary.BigEndian.Uint32(data[pointer : pointer+0x4]),
		Data:      data[pointer+4 : start+length],
	}

	pointer += 0x4 // skip over the blockType
	fmt.Printf("Block Type?: %X\n", block.BlockType)
	for pointer < start+length {
		if pointer%16 == 0 {
			fmt.Printf("\n")
		}

		fmt.Printf("%02x ", data[pointer])
		pointer += 1
	}
	fmt.Printf("\n")

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

	parseHeaderBlock(0x8C, data)
	// the header length is 140 bytes? maybe 38 is just leftover header space?
	//i := 0x54 + 0x38 // there's 0x38 null bytes until the next block (repeats for both blocks)

	// cat9k_iosxe
	i := 0x8C
	parseTLVBlock(i, 0x1F0, data)
	i = 0x27C
	parseUnknownBlock(i, 0x1E4, data)

	// cat9k-rpboot
	i = 0x460 + 0x38 // there's 0x38 null bytes until the next block (repeats for both blocks)
	parseTLVBlock(i, 0x1E8, data)
	i = 0x680
	parseUnknownBlock(i, 0x380, data)

	fmt.Println()
	fmt.Printf("Successfully read %d bytes from %s\n", len(data), filePath)
}
