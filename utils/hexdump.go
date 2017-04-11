package utils

import "fmt"

const (
	ByteSplit = "  "
	DummyOut  = "   "
	ChunkLen  = 16
)

func isPrintable(c byte) bool {
	// as defined in https://en.wikipedia.org/wiki/ASCII#Printable_characters
	if 0x20 < c && c < 0x7e {
		return true
	}
	return false
}
func min(a int, b int) int {
	if a < b {
		return a
	}
	return b
}

// DumpAsHex dump bytes as hex strings
func DumpAsHex(data []byte) {
	for i := 0; i < len(data); i += ChunkLen {
		dumpHexLine(data[i:min(i+ChunkLen, len(data))], i*ChunkLen, '.')
	}
}

func dumpHexLine(d []byte, offset int, r byte) {

	fmt.Printf("%.5x%s ", offset, ByteSplit)

	var i int
	for i, c := range d {
		// put a space between first and last 8 bytes
		if i%8 == 0 {
			fmt.Print(ByteSplit)
		}
		fmt.Printf("%02x ", c)
	}

	// put a missing split space if we got less than 8 bytes
	if i < 8 {
		fmt.Print(ByteSplit)
	}

	// fill missing bytes with spaces
	for n := len(d); n < ChunkLen; n++ {
		fmt.Print(DummyOut)
	}

	// a space between bytes and ASCII content
	fmt.Print(ByteSplit)

	// ASCII outpout
	for _, c := range d {
		if isPrintable(c) {
			fmt.Printf("%c", c)
		} else {
			fmt.Printf("%c", r)
		}
	}
	fmt.Println()
}
