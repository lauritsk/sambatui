package auth

import (
	"encoding/binary"
	"testing"
)

func TestCacheReaderChecksLengthsBeforeArchitectureConversion(t *testing.T) {
	for _, sizeBytes := range []uint32{0, 1, 0x80000000, 0xffffffff} {
		data := make([]byte, 5)
		binary.BigEndian.PutUint32(data, sizeBytes)
		reader := &cacheReader{remaining: data}
		value := reader.data()
		if sizeBytes <= 1 {
			if reader.err != nil || len(value) != int(sizeBytes) {
				t.Fatalf("valid data size %d: %v", sizeBytes, reader.err)
			}
		} else {
			if reader.err == nil || value != nil {
				t.Fatalf("unbounded data size %d accepted", sizeBytes)
			}
			if reader.take(1) != nil {
				t.Fatal("reader resumed after decoding error")
			}
		}
	}
}

func TestCacheItemCountsHaveIndependentAllocationLimit(t *testing.T) {
	for _, count := range []uint32{cacheItemsMax, cacheItemsMax + 1, 0xffffffff} {
		data := make([]byte, 4+4*(cacheItemsMax+1))
		binary.BigEndian.PutUint32(data, count)
		reader := &cacheReader{remaining: data}
		actual := reader.count()
		if count == cacheItemsMax {
			if reader.err != nil || actual != cacheItemsMax {
				t.Fatal("exact count rejected", reader.err)
			}
		} else if reader.err == nil || actual != 0 {
			t.Fatal("unbounded count accepted")
		}
	}
}
