package darwin

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/DanielMao1/chatlog/internal/wechat/decrypt"
)

// Known derived keys from WeChat 4.1.7 memory
var (
	testSessionDerivedKey, _ = hex.DecodeString("33d81c8d3b58873d4c50e18868854eb130e4e80909df687e27608ae2d2071fee")
	testMessageDerivedKey, _ = hex.DecodeString("17776688cb3630f2753b08c2e180d35213c29e2d033903972a56517fb48d08f6")

	testDataDir = "/Users/danielmao/Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files/wxid_p5kf2yvbv7ny22_3678"
)

func setupValidator(t *testing.T) *decrypt.Validator {
	t.Helper()
	v, err := decrypt.NewValidator("darwin", 4, testDataDir)
	if err != nil {
		t.Skipf("Cannot create validator (requires real WeChat data): %v", err)
	}
	return v
}

func TestSearchDerivedKey_FindsKeyInMemory(t *testing.T) {
	v := setupValidator(t)

	ext := NewV4Extractor()
	ext.SetValidate(v)

	// Build a fake memory block with the known derived key embedded at a specific offset
	memory := make([]byte, 4096)
	// Fill with random data to simulate real memory
	rand.Read(memory)
	// Place the known session derived key at offset 1024
	copy(memory[1024:1056], testSessionDerivedKey)

	ctx := context.Background()
	key, found := ext.SearchDerivedKey(ctx, memory)
	if !found {
		t.Fatal("SearchDerivedKey should find the embedded session derived key")
	}
	if key != hex.EncodeToString(testSessionDerivedKey) {
		t.Fatalf("Expected key %s, got %s", hex.EncodeToString(testSessionDerivedKey), key)
	}
}

func TestSearchDerivedKey_FindsMessageKeyInMemory(t *testing.T) {
	v := setupValidator(t)

	ext := NewV4Extractor()
	ext.SetValidate(v)

	// Build memory with message_0.db derived key
	memory := make([]byte, 4096)
	rand.Read(memory)
	copy(memory[2048:2080], testMessageDerivedKey)

	ctx := context.Background()
	key, found := ext.SearchDerivedKey(ctx, memory)
	if !found {
		t.Fatal("SearchDerivedKey should find the embedded message derived key")
	}
	if key != hex.EncodeToString(testMessageDerivedKey) {
		t.Fatalf("Expected key %s, got %s", hex.EncodeToString(testMessageDerivedKey), key)
	}
}

func TestSearchDerivedKey_NoKeyInZeroMemory(t *testing.T) {
	v := setupValidator(t)

	ext := NewV4Extractor()
	ext.SetValidate(v)

	// All-zero memory should not produce a match
	memory := make([]byte, 4096)

	ctx := context.Background()
	_, found := ext.SearchDerivedKey(ctx, memory)
	if found {
		t.Fatal("SearchDerivedKey should not find a key in zero memory")
	}
}

func TestSearchDerivedKey_NoKeyInRandomMemory(t *testing.T) {
	v := setupValidator(t)

	ext := NewV4Extractor()
	ext.SetValidate(v)

	// Random memory should (with overwhelming probability) not match
	memory := make([]byte, 8192)
	rand.Read(memory)

	ctx := context.Background()
	_, found := ext.SearchDerivedKey(ctx, memory)
	if found {
		t.Fatal("SearchDerivedKey should not find a key in random memory")
	}
}

func TestSearchDerivedKey_KeyAt8ByteAlignment(t *testing.T) {
	v := setupValidator(t)

	ext := NewV4Extractor()
	ext.SetValidate(v)

	// Place key at non-16-byte but 8-byte aligned offset
	memory := make([]byte, 4096)
	rand.Read(memory)
	copy(memory[1032:1064], testSessionDerivedKey) // offset 1032 = 8-byte aligned but not 16-byte aligned

	ctx := context.Background()
	key, found := ext.SearchDerivedKey(ctx, memory)
	if !found {
		t.Fatal("SearchDerivedKey should find key at 8-byte aligned offset")
	}
	if key != hex.EncodeToString(testSessionDerivedKey) {
		t.Fatalf("Expected key %s, got %s", hex.EncodeToString(testSessionDerivedKey), key)
	}
}

func TestSearchDerivedKey_RespectsContext(t *testing.T) {
	v := setupValidator(t)

	ext := NewV4Extractor()
	ext.SetValidate(v)

	memory := make([]byte, 4096)
	rand.Read(memory)
	copy(memory[2048:2080], testSessionDerivedKey)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, found := ext.SearchDerivedKey(ctx, memory)
	if found {
		t.Fatal("SearchDerivedKey should respect cancelled context")
	}
}

func TestWorker_FindsDerivedKeyAndReports(t *testing.T) {
	v := setupValidator(t)

	ext := NewV4Extractor()
	ext.SetValidate(v)

	// Simulate the worker flow
	memory := make([]byte, 4096)
	rand.Read(memory)
	copy(memory[512:544], testSessionDerivedKey)

	ctx := context.Background()
	memCh := make(chan []byte, 1)
	resultCh := make(chan [2]string, 1)

	memCh <- memory
	close(memCh)

	ext.worker(ctx, memCh, resultCh)

	// Derived keys are stored in foundDerivedKeys sync.Map, not sent via resultCh
	expectedKey := hex.EncodeToString(testSessionDerivedKey)
	_, found := ext.foundDerivedKeys.Load(expectedKey)
	if !found {
		t.Fatalf("Worker should store derived key in foundDerivedKeys, expected %s", expectedKey)
	}
}
