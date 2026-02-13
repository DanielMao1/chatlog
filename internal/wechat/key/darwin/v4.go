package darwin

import (
	"bytes"
	"context"
	"encoding/hex"
	"runtime"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"

	"github.com/DanielMao1/chatlog/internal/errors"
	"github.com/DanielMao1/chatlog/internal/wechat/decrypt"
	"github.com/DanielMao1/chatlog/internal/wechat/key/darwin/glance"
	"github.com/DanielMao1/chatlog/internal/wechat/model"
)

const (
	MaxWorkers = 8
)

var V4KeyPatterns = []KeyPatternInfo{
	{
		Pattern: []byte{0x20, 0x66, 0x74, 0x73, 0x35, 0x28, 0x25, 0x00},
		Offsets: []int{16, -80, 64},
	},
	{
		Pattern: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		Offsets: []int{-32},
	},
}

// V4DerivedKeyPatterns 用于搜索已派生的密钥（WeChat >= 4.1.0）
// 密钥后紧跟 "AXTM" 标记
var V4DerivedKeyPatterns = []KeyPatternInfo{
	{
		Pattern: []byte{0x41, 0x58, 0x54, 0x4d, 0x00, 0x00, 0x00, 0x00}, // "AXTM\x00\x00\x00\x00"
		Offsets: []int{-32},
	},
}

var V4ImgKeyPatterns = []KeyPatternInfo{
	{
		Pattern: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		Offsets: []int{-32},
	},
}

type V4Extractor struct {
	validator              *decrypt.Validator
	dataKeyPatterns        []KeyPatternInfo
	derivedKeyPatterns     []KeyPatternInfo
	imgKeyPatterns         []KeyPatternInfo
	processedDataKeys      sync.Map // Thread-safe map for processed data keys
	processedDerivedKeys   sync.Map // Thread-safe map for processed derived keys
	processedImgKeys       sync.Map // Thread-safe map for processed image keys
	foundDerivedKeys       sync.Map // Thread-safe map for validated derived keys: keyHex -> true
}

func NewV4Extractor() *V4Extractor {
	return &V4Extractor{
		dataKeyPatterns:    V4KeyPatterns,
		derivedKeyPatterns: V4DerivedKeyPatterns,
		imgKeyPatterns:     V4ImgKeyPatterns,
	}
}

func (e *V4Extractor) Extract(ctx context.Context, proc *model.Process) (string, string, error) {
	if proc.Status == model.StatusOffline {
		return "", "", errors.ErrWeChatOffline
	}

	// Check if SIP is disabled, as it's required for memory reading on macOS
	if !glance.IsSIPDisabled() {
		return "", "", errors.ErrSIPEnabled
	}

	if e.validator == nil {
		return "", "", errors.ErrValidatorNotSet
	}

	// Create context to control all goroutines
	searchCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Create channels for memory data and results
	memoryChannel := make(chan []byte, 200)
	resultChannel := make(chan [2]string, 1)

	// Determine number of worker goroutines
	workerCount := runtime.NumCPU()
	if workerCount < 2 {
		workerCount = 2
	}
	if workerCount > MaxWorkers {
		workerCount = MaxWorkers
	}
	log.Debug().Msgf("Starting %d workers for V4 key search", workerCount)

	// Start consumer goroutines
	var workerWaitGroup sync.WaitGroup
	workerWaitGroup.Add(workerCount)
	for index := 0; index < workerCount; index++ {
		go func() {
			defer workerWaitGroup.Done()
			e.worker(searchCtx, memoryChannel, resultChannel)
		}()
	}

	// Start producer goroutine
	var producerWaitGroup sync.WaitGroup
	producerWaitGroup.Add(1)
	go func() {
		defer producerWaitGroup.Done()
		defer close(memoryChannel) // Close channel when producer is done
		err := e.findMemory(searchCtx, uint32(proc.PID), memoryChannel)
		if err != nil {
			log.Err(err).Msg("Failed to read memory")
		}
	}()

	// Wait for producer and consumers to complete
	go func() {
		producerWaitGroup.Wait()
		workerWaitGroup.Wait()
		close(resultChannel)
	}()

	// Wait for result
	var finalRawDataKey, finalImgKey string

	for {
		select {
		case <-ctx.Done():
			return "", "", ctx.Err()
		case result, ok := <-resultChannel:
			if !ok {
				// All workers finished. Collect all derived keys from foundDerivedKeys.
				var derivedKeys []string
				e.foundDerivedKeys.Range(func(k, _ interface{}) bool {
					derivedKeys = append(derivedKeys, k.(string))
					return true
				})

				var finalDataKey string
				if len(derivedKeys) > 0 {
					finalDataKey = "derived:" + strings.Join(derivedKeys, ",")
					log.Debug().Int("count", len(derivedKeys)).Msg("Total derived keys found")
				} else if finalRawDataKey != "" {
					finalDataKey = finalRawDataKey
				}

				if finalDataKey != "" || finalImgKey != "" {
					return finalDataKey, finalImgKey, nil
				}
				return "", "", errors.ErrNoValidKey
			}

			// Collect raw data key and image key from workers
			if result[0] != "" {
				finalRawDataKey = result[0]
			}
			if result[1] != "" {
				finalImgKey = result[1]
			}

			// Early return only for raw keys (derived keys need full scan)
			if finalRawDataKey != "" && finalImgKey != "" {
				cancel()
				return finalRawDataKey, finalImgKey, nil
			}
		}
	}
}

// findMemory searches for memory regions using Glance
func (e *V4Extractor) findMemory(ctx context.Context, pid uint32, memoryChannel chan<- []byte) error {
	// Initialize a Glance instance to read process memory
	g := glance.NewGlance(pid)

	// Use the Read2Chan method to read and chunk memory
	return g.Read2Chan(ctx, memoryChannel)
}

// worker processes memory regions to find V4 version key
func (e *V4Extractor) worker(ctx context.Context, memoryChannel <-chan []byte, resultChannel chan<- [2]string) {
	// Track found keys (raw key only; derived keys go to foundDerivedKeys sync.Map)
	var rawDataKey, imgKey string

	for {
		select {
		case <-ctx.Done():
			return
		case memory, ok := <-memoryChannel:
			if !ok {
				// Memory scanning complete, return whatever raw/img keys we found
				if rawDataKey != "" || imgKey != "" {
					select {
					case resultChannel <- [2]string{rawDataKey, imgKey}:
					default:
					}
				}
				return
			}

			// Search for derived keys (skip if all databases already matched)
			if !e.validator.AllDerivedKeysFound() {
				e.SearchAllDerivedKeys(ctx, memory)
			}

			// Search for raw data key (older WeChat versions, only if no raw key found yet)
			if rawDataKey == "" {
				if key, ok := e.SearchKey(ctx, memory); ok {
					rawDataKey = key
					log.Debug().Msg("Raw data key found: " + key)
					select {
					case resultChannel <- [2]string{rawDataKey, imgKey}:
					case <-ctx.Done():
						return
					}
				}
			}

			// Search for image key
			if imgKey == "" {
				if key, ok := e.SearchImgKey(ctx, memory); ok {
					imgKey = key
					log.Debug().Msg("Image key found: " + key)
					select {
					case resultChannel <- [2]string{rawDataKey, imgKey}:
					case <-ctx.Done():
						return
					}
				}
			}
		}
	}
}

func (e *V4Extractor) SearchKey(ctx context.Context, memory []byte) (string, bool) {
	for _, keyPattern := range e.dataKeyPatterns {
		index := len(memory)
		zeroPattern := bytes.Equal(keyPattern.Pattern, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

		for {
			select {
			case <-ctx.Done():
				return "", false
			default:
			}

			// Find pattern from end to beginning
			index = bytes.LastIndex(memory[:index], keyPattern.Pattern)
			if index == -1 {
				break // No more matches found
			}

			// align to 16 bytes
			if zeroPattern {
				index = bytes.LastIndexFunc(memory[:index], func(r rune) bool {
					return r != 0
				})
				if index == -1 {
					break // No more matches found
				}
				index += 1
			}

			// Try each offset for this pattern
			for _, offset := range keyPattern.Offsets {
				// Check if we have enough space for the key
				keyOffset := index + offset
				if keyOffset < 0 || keyOffset+32 > len(memory) {
					continue
				}

				if bytes.Contains(memory[keyOffset:keyOffset+32], []byte{0x00, 0x00}) {
					continue
				}

				// Extract the key data, which is at the offset position and 32 bytes long
				keyData := memory[keyOffset : keyOffset+32]
				keyHex := hex.EncodeToString(keyData)

				// Skip if we've already processed this key (thread-safe check)
				if _, loaded := e.processedDataKeys.LoadOrStore(keyHex, true); loaded {
					continue
				}

				// Validate key against database header
				if e.validator.Validate(keyData) {
					log.Debug().
						Str("pattern", hex.EncodeToString(keyPattern.Pattern)).
						Int("offset", offset).
						Str("key", keyHex).
						Msg("Data key found")
					return keyHex, true
				}
			}

			index -= 1
			if index < 0 {
				break
			}
		}
	}

	return "", false
}

func (e *V4Extractor) SearchImgKey(ctx context.Context, memory []byte) (string, bool) {

	for _, keyPattern := range e.imgKeyPatterns {
		index := len(memory)

		for {
			select {
			case <-ctx.Done():
				return "", false
			default:
			}

			// Find pattern from end to beginning
			index = bytes.LastIndex(memory[:index], keyPattern.Pattern)
			if index == -1 {
				break // No more matches found
			}

			// align to 16 bytes
			index = bytes.LastIndexFunc(memory[:index], func(r rune) bool {
				return r != 0
			})

			if index == -1 {
				break // No more matches found
			}

			index += 1

			// Try each offset for this pattern
			for _, offset := range keyPattern.Offsets {
				// Check if we have enough space for the key (16 bytes for image key)
				keyOffset := index + offset
				if keyOffset < 0 || keyOffset+16 > len(memory) {
					continue
				}

				if bytes.Contains(memory[keyOffset:keyOffset+16], []byte{0x00, 0x00}) {
					continue
				}

				// Extract the key data, which is at the offset position and 16 bytes long
				keyData := memory[keyOffset : keyOffset+16]
				keyHex := hex.EncodeToString(keyData)

				// Skip if we've already processed this key (thread-safe check)
				if _, loaded := e.processedImgKeys.LoadOrStore(keyHex, true); loaded {
					continue
				}

				// Validate key using image key validator
				if e.validator.ValidateImgKey(keyData) {
					log.Debug().
						Str("pattern", hex.EncodeToString(keyPattern.Pattern)).
						Int("offset", offset).
						Str("key", keyHex).
						Msg("Image key found")
					return keyHex, true
				}
			}

			index -= 1
			if index < 0 {
				break
			}
		}
	}

	return "", false
}

// SearchAllDerivedKeys 搜索所有已派生的数据密钥（WeChat >= 4.1.0）
// 暴力扫描所有 8 字节对齐的 32 字节候选，用快速 PBKDF2-2 验证
// 找到的密钥存储在 foundDerivedKeys 中，返回本次扫描找到的数量
func (e *V4Extractor) SearchAllDerivedKeys(ctx context.Context, memory []byte) int {
	if len(memory) < 32 {
		return 0
	}

	count := 0
	for pos := 0; pos+32 <= len(memory); pos += 8 {
		// 定期检查取消和是否已找到所有密钥
		if pos%(8*1024) == 0 {
			select {
			case <-ctx.Done():
				return count
			default:
			}
			if e.validator.AllDerivedKeysFound() {
				return count
			}
		}

		keyData := memory[pos : pos+32]

		// 跳过全零或几乎全零的区域
		zeroCount := 0
		for _, b := range keyData {
			if b == 0 {
				zeroCount++
			}
		}
		if zeroCount > 24 {
			continue
		}

		keyHex := hex.EncodeToString(keyData)

		if _, loaded := e.processedDerivedKeys.LoadOrStore(keyHex, true); loaded {
			continue
		}

		if e.validator.ValidateDerivedKey(keyData) {
			e.foundDerivedKeys.Store(keyHex, true)
			count++
			log.Debug().
				Int("offset", pos).
				Str("key", keyHex).
				Msg("Derived data key found via brute-force scan")
		}
	}

	return count
}

// SearchDerivedKey 搜索单个已派生的数据密钥（兼容接口，用于测试）
func (e *V4Extractor) SearchDerivedKey(ctx context.Context, memory []byte) (string, bool) {
	count := e.SearchAllDerivedKeys(ctx, memory)
	if count > 0 {
		var firstKey string
		e.foundDerivedKeys.Range(func(k, _ interface{}) bool {
			firstKey = k.(string)
			return false
		})
		return firstKey, true
	}
	return "", false
}

func (e *V4Extractor) SetValidate(validator *decrypt.Validator) {
	e.validator = validator
}

type KeyPatternInfo struct {
	Pattern []byte
	Offsets []int
}
