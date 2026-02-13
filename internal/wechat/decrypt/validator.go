package decrypt

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/rs/zerolog/log"
	"github.com/DanielMao1/chatlog/internal/wechat/decrypt/common"
	"github.com/DanielMao1/chatlog/pkg/util/dat2img"
)

type Validator struct {
	platform        string
	version         int
	dbPath          string
	decryptor       Decryptor
	dbFile          *common.DBFile
	extraDBFiles    []*common.DBFile // 额外的数据库文件，用于派生密钥验证
	imgKeyValidator *dat2img.AesKeyValidator
	// 派生密钥搜索优化：跟踪已匹配的数据库，跳过已找到密钥的数据库
	matchedDBs   sync.Map // index -> true (-1=primary, 0..N=extra)
	matchedCount int32    // 已匹配数据库数量（atomic）
	totalDBCount int      // 总数据库数量
}

// NewValidator 创建一个仅用于验证的验证器
func NewValidator(platform string, version int, dataDir string) (*Validator, error) {
	return NewValidatorWithFile(platform, version, dataDir)
}

func NewValidatorWithFile(platform string, version int, dataDir string) (*Validator, error) {
	dbFile := GetSimpleDBFile(platform, version)
	dbPath := filepath.Join(dataDir, dbFile)
	decryptor, err := NewDecryptor(platform, version)
	if err != nil {
		return nil, err
	}
	d, err := common.OpenDBFile(dbPath, decryptor.GetPageSize())
	if err != nil {
		return nil, err
	}

	validator := &Validator{
		platform:  platform,
		version:   version,
		dbPath:    dbPath,
		decryptor: decryptor,
		dbFile:    d,
	}

	if version == 4 {
		validator.imgKeyValidator = dat2img.NewImgKeyValidator(dataDir)

		// 扫描所有数据库文件用于派生密钥验证（不同数据库有不同的 salt/派生密钥）
		dbStorageDir := filepath.Join(dataDir, "db_storage")
		filepath.Walk(dbStorageDir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if info.IsDir() {
				if strings.Contains(info.Name(), "fts") {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(info.Name(), ".db") || strings.Contains(info.Name(), "fts") {
				return nil
			}
			if path == dbPath {
				return nil // 跳过已作为主数据库加载的文件
			}
			extraFile, err := common.OpenDBFile(path, decryptor.GetPageSize())
			if err != nil {
				log.Debug().Str("path", path).Err(err).Msg("Failed to open extra DB file for derived key validation")
				return nil
			}
			validator.extraDBFiles = append(validator.extraDBFiles, extraFile)
			return nil
		})
		validator.totalDBCount = len(validator.extraDBFiles) + 1
		log.Debug().Int("count", validator.totalDBCount).Msg("Loaded database files for derived key validation")
	}

	return validator, nil
}

func (v *Validator) Validate(key []byte) bool {
	return v.decryptor.Validate(v.dbFile.FirstPage, key)
}

// ValidateDerivedKey 验证已派生的密钥（如果解密器支持）
// 派生密钥是数据库专属的（因为每个数据库有不同的 salt），
// 所以需要尝试所有未匹配的数据库文件，跳过已找到密钥的数据库
func (v *Validator) ValidateDerivedKey(key []byte) bool {
	type derivedKeyValidator interface {
		ValidateDerivedKey(page1 []byte, key []byte) bool
	}
	dv, ok := v.decryptor.(derivedKeyValidator)
	if !ok {
		return false
	}
	// 先尝试主数据库（跳过已匹配的）
	if _, matched := v.matchedDBs.Load(-1); !matched {
		if dv.ValidateDerivedKey(v.dbFile.FirstPage, key) {
			if _, already := v.matchedDBs.LoadOrStore(-1, true); !already {
				atomic.AddInt32(&v.matchedCount, 1)
			}
			return true
		}
	}
	// 再尝试未匹配的额外数据库文件
	for i, extraDB := range v.extraDBFiles {
		if _, matched := v.matchedDBs.Load(i); matched {
			continue
		}
		if dv.ValidateDerivedKey(extraDB.FirstPage, key) {
			if _, already := v.matchedDBs.LoadOrStore(i, true); !already {
				atomic.AddInt32(&v.matchedCount, 1)
			}
			return true
		}
	}
	return false
}

// AllDerivedKeysFound 返回是否已为所有数据库找到派生密钥
func (v *Validator) AllDerivedKeysFound() bool {
	return v.totalDBCount > 0 && atomic.LoadInt32(&v.matchedCount) >= int32(v.totalDBCount)
}

func (v *Validator) ValidateImgKey(key []byte) bool {
	if v.imgKeyValidator == nil {
		return false
	}
	return v.imgKeyValidator.Validate(key)
}


func GetSimpleDBFile(platform string, version int) string {
	switch {
	case platform == "windows" && version == 3:
		return "Msg\\Misc.db"
	case platform == "windows" && version == 4:
		return "db_storage\\message\\message_0.db"
	case platform == "darwin" && version == 3:
		return "Message/msg_0.db"
	case platform == "darwin" && version == 4:
		return "db_storage/message/message_0.db"
	}
	return ""

}
