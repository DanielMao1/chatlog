package darwin

import (
	"encoding/hex"
	"testing"

	"github.com/DanielMao1/chatlog/internal/wechat/decrypt/common"
)

// Test data from a real WeChat 4.1.7 session.db and message_0.db.
// The derived keys were extracted from MALLOC_NANO process memory.

var (
	// session.db first page (only salt + first encrypted bytes needed for test, rest is padded)
	sessionSalt, _ = hex.DecodeString("b8f04a11e11f401028117c32ec1c5743")
	// message_0.db salt
	messageSalt, _ = hex.DecodeString("8ed123e42fe685e72abe09d875a93538")

	// Known derived keys (post-PBKDF2 enc_keys found in memory)
	sessionDerivedKey, _ = hex.DecodeString("33d81c8d3b58873d4c50e18868854eb130e4e80909df687e27608ae2d2071fee")
	messageDerivedKey, _ = hex.DecodeString("17776688cb3630f2753b08c2e180d35213c29e2d033903972a56517fb48d08f6")
)

func loadTestDBPage(t *testing.T, dbRelPath string) []byte {
	t.Helper()
	base := "/Users/danielmao/Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files/wxid_p5kf2yvbv7ny22_3678"
	dbFile, err := common.OpenDBFile(base+"/"+dbRelPath, V4PageSize)
	if err != nil {
		t.Skipf("Cannot open test DB %s: %v (skipping, requires real WeChat data)", dbRelPath, err)
	}
	return dbFile.FirstPage
}

func TestValidateDerivedKey_SessionDB(t *testing.T) {
	page := loadTestDBPage(t, "db_storage/session/session.db")
	d := NewV4Decryptor()

	if !d.ValidateDerivedKey(page, sessionDerivedKey) {
		t.Fatal("ValidateDerivedKey should accept the correct session.db derived key")
	}
}

func TestValidateDerivedKey_MessageDB(t *testing.T) {
	page := loadTestDBPage(t, "db_storage/message/message_0.db")
	d := NewV4Decryptor()

	if !d.ValidateDerivedKey(page, messageDerivedKey) {
		t.Fatal("ValidateDerivedKey should accept the correct message_0.db derived key")
	}
}

func TestValidateDerivedKey_WrongKey(t *testing.T) {
	page := loadTestDBPage(t, "db_storage/session/session.db")
	d := NewV4Decryptor()

	// session derived key should NOT validate against message_0.db's page
	if d.ValidateDerivedKey(page, messageDerivedKey) {
		t.Fatal("ValidateDerivedKey should reject a derived key from a different database")
	}

	// random key should not validate
	badKey, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000001")
	if d.ValidateDerivedKey(page, badKey) {
		t.Fatal("ValidateDerivedKey should reject a random key")
	}
}

func TestValidateDerivedKey_BadInput(t *testing.T) {
	page := loadTestDBPage(t, "db_storage/session/session.db")
	d := NewV4Decryptor()

	// Too short key
	if d.ValidateDerivedKey(page, sessionDerivedKey[:16]) {
		t.Fatal("ValidateDerivedKey should reject a 16-byte key")
	}

	// Empty key
	if d.ValidateDerivedKey(page, nil) {
		t.Fatal("ValidateDerivedKey should reject nil key")
	}

	// Too short page
	if d.ValidateDerivedKey(page[:100], sessionDerivedKey) {
		t.Fatal("ValidateDerivedKey should reject a truncated page")
	}
}

func TestDeriveDerivedKeys(t *testing.T) {
	d := NewV4Decryptor()

	// deriveDerivedKeys should return encKey unchanged as the first value
	encKey, macKey := d.deriveDerivedKeys(sessionDerivedKey, sessionSalt)

	if hex.EncodeToString(encKey) != hex.EncodeToString(sessionDerivedKey) {
		t.Fatal("deriveDerivedKeys should return encKey unchanged")
	}

	if len(macKey) != common.KeySize {
		t.Fatalf("macKey should be %d bytes, got %d", common.KeySize, len(macKey))
	}

	// macKey should NOT equal encKey
	if hex.EncodeToString(macKey) == hex.EncodeToString(encKey) {
		t.Fatal("macKey should differ from encKey")
	}
}
