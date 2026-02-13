# Chatlog 技术报告：微信数据库密钥提取与 4.1.7 适配

## 1. 概述

Chatlog 是一个微信聊天记录工具，核心能力是从本地加密的微信数据库中提取并解密聊天数据。微信在本地使用 SQLCipher 变体对所有数据库文件进行 AES-256-CBC 加密，密钥存储在微信进程的运行时内存中。Chatlog 通过读取进程内存、搜索特征码、验证候选密钥的方式获取解密密钥。

## 2. 微信数据库加密方案

### 2.1 加密参数（macOS V4）

| 参数 | 值 |
|------|-----|
| 算法 | AES-256-CBC |
| 页大小 | 4096 字节 |
| 哈希函数 | SHA-512 |
| HMAC 大小 | 64 字节 |
| 保留区（Reserve） | 80 字节（16 字节 IV + 64 字节 HMAC） |
| PBKDF2 迭代次数 | 256,000 |

### 2.2 密钥派生流程

```
原始密钥 (raw_key, 32 字节)
    │
    ├─ PBKDF2(raw_key, salt, 256000, SHA-512) ──→ 加密密钥 (enc_key, 32 字节)
    │                                                  │
    │                                                  ├─ PBKDF2(enc_key, salt⊕0x3a, 2, SHA-512) ──→ MAC 密钥 (mac_key)
    │                                                  │
    │                                                  └─ AES-256-CBC 加解密
    │
    └─ 每个数据库文件有独立的 salt（文件头 16 字节）
```

### 2.3 数据库页面结构

```
第 0 页 (4096 字节):
┌──────────────────────────────────────────────────┐
│ Salt (16 bytes)                                  │
│ 加密数据 (AES-CBC)                                │
│ ...                                              │
│ IV (16 bytes) │ HMAC-SHA512 (64 bytes)           │  ← 保留区 (80 bytes)
└──────────────────────────────────────────────────┘
```

### 2.4 密钥验证方法

给定候选密钥和数据库文件第一页：

1. 从第一页提取 salt（前 16 字节）
2. 派生 enc_key 和 mac_key
3. 计算 `HMAC-SHA512(mac_key, page[16 : 4032] || little_endian(1))`
4. 与页面中存储的 HMAC（偏移 4032-4096）比较
5. 匹配则密钥正确

## 3. 原始密钥提取流程（WeChat < 4.1.0）

### 3.1 内存区域定位

```
vmmap -wide <PID>
    │
    └─ 过滤 MALLOC_NANO 区域（Darwin 24.x）
       或 MALLOC_SMALL 区域（Darwin 25.x / macOS 26）
```

macOS 需要关闭 SIP（系统完整性保护）才能读取其他进程的内存。

### 3.2 内存读取

通过 `lldb`（macOS 自带调试器）attach 到微信进程，使用 `memory read --binary` 命令将目标内存区域 dump 到命名管道（FIFO），再由 Go 程序读取。

512MB 的 MALLOC_NANO 区域被分割为 16 个约 32MB 的 chunk，由 8 个 worker 并行处理。

### 3.3 特征码搜索

在 dump 出的内存中搜索已知特征码，在特征码的固定偏移处提取 32 字节候选密钥：

**Data Key 特征码：**

| 特征码 | 含义 | 偏移量 |
|--------|------|--------|
| `20 66 74 73 35 28 25 00` | ASCII ` fts5(%\0`（SQLite FTS5 配置字符串） | +16, -80, +64 |
| 16 字节全零 | 空填充块 | -32 |

**Image Key 特征码：**

| 特征码 | 偏移量 |
|--------|--------|
| 16 字节全零 | -32 |

### 3.4 候选过滤与验证

对每个候选密钥：
1. 排除包含连续 `\x00\x00` 的候选（降低误报）
2. 去重（`sync.Map`）
3. 执行完整 PBKDF2-256K 密钥验证（约 0.1-0.2 秒/次）

## 4. WeChat 4.1.7 的变化与适配

### 4.1 发现问题

在 WeChat 4.1.7 上，原有的特征码搜索（FTS5 模式 + 零填充模式）均无法找到有效密钥。通过日志分析确认：
- FTS5 特征码存在于内存中（19 处匹配）
- 但所有偏移位置的候选密钥验证均失败

### 4.2 根因分析

通过 Python 脚本对 MALLOC_NANO 区域进行暴力搜索，发现：

**WeChat 4.1.7 在内存中存储的是 PBKDF2 派生后的加密密钥（enc_key），而非原始密钥（raw_key）。**

验证方式从原来的：
```
PBKDF2(candidate, salt, 256000) → enc_key → PBKDF2(enc_key, salt⊕0x3a, 2) → mac_key → HMAC 验证
```
变为：
```
candidate 即 enc_key → PBKDF2(candidate, salt⊕0x3a, 2) → mac_key → HMAC 验证
```

关键证据：

| 数据库 | 派生密钥（内存中） | 内存偏移 |
|--------|-------------------|----------|
| session.db | `33d81c8d3b58873d...` | 0x27C080 |
| message_0.db | `17776688cb3630f2...` | 0x26FD40 |

### 4.3 派生密钥的特点

1. **数据库专属**：每个数据库有独立的 salt，因此派生出的 enc_key 不同
2. **无统一特征码**：session.db 的密钥后跟 `AXTM` 标记，message_0.db 的密钥后无此标记
3. **验证速度极快**：只需 2 次 PBKDF2 迭代（vs 原来的 256,000 次），单次验证约 0.001 秒

### 4.4 代码改动

#### 4.4.1 新增派生密钥验证（`internal/wechat/decrypt/darwin/v4.go`）

```go
// ValidateDerivedKey 跳过 256K 次 PBKDF2，直接将候选密钥作为 enc_key
func (d *V4Decryptor) ValidateDerivedKey(page1 []byte, key []byte) bool { ... }

// deriveDerivedKeys 只执行 2 次 PBKDF2 生成 mac_key
func (d *V4Decryptor) deriveDerivedKeys(encKey []byte, salt []byte) ([]byte, []byte) { ... }
```

同时修改 `Decrypt` 方法，通过 `derived:` 前缀识别派生密钥，选择对应的解密路径。Windows V4 解密器（`internal/wechat/decrypt/windows/v4.go`）做了相同修改。

#### 4.4.2 Validator 多数据库支持（`internal/wechat/decrypt/validator.go`）

```go
type Validator struct {
    ...
    extraDBFiles []*common.DBFile // 额外数据库文件，用于派生密钥验证
}
```

- `ValidateDerivedKey` 方法依次尝试所有已加载的数据库文件（message_0.db + session.db）
- 通过 Go 接口断言（`derivedKeyValidator`）实现，不修改 `Decryptor` 接口，保持向后兼容

#### 4.4.3 暴力扫描搜索（`internal/wechat/key/darwin/v4.go`）

原有的特征码搜索对 4.1.7 无效，改用暴力扫描：

```go
func (e *V4Extractor) SearchDerivedKey(ctx context.Context, memory []byte) (string, bool) {
    // 遍历所有 8 字节对齐的位置
    // 跳过零字节 > 24 的区域
    // 用快速 PBKDF2-2 验证每个 32 字节候选
}
```

Worker 优先调用 `SearchDerivedKey`（快），再 fallback 到 `SearchKey`（慢），兼容新旧版本。

#### 4.4.4 文件改动总结

| 文件 | 改动 |
|------|------|
| `internal/wechat/key/darwin/v4.go` | 新增 `SearchDerivedKey` 暴力扫描；worker 优先搜索派生密钥 |
| `internal/wechat/decrypt/validator.go` | 新增 `ValidateDerivedKey`；加载 session.db 作为额外验证源 |
| `internal/wechat/decrypt/darwin/v4.go` | 新增 `ValidateDerivedKey`、`deriveDerivedKeys`；`Decrypt` 支持 `derived:` 前缀 |
| `internal/wechat/decrypt/windows/v4.go` | 同 darwin v4，保持一致性 |

## 5. 测试

新增 11 个单元测试，覆盖：

- 派生密钥验证：正确密钥通过、错误密钥拒绝、异常输入处理
- 暴力搜索：在模拟内存中找到嵌入密钥、零内存无误报、随机内存无误报、8 字节对齐、context 取消
- Worker 集成：找到密钥后正确添加 `derived:` 前缀并上报

```
=== 解密器测试 ===
PASS: TestValidateDerivedKey_SessionDB
PASS: TestValidateDerivedKey_MessageDB
PASS: TestValidateDerivedKey_WrongKey
PASS: TestValidateDerivedKey_BadInput
PASS: TestDeriveDerivedKeys

=== 密钥提取器测试 ===
PASS: TestSearchDerivedKey_FindsKeyInMemory
PASS: TestSearchDerivedKey_FindsMessageKeyInMemory
PASS: TestSearchDerivedKey_NoKeyInZeroMemory
PASS: TestSearchDerivedKey_NoKeyInRandomMemory
PASS: TestSearchDerivedKey_KeyAt8ByteAlignment
PASS: TestSearchDerivedKey_RespectsContext
PASS: TestWorker_FindsDerivedKeyAndReports
```

## 6. 已知限制

1. **派生密钥是数据库专属的**：找到的密钥只能解密其对应的数据库。解密其他数据库时可能需要二次内存搜索。
2. **暴力扫描性能**：对 512MB MALLOC_NANO 区域的完整扫描约需数秒（Go 实现），可接受但不如特征码匹配快。
3. **需要微信运行中**：派生密钥只在微信进程存活时存在于内存中。
