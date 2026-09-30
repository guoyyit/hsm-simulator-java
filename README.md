# HSM Simulator (Java / Spring Boot)

一个本地硬件安全模块（HSM）模拟服务，对外提供与主流密码令牌接口标准（PKCS#11）兼容的
**令牌生命周期、会话、登录与密钥对象管理**语义。所有敏感密钥材料只以受保护（密文）形式
离开密码边界，支持并发访问，并在进程重启后完整恢复状态。

## 运行与测试

```bash
mvn spring-boot:run          # 启动服务，默认 http://localhost:8080
mvn test                     # 全部自动化测试
```

配置项（`src/main/resources/application.properties`，均可用环境变量覆盖）：

| 配置 | 环境变量 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `hsm.data-dir` | `HSM_DATA_DIR` | `./hsm-data` | 令牌持久化目录 |
| `hsm.max-pin-attempts` | `HSM_MAX_PIN_ATTEMPTS` | `3` | 每角色连续 PIN 错误锁定阈值 |

## 对象模型

- **令牌（`HsmToken`）**：每个数据目录对应一个令牌，持有 PIN 记录、错误计数、锁定标志与全部密钥对象。
- **角色（`UserType`）**：`SO` 安全管理员可锁定/解锁令牌，解锁会清零普通用户错误计数并关闭全部会话；`USER` 普通用户登录后进行密钥对象与密码运算。
- **会话（`Session`）**：进程内对象，仅存于内存不持久化；每个会话拥有**独立的登录状态**，关闭或清理任意会话不影响其他会话。
- **密钥对象（`StoredKey`）**：
- 类型为 `AES`（128/192/256）与 `RSA`（≥2048）。
- 属性包含 `id`、`label`、`keyType`、`keyBits`、`usages`、`sensitive`、`extractable`、`destroyed`。
- 允许用途 `KeyUsage`：`SIGN`、`VERIFY`、`ENCRYPT`、`DECRYPT`、`WRAP`、`UNWRAP`。
- 敏感/私钥材料在快照中以主密钥 AES-GCM 加密保存且 `extractable=false`，服务不提供任何明文导出接口；RSA 公钥可通过 `/keys/{id}/public` 导出。

## 生命周期

1. **初始化**：`POST /api/hsm/initialize` 建立 SO/USER 两类 PIN（PBKDF2-HMAC-SHA256 + 随机盐）。
2. **打开会话与登录**：未初始化、令牌锁定、未登录都会被拒绝。
3. **密钥管理**：生成、导入、查询、导出公钥、销毁；销毁为墓碑状态，任何后续使用返回 `KEY_DESTROYED`。
4. **密码运算**：RSA 使用 `SHA256withRSA` 签名/验签与 `RSA/ECB/PKCS1Padding` 加解密；AES 使用 `AES/GCM/NoPadding`（随机 12 字节 IV，AAD 绑定 keyId）；摘要使用 `SHA-256`。
5. **包装/解包**：包装密钥必须是允许 `WRAP` 的 AES 密钥，解包需要 `UNWRAP`。信封为 JSON，`header`（算法、位数、用途、敏感性、公钥）作为 AES-GCM 的 AAD 与密文绑定；篡改信封或密文会在 GCM 认证时失败（`UNWRAPPING_FAILED`）。解包后对象的算法、位数与用途集合与源密钥一致、行为等价；用途模板与信封不一致时拒绝（`KEY_USAGE_VIOLATION`）。
6. **锁定/解锁**：锁定后除 `POST /unlock` 与 `GET /status` 等管理操作外，所有操作返回 `TOKEN_LOCKED`。

## 并发语义

- 所有会改变持久化状态的操作在 `HsmToken` 的单一监视器锁内执行，状态变更与原子落盘处于同一临界区，多会话/多线程并发下操作串行化提交，不会出现交错的部分状态。
- 会话表为 `ConcurrentHashMap`，句柄全局递增；会话登录态仅保存在各自的 `Session` 对象上，`closeSession` 只移除目标会话，不触碰其他会话的登录态或进行中的操作。
- 内存密码运算也在临界区内完成后再返回，保证“返回成功”即“已可被其他会话观察到”。

## 崩溃恢复（原子落盘）

数据目录包含两个文件：

- `token.json`：完整令牌快照（PIN 盐/摘要、每角色错误计数与 PIN 锁定、令牌锁定、全部密钥对象）。
- `master.key`：主密钥受随机本地 KEK 的 AES-GCM 包装保存（owner-only 权限），模拟真实令牌的防拆存储。

每次状态变更都走“写临时文件 → `fsync` → 原子 `rename` → 目录 `fsync`”流程：

- 已成功返回的操作结果在任意进程重启后不丢失。
- 未完成的操作只可能留下被覆盖前的旧快照，不会出现部分生效的中间状态。
- PIN 错误计数、PIN 锁定、令牌锁定、销毁状态均随快照持久化。
- 会话不持久化：重启后所有客户端需重新打开会话并登录（与 PKCS#11 的进程/令牌会话语义一致）。

## REST API（`/api/hsm`）

二进制数据统一使用 Base64。

| 方法与路径 | 说明 |
| --- | --- |
| `POST /initialize` | 初始化令牌（`soPin`、`userPin`、`label`） |
| `GET /status` | 管理查询：初始化/锁定、错误计数、会话数、密钥数 |
| `POST /lock` | SO 会话锁定令牌 |
| `POST /unlock` | SO PIN 解锁，清零 USER 计数，关闭全部会话 |
| `POST /sessions` | 打开会话，返回 `sessionHandle` |
| `DELETE /sessions/{handle}` | 关闭单个会话 |
| `POST /sessions/{handle}/login` | 按 `role`（`SO`/`USER`）登录 |
| `POST /sessions/{handle}/logout` | 登出，不影响其他会话 |
| `GET /sessions/{handle}` | 查询会话当前角色 |
| `POST /keys/generate` | 生成 AES/RSA 密钥 |
| `POST /keys/import` | 导入 AES 原始密钥或 RSA 私钥+公钥 |
| `GET /keys/{id}?sessionHandle=` | 查询密钥属性（不含任何材料） |
| `GET /keys/{id}/public?sessionHandle=` | 导出 RSA 公钥 |
| `DELETE /keys/{id}?sessionHandle=` | 销毁密钥 |
| `POST /sign` / `/verify` | RSA 签名/验签 |
| `POST /encrypt` / `/decrypt` | AES-GCM 或 RSA 加解密 |
| `POST /digest` | SHA-256 摘要 |
| `POST /keys/wrap` / `/keys/unwrap` | 密钥包装与解包 |

### 可区分错误码（响应体 `error` 字段）

`TOKEN_NOT_INITIALIZED`、`TOKEN_ALREADY_INITIALIZED`、`TOKEN_LOCKED`、
`SESSION_HANDLE_INVALID`、`ALREADY_LOGGED_IN`、`NOT_LOGGED_IN`、`ROLE_REQUIRED`、
`PIN_INCORRECT`、`PIN_LOCKED`、`KEY_NOT_FOUND`、`KEY_DESTROYED`、`KEY_USAGE_VIOLATION`、
`KEY_SENSITIVE`、`KEY_NOT_EXTRACTABLE`、`INVALID_KEY_TYPE`、`INVALID_ARGUMENT`、
`SIGNATURE_INVALID`、`DECRYPT_FAILED`、`WRAPPING_FAILED`、`UNWRAPPING_FAILED`、
`PERSISTENCE_FAILED`、`INTERNAL_ERROR`。

错误同时映射为合适的 HTTP 状态（404/423/401/403/409/410/400/500），客户端既可按 HTTP
状态粗分，也可按 `error` 精确区分失败原因。

### 快速示例

```bash
curl -s -X POST localhost:8080/api/hsm/initialize \
  -H 'Content-Type: application/json' \
  -d '{"soPin":"so-pin","userPin":"user-pin","label":"demo"}'
HANDLE=$(curl -s -X POST localhost:8080/api/hsm/sessions | sed 's/[^0-9]//g')
curl -s -X POST localhost:8080/api/hsm/sessions/$HANDLE/login \
  -H 'Content-Type: application/json' -d '{"role":"USER","pin":"user-pin"}'
```

## 代码结构

```
hsm/
  model/      枚举（错误/角色/密钥类型/用途）与持久化模型（StoredKey、TokenSnapshot）
  exception/  携带 HsmError 的 HsmException
  session/    Session、SessionManager（进程内会话隔离）
  crypto/     CryptoEngine（JCA 原语：密钥生成、PIN 摘要、RSA、AES-GCM、SHA-256）
  persist/    TokenStore（主密钥保护 + 原子快照读写）
  core/       HsmToken（全部业务语义与访问控制）
  web/        HsmController、HsmExceptionHandler（REST 外观与错误映射）
```

## 测试覆盖

- `LifecycleSessionLoginTest`：生命周期、会话独立性、并发会话隔离、PIN 累计锁定与 SO 解锁、角色分离。
- `KeyLifecycleUsageTest`：生成/导入、AES/RSA 运算、用途拒绝、材料不外泄、销毁后失败、未知密钥。
- `WrapUnwrapTest`：AES/RSA 包装往返、用途保持、用途不匹配拒绝、篡改信封认证失败。
- `CrashRecoveryTest`：密钥与材料、PIN 计数与锁定、令牌锁定、销毁状态在“重启”（同目录新建实例）后恢复。
- `HsmRestFlowTest` / `HsmRestErrorTest`：REST 端到端流程与错误码 HTTP 映射。

## 安全边界说明

这是一个用于开发/测试的**模拟器**：主密钥的本地 KEK 存放在同一数据目录中（POSIX 权限 0600），
不提供真实 HSM 的物理防拆能力。它精确模拟的是 PKCS#11 的**语义与接口行为**
（角色、会话、用途对象、受保护材料、原子持久化），而非硬件攻击抗性。
