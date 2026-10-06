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
- 敏感/私钥材料在快照中以主密钥 AES-GCM 加密保存，服务不提供任何明文导出接口；RSA 公钥可通过 `/keys/{id}/public` 导出。

### 角色权限规则

- 密钥对象管理与密码运算（生成、导入、属性查询、导出公钥、销毁、签名、验签、加密、解密、摘要、包装、解包）**只允许 `USER` 会话**执行。
- `SO` 会话执行上述任何操作都会被拒绝，返回 `ROLE_REQUIRED`（HTTP 403），与未登录
  （`NOT_LOGGED_IN`）、会话句柄无效（`SESSION_HANDLE_INVALID`）、令牌锁定（`TOKEN_LOCKED`）明确区分。
- 管理操作保持可用：`POST /lock`（SO 会话）、`POST /unlock`（SO PIN）、`GET /status`、会话打开/关闭/清理。
- 令牌锁定后，除解锁与管理查询外的所有操作仍返回 `TOKEN_LOCKED`。

### 密钥属性：`extractable`（可导出性）

- 含义：是否允许该密钥被 `POST /keys/wrap` 包装导出。
- 默认值：`false`。生成（`POST /keys/generate`）与导入（`POST /keys/import`）时可显式传入
  `extractable: true/false`；不传入时保持既有默认（不可导出），既有客户端无需修改请求。
- 该属性随令牌快照持久化，进程重启后保持一致，并在 `GET /keys/{id}` 中如实返回。
- 对不可导出密钥执行包装会被拒绝，返回 `KEY_NOT_EXTRACTABLE`（HTTP 403），与用途不允许
  （`KEY_USAGE_VIOLATION`）、密钥不存在（`KEY_NOT_FOUND`）、密钥已销毁（`KEY_DESTROYED`）互相区分。
- 可导出密钥被包装后，解包得到的副本保留同样的 `extractable` 取值。

### 会话清理

- `DELETE /api/hsm/sessions` 一次性清理全部会话：所有已发放句柄立即失效，客户端需重新打开会话并登录。
- 清理只影响会话状态：不改变令牌锁定状态、PIN 错误计数、密钥对象及其约束；随后可正常新开会话与登录。
- `DELETE /api/hsm/sessions/{handle}` 只关闭单个会话，与整体清理互不干扰。

## 生命周期

1. **初始化**：`POST /api/hsm/initialize` 建立 SO/USER 两类 PIN（PBKDF2-HMAC-SHA256 + 随机盐）。
2. **打开会话与登录**：未初始化、令牌锁定、未登录都会被拒绝。
3. **密钥管理**：生成、导入、查询、导出公钥、销毁；销毁为墓碑状态，任何后续使用返回 `KEY_DESTROYED`。
4. **密码运算**：RSA 使用 `SHA256withRSA` 签名/验签与 `RSA/ECB/PKCS1Padding` 加解密；AES 使用 `AES/GCM/NoPadding`（随机 12 字节 IV，AAD 为与密钥 id 无关的固定常量，保证包装副本与源密钥互通）；摘要使用 `SHA-256`。
5. **包装/解包**：包装密钥必须是允许 `WRAP` 的 AES 密钥，解包需要 `UNWRAP`；被包装密钥必须 `extractable=true`。信封为 JSON，`header`（算法、位数、用途、敏感性、可导出性、公钥）作为 AES-GCM 的 AAD 与密文绑定；篡改信封或密文会在 GCM 认证时失败（`UNWRAPPING_FAILED`）。解包后对象的算法、位数、用途集合、敏感性与可导出性与源密钥完全一致；用途模板与信封不一致时拒绝（`KEY_USAGE_VIOLATION`）。
6. **锁定/解锁**：锁定后除 `POST /unlock` 与 `GET /status` 等管理操作外，所有操作返回 `TOKEN_LOCKED`。

### 包装/解包互通语义

解包得到的副本与源密钥**行为等价、双向互通**：

- 源密钥加密的数据可由副本解密，副本加密的数据可由源密钥解密（AES 与 RSA 均成立）。
- 源密钥产生的签名可由副本验签通过，副本产生的签名可由源密钥验签通过。
- 副本在密钥类型、长度、允许用途集合、敏感性与可导出性上与源密钥完全一致，往返不会放宽或丢失任何约束。
- 互通性跨进程重启保持：重启前包装的信封可在重启后解包，副本与源密钥的双向互通在重启后依然成立。

## 并发语义

- 所有会改变持久化状态的操作在 `HsmToken` 的单一监视器锁内执行，状态变更与原子落盘处于同一临界区，多会话/多线程并发下操作串行化提交，不会出现交错的部分状态。
- 会话表为 `ConcurrentHashMap`，句柄全局递增；会话登录态仅保存在各自的 `Session` 对象上，`closeSession` 只移除目标会话，不触碰其他会话的登录态或进行中的操作。
- `closeAllSessions` 同样在该锁内执行，与包装、解包、销毁等操作串行化：任一操作要么完全生效要么完全无效，不会出现半生效状态。
- 包装/解包过程中若包装密钥或目标密钥已被销毁，操作明确失败并返回 `KEY_DESTROYED`；被篡改的信封在 GCM 认证处失败（`UNWRAPPING_FAILED`），不影响其他密钥与其他会话。
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
| `DELETE /sessions` | 一次性清理全部会话（只影响会话状态） |
| `DELETE /sessions/{handle}` | 关闭单个会话 |
| `POST /sessions/{handle}/login` | 按 `role`（`SO`/`USER`）登录 |
| `POST /sessions/{handle}/logout` | 登出，不影响其他会话 |
| `GET /sessions/{handle}` | 查询会话当前角色 |
| `POST /keys/generate` | 生成 AES/RSA 密钥（可选 `extractable`，默认 `false`） |
| `POST /keys/import` | 导入 AES 原始密钥或 RSA 私钥+公钥（可选 `extractable`，默认 `false`） |
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
- `RoleAccessControlTest`：SO 会话对全部密钥管理与密码运算的越权拒绝（`ROLE_REQUIRED`）、与未登录/句柄无效/令牌锁定的区分、重启后角色规则保持。
- `KeyLifecycleUsageTest`：生成/导入、AES/RSA 运算、用途拒绝、材料不外泄、销毁后失败、未知密钥。
- `ExtractableKeyTest`：`extractable` 默认值、显式指定、不可导出拒绝原因可区分、副本保留可导出性、销毁/缺失密钥原因不混同、重启后保持。
- `WrapUnwrapTest`：AES/RSA 包装往返、源↔副本双向加解密与签名验签互通、用途保持、用途不匹配拒绝、篡改信封认证失败。
- `RestartConsistencyTest`：重启前包装重启后解包、互通性跨重启保持、可导出性与用途约束跨重启保持、会话清理规则与角色规则跨重启保持。
- `SessionCleanupTest`：一次性清理全部会话、清理只影响会话状态、单会话关闭与整体清理互不干扰。
- `ConcurrencyConsistencyTest`：并发包装/解包/销毁/清理的原子性、销毁后相关操作明确失败、篡改信封不影响其他密钥与会话。
- `CrashRecoveryTest`：密钥与材料、PIN 计数与锁定、令牌锁定、销毁状态在“重启”（同目录新建实例）后恢复。
- `HsmRestFlowTest` / `HsmRestErrorTest` / `HsmRestSecurityTest`：REST 端到端流程、错误码 HTTP 映射、SO 越权 403、`extractable` 字段、会话清理端点。

## 本地验证

```bash
mvn test                                   # 全部自动化测试
mvn test -Dtest='WrapUnwrapTest'           # 只跑包装/解包互通测试
mvn spring-boot:run                        # 本地启动后可用上方 curl 示例手工验证
```

## 安全边界说明

这是一个用于开发/测试的**模拟器**：主密钥的本地 KEK 存放在同一数据目录中（POSIX 权限 0600），
不提供真实 HSM 的物理防拆能力。它精确模拟的是 PKCS#11 的**语义与接口行为**
（角色、会话、用途对象、受保护材料、原子持久化），而非硬件攻击抗性。
