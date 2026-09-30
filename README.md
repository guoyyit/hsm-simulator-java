# HSM Simulator (Java)

A local Hardware Security Module simulation service. It exposes session, login,
and key-object management semantics compatible with mainstream cryptographic
token interfaces (PKCS#11-style), over a JSON/HTTP API backed by the Java
Cryptography Architecture (JCA).

- Token lifecycle: initialization, locking and unlocking with two roles.
- Independent sessions that coexist concurrently within one process.
- Role-based login (`USER` / Security Officer `SO`) with per-role PIN failure
  counters and automatic lockout.
- Key objects with attributes and usage constraints; private/sensitive material
  never leaves the service in plaintext.
- Sign, verify, encrypt, decrypt and digest operations with distinct,
  machine-readable failure codes.
- Key wrap/unwrap with a hybrid envelope so an unwrapped key behaves
  identically to the original, including its usage constraints.
- Atomic, encrypted persistence; every acknowledged change survives process
  restart and no partially applied state is ever visible.

## Build & Run

```bash
mvn spring-boot:run
# or
mvn package && java -jar target/hsm-simulator-java-1.0-SNAPSHOT.jar
```

Configuration (in `src/main/resources/application.properties` or via
environment/property override):

| Property        | Default      | Purpose                                   |
|-----------------|--------------|-------------------------------------------|
| `hsm.data.dir`  | `./hsm-data` | Directory for the state file and master key |
| `server.port`   | `8080`       | HTTP port                                 |

## Object Model

- **Token** (`TokenState`): the single logical token. Holds initialization
  flag, lock flag, PBKDF2-hashed SO and USER PINs, per-role failure counters and
  lock flags, the max-attempts threshold (3), and the key object table.
- **Session** (`Session`): an in-memory, transient handle with an UUID, an open
  flag, and an independent login role (`USER`, `SO`, or anonymous). Sessions are
  never persisted (matching PKCS#11 semantics).
- **Key object** (`KeyObject`):
  - `id`, `label`, `keyType` (`RSA` | `AES`).
  - `usages`: subset of `SIGN`, `VERIFY`, `ENCRYPT`, `DECRYPT`, `WRAP`,
    `UNWRAP`.
  - `sensitive`, `extractable`, `destroyed`.
  - Material: PKCS#8 private key / X.509 public key bytes for RSA; raw key bytes
    for AES.
  - API responses return a sanitized view: the private material field is always
    stripped. Only an RSA public component is exposed.
- **Wrapped key** (`WrappedKey`): version, algorithm id, wrapping key id, IV,
  RSA-OAEP-encrypted content-encryption key (CEK), and AES-GCM ciphertext of a
  JSON envelope carrying the key material **and** all attributes (type, label,
  usages, sensitive, extractable).

## Lifecycle

1. `POST /api/hsm/init` creates the two roles and their PINs; the token starts
   unlocked. Re-initializing an existing token fails with
   `TOKEN_ALREADY_INITIALIZED`.
2. Open sessions, then `login` as `USER` or `SO`.
3. An SO session can `lock` the token. While locked every operation is rejected
   with `TOKEN_LOCKED` except:
   - `GET /api/hsm/status` (management query), and
   - `POST /api/hsm/unlock` (SO PIN required).
   Locking also closes all sessions.
4. `unlock` verifies the SO PIN, clears the token lock, and resets the USER
   failure counter / lock.
5. Keys are generated or imported by a logged-in `USER`, used according to
   their `usages`, and destroyed explicitly. Destroyed keys are tombstoned:
   subsequent lookup or use fails with `KEY_NOT_FOUND`.

### PIN lockout

- Failures accumulate independently per role.
- The 3rd consecutive failure locks that role (`PIN_LOCKED`); earlier failures
- return `INVALID_PIN`.
- A successful login resets that role's counter.
- SO unlock resets the USER counter and lock. Counter and lock flags are part
  of the persisted token state, so lockout survives restart.

## Cryptographic Operations

| Operation | Key type | Required usage | Algorithm                          |
|-----------|----------|----------------|------------------------------------|
| sign      | RSA      | `SIGN`         | SHA256withRSA                      |
| verify    | RSA      | `VERIFY`       | SHA256withRSA                      |
| encrypt   | RSA/AES  | `ENCRYPT`      | RSA/ECB/OAEP-SHA256 or AES-128-GCM |
| decrypt   | RSA/AES  | `DECRYPT`      | same as encrypt                    |
| digest    | -        | -              | SHA-256                            |
| wrap      | RSA KEK  | `WRAP`         | RSA-OAEP + AES-256-GCM envelope    |
| unwrap    | RSA KEK  | `UNWRAP`       | same envelope                      |

Authorization order for key operations: token initialized -> token unlocked ->
session exists -> session logged in as `USER` (SO only performs token
administration) -> key exists and not destroyed -> key allows the requested
usage. Each violation produces a distinct error code.

### Wrap/unwrap round trip

- Only RSA keys with `WRAP`/`UNWRAP` may act as key-encryption keys.
- The target key must be `extractable`; otherwise `KEY_NOT_EXTRACTABLE`.
- The GCM envelope authenticates the key attributes, so tampering is rejected,
  and the unwrapped key keeps exactly the original `usages`, `sensitive` and
  `extractable` values. The new key gets a fresh UUID but is cryptographically
  identical and interoperates with data produced by the original key.

## Concurrency Semantics

- Sessions live in a `ConcurrentHashMap`; login state is per session and
  volatile. Closing one session removes only that entry; other sessions keep
  their login state and ongoing operations.
- All token-state access is guarded by a fair `ReentrantReadWriteLock`:
  read lock for status/queries/crypto use, write lock for initialization,
  login (counter updates), key changes, wrap-import and lock changes.
- Every mutating operation persists before returning (see below), so concurrent
  readers always observe the last committed state.

## Crash Recovery

- State file: `<data.dir>/token.state` — JSON serialized with Jackson, then
  AES-256-GCM encrypted.
- Master key: `<data.dir>/master.key` — 256-bit random key created on first use,
  written via temp-file + `fsync` + atomic rename, with `0600` permissions on
  POSIX systems.
- Each save serializes the whole state, writes `token.state.tmp`, forces it to
  disk (`fsync`), then atomically renames it over the old file. A crash leaves
  either the previous complete file or the new complete file — never a mix.
- State changes are applied in memory and persisted inside the same write lock;
  the response is returned only after the rename succeeds. If persistence fails
  the caller receives `STORAGE_ERROR`. (The in-memory copy can be ahead of disk
  in that error case; successful responses are always durable by construction.)
- On startup the service loads and decrypts the state file. Keys, PIN hashes,
  failure counters, role lock flags and the token lock are restored; sessions
  start empty as required by the session model.

## HTTP API

Key/crypto requests carry the session id in the `X-Session-Id` header. Binary
payloads are Base64 encoded (`data` for encrypt/sign/verify is UTF-8 text;
ciphertext/signature/import material are Base64).

| Method   | Path                                        | Notes                          |
|----------|---------------------------------------------|--------------------------------|
| POST     | `/api/hsm/init`                             | `{soPin,userPin}`              |
| GET      | `/api/hsm/status`                           | allowed while locked           |
| POST     | `/api/hsm/lock/{sessionId}`                 | SO session                     |
| POST     | `/api/hsm/unlock`                           | `{pin}` SO                     |
| POST     | `/api/hsm/sessions`                         | returns `sessionId`            |
| DELETE   | `/api/hsm/sessions/{sessionId}`             | close one session              |
| DELETE   | `/api/hsm/sessions`                         | close all sessions            |
| POST     | `/api/hsm/sessions/{sessionId}/login`       | `{role,pin}`                   |
| POST     | `/api/hsm/sessions/{sessionId}/logout`      |                                |
| POST     | `/api/hsm/keys`                             | generate key                   |
| POST     | `/api/hsm/keys/import`                      | import AES material            |
| GET      | `/api/hsm/keys`                             | list keys                      |
| GET      | `/api/hsm/keys/{keyId}`                     | key attributes only            |
| DELETE   | `/api/hsm/keys/{keyId}`                     | destroy                        |
| POST     | `/api/hsm/keys/{keyId}/sign`                |                                |
| POST     | `/api/hsm/keys/{keyId}/verify`              |                                |
| POST     | `/api/hsm/keys/{keyId}/encrypt`             |                                |
| POST     | `/api/hsm/keys/{keyId}/decrypt`             |                                |
| POST     | `/api/hsm/digest`                           |                                |
| POST     | `/api/hsm/keys/{keyId}/wrap`                | `{wrappingKeyId}`              |
| POST     | `/api/hsm/keys/unwrap`                      | `{wrappingKeyId,wrappedKey}`   |

### Error codes

`TOKEN_NOT_INITIALIZED`, `TOKEN_ALREADY_INITIALIZED`, `TOKEN_LOCKED`,
`INVALID_PIN`, `PIN_LOCKED`, `SESSION_NOT_FOUND`, `NOT_LOGGED_IN`,
`ACCESS_DENIED`, `KEY_NOT_FOUND`, `KEY_DESTROYED`, `USAGE_NOT_ALLOWED`,
`KEY_NOT_EXTRACTABLE`, `INVALID_ARGUMENT`, `CRYPTO_FAILED`, `STORAGE_ERROR`,
`UNSUPPORTED_OPERATION`.

Errors are returned as `{"code": "...", "message": "..."}` with an appropriate
HTTP status (e.g. 401 for PIN/login, 403 for role/usage denial, 404 unknown
session/key, 423 locked token/PIN, 409 already initialized, 500 storage).

## Tests

```bash
mvn test
```

- `SessionConcurrencyTest` — parallel sessions, login independence, isolation
  on close, 8-thread concurrent sign/verify.
- `PinLockoutTest` — per-role counter, lockout threshold, restart persistence,
  reset on SO unlock and on successful login.
- `KeyUsageTest` — RSA sign/verify, AES GCM encrypt/decrypt, usage rejection,
  destroyed-key failure, private material never exposed, SO denial.
- `WrapRoundTripTest` — equivalence after unwrap, usage/extractability checks,
  tamper detection.
- `CrashRecoveryTest` — keys/destruction survive restart, wrapped keys remain
  usable, token lock and PINs are recovered.
- `HsmControllerIntegrationTest` — end-to-end HTTP workflow and status codes.

## Security Notes

This is a simulator for local development and testing. Keys are protected at
rest with an automatically generated master key stored beside the state file;
it is not backed by an HSM/TPM and does not provide physical tamper resistance.
