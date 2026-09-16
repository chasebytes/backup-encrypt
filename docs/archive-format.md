# Backcrypter archive format, version 1

The `.bcrypt` extension identifies the Backcrypter container. It is unrelated to bcrypt password hashes. All numeric fields are little-endian. Paths are UTF-8 with `/` separators; integers have fixed widths. This format does not use compression.

## Header: 45 bytes

| Offset | Size | Meaning |
| --- | --- | --- |
| 0 | 8 | ASCII `BCHIVE01`; the final two bytes identify version 1 |
| 8 | 32 | Random per-archive PBKDF2 salt |
| 40 | 4 | Signed iteration count: 600000, 1200000, or 2400000 |
| 44 | 1 | Key-file flag: 0 or 1 |

Readers reject unknown magic, versions, flags, or work factors before attempting expensive key derivation. The supported work-factor set also bounds attacker-controlled KDF work. A header is not trusted until authenticated by a record.

Derive 32 bytes with PBKDF2-HMAC-SHA256 over the exact UTF-8 password bytes and the stored salt. No Unicode normalization is performed. For password-only archives, these bytes are the AES key. For key-file archives, the final AES key is `HMAC-SHA256(key = 32 key-file bytes, message = PBKDF2 result)`. Every archive receives a fresh random salt, including archives created with identical credentials.

## Authenticated record framing

Every record consists of a signed 4-byte plaintext length, ciphertext of that length, and a 16-byte AES-GCM tag. Length must be between 1 and 1,048,576 bytes. Encryption preserves length.

The record counter starts at zero and increases once per record. A nonce is four zero bytes followed by the 8-byte little-endian unsigned counter. Associated data is the full 45-byte header, followed by that 8-byte counter, followed by the 4-byte record length. Neither the nonce nor the counter is stored separately. The implementation permits counters 0 through 4,294,967,294 and refuses further records. Record ordering, lengths, and header changes are therefore authenticated as well as ciphertext.

## Payload sequence

Each entry begins with one encrypted metadata record:

| Field | Size | Meaning |
| --- | --- | --- |
| Type | 1 | 1 = directory; 2 = regular file |
| Path length | 4 | UTF-8 byte count, 1 through 32768 |
| Path | variable | Relative archive path including its selected top-level name |
| File length | 8 | Nonnegative signed content length; zero for directories |
| Last-write timestamp | 8 | Signed .NET UTC ticks, validated against `DateTime` range |

Metadata records cannot contain extra bytes. Directory entries have no content records. File entries have exactly enough subsequent encrypted content records to cover the declared file length. Each content record is exactly 1 MiB except the final record, which contains the remaining bytes. Empty files have no content records. Content records have no type prefix; their role and expected size follow from the authenticated metadata.

After the last entry, a one-byte encrypted record containing zero marks the end. The reader requires this marker and physical EOF immediately after it. This prevents an archive truncated between entries from being mistaken for a complete backup, and rejects appended data. Reordered or substituted records fail tag validation because their counter or archive header differs.

## Extraction rules

Readers reject absolute paths, empty segments, `.` and `..`, backslashes, colons, control characters, Windows-invalid characters, trailing dots/spaces, reserved Windows device names, and case-insensitive duplicate paths. A final normalized-path check requires every entry to stay beneath the staging directory. Files use exclusive create-new semantics; conflicting file/directory structures fail restoration.

The caller's entry and total-content limits are checked before materializing each entry's contents. The desktop uses the library defaults: one million entries and 1 TiB. The reader never allocates a buffer based on an unbounded file length. It authenticates each bounded record before writing its plaintext, but publishes the staging directory only after the authenticated end marker and EOF check succeed.

Only new destination directories are supported. This prevents restoration from overwriting existing user files and makes failure cleanup confined to the newly created staging directory. The parent directory must be trusted; this is not a defense against privileged or same-user attackers modifying filesystem objects concurrently.
