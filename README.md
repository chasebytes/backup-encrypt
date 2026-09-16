# Backcrypter

Backcrypter creates one encrypted `.bcrypt` backup from a selection of files and folders, then restores it using the same password and optional key file. The desktop application uses WPF with a declarative XAML layout; encryption and filesystem operations live in a separate, platform-neutral .NET 10 library.

## Run and test

Install the .NET 10 SDK. The desktop application requires Windows.

```powershell
dotnet build backcrypter.slnx --configuration Release
dotnet run --project Backcrypter --configuration Release
dotnet test backcrypter.slnx --configuration Release
```

In Visual Studio, open `backcrypter.slnx` and use `Backcrypter` as the startup project. Open `Backcrypter/MainWindow.xaml` for the WPF designer or XAML editor. Layout and styling live in XAML; `MainWindow.xaml.cs` wires the dialogs and archive operations. The MSTest suite appears in Test Explorer. Tests create real files beneath the test assembly's `bin/.../TestArtifacts/<unique-id>` directory and remove each fixture after running.

## Create a backup

The app starts in dark mode. Use **Dark mode** in the header to switch to the light palette. **Create backup** and **Restore / decrypt** have separate credentials and controls. The activity console and cancellation button remain visible while the tab contents scroll.

1. Use **Add files** and **Add folders** to accumulate a mixed selection. Both dialogs support multiple selections. Remove individual selections or clear the list as needed.
2. Enter and confirm a passphrase of at least 12 characters. Prefer a long, unique passphrase; a length minimum alone does not guarantee strength.
3. Choose a password work factor. Standard, Strong, and Maximum use 600,000, 1,200,000, and 2,400,000 PBKDF2-HMAC-SHA256 iterations respectively. Increasing this makes password derivation slower for both you and someone guessing passwords. Every setting uses AES-256-GCM.
4. Choose **Password only** (the default), or **Password + key file** under Protection. Both use AES-256-GCM; the password derives the encryption key rather than merely gating access in the app. In key-file mode, generate or select a `.bkey` file. Generated keys contain 32 cryptographically random bytes. This mode requires **both** the password and the exact key file to restore. Switching back to password-only mode excludes any previously selected key file from the operation. Keep a separate safe copy of the key, apart from the uploaded archive. There is no password reset or recovery key. Base64 and toy ciphers are intentionally not offered as protection options.
5. Choose **Create encrypted archive** and save outside the selected source directories. Existing output files are refused, even if the save dialog offers to replace them.

Source files are retained. The progress bar and console report the current file and bytes processed, and **Cancel** stops work and cleans up the temporary archive. Closing during an operation requests cancellation; close again after cleanup finishes. Password fields are cleared after each operation.

Selected folders retain their top-level name, subdirectories, and empty directories. Loose files retain their filename. Repeated selections and children of selected folders are folded into one selection. Distinct roots with the same name are rejected so that nothing is silently renamed or overwritten.

## Restore a backup

Open **Restore / decrypt**. Browse to the encrypted archive, then browse for a destination parent directory. The destination field suggests a new timestamped subfolder, and you can edit the full path before starting. Enter the original password and, if applicable, select the original key file in this tab. Click **Decrypt and restore**. Restoration has its own credentials, independent of the Create tab, and reads encryption settings from the archive automatically. There is no password confirmation or work-factor choice during restoration.

Files first go into a temporary staging directory next to the destination. The destination appears only after all encrypted records and the archive's end marker have authenticated. Wrong credentials, corruption, cancellation, unsafe paths, and size-limit failures remove staging during normal error handling. Existing destinations are never merged or overwritten.

## Library boundary

`Backcrypter.Core` has no desktop UI dependency or third-party runtime packages. `IArchiveService` exposes creation and restoration with `IProgress<ArchiveProgress>` and `CancellationToken`; `ArchiveService` is the filesystem implementation. Work is dispatched off the caller's thread. A future web host can supply server-controlled paths, credentials, progress handling, concurrency limits, and access control around this service.

```csharp
IArchiveService archives = new ArchiveService();
var credentials = new ArchiveCredentials(password, optionalKeyFilePath);
await archives.CreateAsync(sourcePaths, outputPath, credentials,
    PasswordWorkFactor.Standard, progress, cancellationToken);

await archives.RestoreAsync(outputPath, newDestinationPath, credentials,
    progress, cancellationToken,
    new RestoreLimits(MaxTotalBytes: 100L * 1024 * 1024 * 1024, MaxEntries: 100_000));
```

`ArchiveService.GenerateKeyFile(path)` creates a key without overwriting an existing file. The default restore limits are 1 TiB of file contents and one million entries. Hosts should select smaller limits where appropriate. Memory for file contents is bounded by the 1 MiB record size; source inventory and restore path tracking scale with entry count. Errors propagate to the caller; cryptographic authentication failures deliberately do not distinguish incorrect credentials from corruption.

## Security and backup scope

This is a versioned custom container using the .NET cryptography implementation, not ZIP encryption or an implementation of the bcrypt password-hashing algorithm. Filenames, relative paths, timestamps, and contents are encrypted. A random salt derives a fresh archive key; each record uses a distinct counter nonce and authenticates its position, length, and header. See [the archive format](docs/archive-format.md) and Microsoft's [AES-GCM API requirements](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.aesgcm.encrypt?view=net-10.0).

The initial version deliberately has the following boundaries:

- No compression or padding. Ciphertext size, record boundaries, version, work factor, and whether a key file is required are visible. The format adds a small overhead to the input data size.
- Ordinary file contents, directory structure, and last-write timestamps are preserved. ACLs, ownership, alternate data streams, hard-link relationships, sparse allocation, and other filesystem metadata are not backed up.
- Symbolic links, junctions, and other reparse points are rejected, including reparse-point ancestors. Windows-unsafe filenames are rejected even when using the library on another platform.
- This is not a filesystem snapshot. Close applications that modify the source files before backing up. Read failures abort creation; a successful backup does not guarantee all files represent the same instant in time.
- Creation writes only encrypted temporary output. Restoration necessarily writes plaintext into staging on the destination disk. Staging inherits the parent directory's permissions. Use a private, trusted destination directory and device encryption when local disk exposure matters.
- Normal failure cleanup is not secure erasure. A process crash or power loss can leave `.partial` files or `.backcrypter-*` staging directories. Inspect these before deleting them; restoration staging may contain plaintext. Cleanup can also fail if the filesystem becomes unavailable.
- Credentials exist in process memory while in use. Derived byte buffers are cleared where practical; managed password strings cannot be reliably erased. Local administrators, malware, and hostile concurrent filesystem changes are outside this tool's protection.
- Standard cryptographic primitives do not amount to an independent audit of this new container implementation. Keep original backups and verify a restore before relying on an archive as your only copy.

The functional suite covers mixed and overlapping selections, multi-record binary files, Unicode names, empty files and directories, timestamps, password/key modes, all work factors, randomized encryption, authentication failures, reordered records, truncation, trailing data, path traversal, duplicate paths, restore limits, cancellation cleanup, and preservation of existing outputs.

