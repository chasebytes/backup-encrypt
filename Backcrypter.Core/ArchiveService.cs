using System.Security.Cryptography;
using System.Text;

namespace Backcrypter.Core;

public sealed class ArchiveService : IArchiveService
{
    private sealed record Entry(string Source, string Name, bool Directory);

    public Task CreateAsync(IEnumerable<string> sources, string outputPath, ArchiveCredentials credentials,
        PasswordWorkFactor workFactor = PasswordWorkFactor.Standard, IProgress<ArchiveProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        var selection = sources.ToArray();
        return Task.Run(() => Create(selection, outputPath, credentials, workFactor, progress, cancellationToken), cancellationToken);
    }

    public Task RestoreAsync(string archivePath, string destinationPath, ArchiveCredentials credentials,
        IProgress<ArchiveProgress>? progress = null, CancellationToken cancellationToken = default, RestoreLimits? limits = null)
        => Task.Run(() => Restore(archivePath, destinationPath, credentials, progress, cancellationToken, limits ?? new()), cancellationToken);

    public static void GenerateKeyFile(string path)
    {
        byte[] key = RandomNumberGenerator.GetBytes(32);
        try
        {
            using var file = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            file.Write(key);
            file.Flush(true);
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }

    private static void Create(string[] sources, string outputPath, ArchiveCredentials credentials,
        PasswordWorkFactor workFactor, IProgress<ArchiveProgress>? progress, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        string output = Path.GetFullPath(outputPath);
        EnsureNew(output);
        CheckAncestors(Path.GetDirectoryName(output)!);
        progress?.Report(new("Inspecting source files…", 0));
        var entries = Inventory(sources, output, ct);
        long total = entries.Where(x => !x.Directory).Sum(x => new FileInfo(x.Source).Length);
        long done = 0;
        string temp = output + "." + Guid.NewGuid().ToString("N") + ".partial";
        try
        {
            using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                progress?.Report(new("Deriving encryption key…", 0, total));
                using var records = new EncryptedRecords(stream, credentials, workFactor);
                byte[] buffer = new byte[EncryptedRecords.ChunkSize];
                try
                {
                    foreach (var entry in entries)
                    {
                        ct.ThrowIfCancellationRequested();
                        CheckAncestors(entry.Source);
                        progress?.Report(new($"Encrypting {entry.Name}", done, total));
                        using var file = entry.Directory ? null : new FileStream(entry.Source, FileMode.Open, FileAccess.Read, FileShare.Read);
                        long length = file?.Length ?? 0;
                        using var metadata = new MemoryStream();
                        using (var writer = new BinaryWriter(metadata, Encoding.UTF8, true))
                        {
                            writer.Write(entry.Directory ? (byte)1 : (byte)2);
                            byte[] name = Encoding.UTF8.GetBytes(entry.Name);
                            writer.Write(name.Length);
                            writer.Write(name);
                            writer.Write(length);
                            writer.Write(File.GetLastWriteTimeUtc(entry.Source).Ticks);
                        }
                        records.Write(metadata.ToArray());
                        long remaining = length;
                        while (remaining > 0)
                        {
                            ct.ThrowIfCancellationRequested();
                            int count = (int)Math.Min(buffer.Length, remaining);
                            file!.ReadExactly(buffer.AsSpan(0, count));
                            records.Write(buffer.AsSpan(0, count));
                            remaining -= count;
                            done += count;
                            progress?.Report(new($"Encrypting {entry.Name}", done, total));
                        }
                        if (file is not null && file.ReadByte() != -1) throw new IOException("Source changed during backup: " + entry.Source);
                    }
                    ct.ThrowIfCancellationRequested();
                    records.Write([0]); // Authenticated end marker prevents truncation at a record boundary.
                    stream.Flush(true);
                }
                finally { CryptographicOperations.ZeroMemory(buffer); }
            }
            ct.ThrowIfCancellationRequested();
            File.Move(temp, output); // Never overwrite an existing backup.
            progress?.Report(new("Encrypted archive created.", done, total));
        }
        finally { if (File.Exists(temp)) File.Delete(temp); }
    }

    private static void Restore(string archivePath, string destinationPath, ArchiveCredentials credentials,
        IProgress<ArchiveProgress>? progress, CancellationToken ct, RestoreLimits limits)
    {
        if (limits.MaxEntries < 1 || limits.MaxTotalBytes < 0) throw new ArgumentOutOfRangeException(nameof(limits));
        ct.ThrowIfCancellationRequested();
        string destination = Path.TrimEndingDirectorySeparator(Path.GetFullPath(destinationPath));
        EnsureNew(destination);
        string parent = Path.GetDirectoryName(destination) ?? throw new ArgumentException("Choose a new subfolder for restoration.");
        if (!Directory.Exists(parent)) throw new DirectoryNotFoundException("The destination parent folder must exist.");
        CheckAncestors(parent);
        string staging = Path.Combine(parent, ".backcrypter-" + Guid.NewGuid().ToString("N"));
        long done = 0, declared = 0;
        int count = 0;
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var directories = new List<(string Path, DateTime Time)>();
        try
        {
            using (var stream = File.OpenRead(archivePath))
            using (var records = new EncryptedRecords(stream, credentials, null))
            {
                progress?.Report(new("Authenticating and restoring archive…", 0));
                Directory.CreateDirectory(staging);
                while (true)
                {
                    ct.ThrowIfCancellationRequested();
                    byte[] metadata = records.Read();
                    try
                    {
                        if (metadata.Length == 1 && metadata[0] == 0) break;
                        if (++count > limits.MaxEntries) throw new InvalidDataException("Archive exceeds the entry limit.");
                        using var reader = new BinaryReader(new MemoryStream(metadata), new UTF8Encoding(false, true));
                        byte type = reader.ReadByte();
                        if (type is not (1 or 2)) throw new InvalidDataException("Invalid entry type.");
                        int nameLength = reader.ReadInt32();
                        if (nameLength is < 1 or > 32768 || nameLength > metadata.Length - 21)
                            throw new InvalidDataException("Invalid entry name length.");
                        string name = new UTF8Encoding(false, true).GetString(reader.ReadBytes(nameLength));
                        ValidateName(name);
                        if (!names.Add(name)) throw new InvalidDataException("Duplicate archive path.");
                        long length = reader.ReadInt64();
                        long ticks = reader.ReadInt64();
                        if (reader.BaseStream.Position != metadata.Length || length < 0 || (type == 1 && length != 0)
                            || length > limits.MaxTotalBytes - declared || ticks < DateTime.MinValue.Ticks || ticks > DateTime.MaxValue.Ticks)
                            throw new InvalidDataException("Invalid entry metadata or restore size limit exceeded.");
                        declared += length;
                        string target = Path.GetFullPath(Path.Combine(staging, name.Replace('/', Path.DirectorySeparatorChar)));
                        if (!target.StartsWith(staging + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                            throw new InvalidDataException("Entry escapes the destination.");
                        DateTime timestamp = new(ticks, DateTimeKind.Utc);
                        progress?.Report(new($"Restoring {name}", done));
                        if (type == 1)
                        {
                            Directory.CreateDirectory(target);
                            directories.Add((target, timestamp));
                            continue;
                        }
                        Directory.CreateDirectory(Path.GetDirectoryName(target)!);
                        using (var output = new FileStream(target, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                        {
                            long remaining = length;
                            while (remaining > 0)
                            {
                                ct.ThrowIfCancellationRequested();
                                byte[] data = records.Read();
                                try
                                {
                                    if (data.Length != Math.Min(EncryptedRecords.ChunkSize, remaining))
                                        throw new InvalidDataException("Unexpected file record size.");
                                    output.Write(data);
                                    remaining -= data.Length;
                                    done += data.Length;
                                    progress?.Report(new($"Restoring {name}", done));
                                }
                                finally { CryptographicOperations.ZeroMemory(data); }
                            }
                        }
                        File.SetLastWriteTimeUtc(target, timestamp);
                    }
                    finally { CryptographicOperations.ZeroMemory(metadata); }
                }
                if (stream.ReadByte() != -1) throw new InvalidDataException("Unexpected data after archive end.");
            }
            foreach (var dir in directories.OrderByDescending(x => x.Path.Length)) Directory.SetLastWriteTimeUtc(dir.Path, dir.Time);
            ct.ThrowIfCancellationRequested();
            Directory.Move(staging, destination);
            progress?.Report(new("Archive verified. Restoration complete.", done, done));
        }
        finally { if (Directory.Exists(staging)) Directory.Delete(staging, true); }
    }

    private static List<Entry> Inventory(string[] sources, string output, CancellationToken ct)
    {
        if (sources.Length == 0) throw new ArgumentException("Select at least one file or folder.");
        var roots = sources.Select(x => Path.TrimEndingDirectorySeparator(Path.GetFullPath(x)))
            .Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        // Selecting a folder already includes any explicitly selected descendants.
        roots = roots.Where(x => !roots.Any(y => !x.Equals(y, StringComparison.OrdinalIgnoreCase)
            && Directory.Exists(y) && x.StartsWith(y + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))).ToArray();
        var entries = new List<Entry>();
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (string root in roots)
        {
            if (output.Equals(root, StringComparison.OrdinalIgnoreCase) || output.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException("Save the archive outside the selected source folders.");
            Add(root, Path.GetFileName(root));
        }
        return entries;

        void Add(string path, string name)
        {
            ct.ThrowIfCancellationRequested();
            CheckAncestors(path);
            ValidateName(name);
            if (!names.Add(name)) throw new ArgumentException("Selected sources have colliding archive names: " + name);
            bool directory = Directory.Exists(path);
            if (!directory && !File.Exists(path)) throw new FileNotFoundException("Source not found.", path);
            entries.Add(new(path, name, directory));
            if (directory)
                foreach (string child in Directory.EnumerateFileSystemEntries(path).Order(StringComparer.OrdinalIgnoreCase))
                    Add(child, name + "/" + Path.GetFileName(child));
        }
    }

    internal static void ValidateName(string name)
    {
        if (Encoding.UTF8.GetByteCount(name) > 32768) throw new InvalidDataException("Archive path is too long.");
        foreach (string part in name.Split('/'))
        {
            string stem = part.Split('.')[0];
            if (part.Length == 0 || part is "." or ".." || part.EndsWith(' ') || part.EndsWith('.')
                || part.Any(c => c < 32 || "\\:<>\"|?*".Contains(c))
                || new[] { "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$" }.Contains(stem, StringComparer.OrdinalIgnoreCase)
                || (stem.Length == 4 && (stem.StartsWith("COM", StringComparison.OrdinalIgnoreCase) || stem.StartsWith("LPT", StringComparison.OrdinalIgnoreCase))
                    && "123456789¹²³".Contains(stem[3])))
                throw new InvalidDataException("Unsafe or unsupported archive path: " + name);
        }
    }

    private static void EnsureNew(string path)
    {
        if (File.Exists(path) || Directory.Exists(path)) throw new IOException("The output already exists. Choose a new name.");
    }

    private static void CheckAncestors(string path)
    {
        for (string? current = Path.GetFullPath(path); current is not null; current = Path.GetDirectoryName(current))
            if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                throw new IOException("Symbolic links, junctions, and other reparse points are not supported: " + current);
    }
}
