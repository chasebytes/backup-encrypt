using System.Security.Cryptography;
using System.Text;
using Backcrypter.Core;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Backcrypter.Core.Tests;

[TestClass]
public sealed class ArchiveServiceTests
{
    private readonly ArchiveService service = new();
    private readonly ArchiveCredentials credentials = new("correct horse battery staple");
    private string root = null!;
    private string Archive => Path.Combine(root, "backup.bcrypt");
    private string Destination => Path.Combine(root, "restored");

    [TestInitialize]
    public void Setup()
    {
        root = Path.Combine(AppContext.BaseDirectory, "TestArtifacts", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
    }

    [TestCleanup]
    public void Cleanup() => Directory.Delete(root, true);

    private string Write(string relative, byte[]? content = null)
    {
        var path = Path.Combine(root, relative);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllBytes(path, content ?? "private sample data"u8.ToArray());
        return path;
    }

    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task MixedSelectionRoundTripsContentsNamesEmptyDirectoriesAndTimestamps(bool withKey)
    {
        var folder = Path.Combine(root, "photos");
        Write("photos/nested/日本語.txt", Encoding.UTF8.GetBytes("hello 🌍"));
        Write("photos/empty.bin", []);
        Write("photos/large.bin", RandomNumberGenerator.GetBytes(2 * EncryptedRecords.ChunkSize + 731));
        Directory.CreateDirectory(Path.Combine(folder, "empty-folder"));
        var single = Write("loose.txt");
        var stamp = new DateTime(2020, 5, 6, 12, 13, 14, DateTimeKind.Utc);
        File.SetLastWriteTimeUtc(single, stamp);
        var auth = credentials;
        if (withKey)
        {
            var key = Path.Combine(root, "secret.bkey");
            ArchiveService.GenerateKeyFile(key);
            auth = credentials with { KeyFilePath = key };
        }
        var reports = new List<ArchiveProgress>();
        await service.CreateAsync([folder, single, single, Path.Combine(folder, "empty.bin")], Archive, auth,
            progress: new CallbackProgress(reports.Add));
        await service.RestoreAsync(Archive, Destination, auth);
        foreach (var source in Directory.GetFiles(folder, "*", SearchOption.AllDirectories).Append(single))
        {
            var restored = Path.Combine(Destination, Path.GetRelativePath(root, source));
            CollectionAssert.AreEqual(await File.ReadAllBytesAsync(source), await File.ReadAllBytesAsync(restored));
        }
        Assert.IsTrue(Directory.Exists(Path.Combine(Destination, "photos", "empty-folder")));
        Assert.AreEqual(stamp, File.GetLastWriteTimeUtc(Path.Combine(Destination, "loose.txt")));
        Assert.IsTrue(reports.Last().BytesProcessed > 2 * EncryptedRecords.ChunkSize);
        Assert.AreEqual(reports.Last().TotalBytes, reports.Last().BytesProcessed);
        AssertClean();
    }

    [TestMethod]
    public async Task RandomSaltProducesDifferentArchivesAndConcealsNamesAndContent()
    {
        var input = Write("confidential-name-1234567.txt");
        await service.CreateAsync([input], Archive, credentials);
        var second = Path.Combine(root, "second.bcrypt");
        await service.CreateAsync([input], second, credentials);
        Assert.IsFalse(File.ReadAllBytes(Archive).SequenceEqual(File.ReadAllBytes(second)));
        var raw = Encoding.UTF8.GetString(File.ReadAllBytes(Archive));
        Assert.IsFalse(raw.Contains(Path.GetFileName(input)));
        Assert.IsFalse(raw.Contains("private sample data"));
    }

    [TestMethod]
    [DataRow(PasswordWorkFactor.Strong)]
    [DataRow(PasswordWorkFactor.Maximum)]
    public async Task WorkFactorIsReadFromArchive(PasswordWorkFactor factor)
    {
        await service.CreateAsync([Write("input")], Archive, credentials, factor);
        await service.RestoreAsync(Archive, Destination, credentials);
        Assert.IsTrue(File.Exists(Path.Combine(Destination, "input")));
    }

    [TestMethod]
    public async Task WrongPasswordDoesNotPublishOrLeaveStaging()
    {
        await service.CreateAsync([Write("input")], Archive, credentials);
        await Assert.ThrowsExceptionAsync<AuthenticationTagMismatchException>(() => service.RestoreAsync(Archive, Destination, new("wrong password")));
        AssertNoRestore();
    }

    [TestMethod]
    public async Task MissingOrWrongKeyFileFails()
    {
        var key = Path.Combine(root, "key.bkey");
        var wrong = Path.Combine(root, "wrong.bkey");
        ArchiveService.GenerateKeyFile(key);
        ArchiveService.GenerateKeyFile(wrong);
        await service.CreateAsync([Write("input")], Archive, credentials with { KeyFilePath = key });
        await Assert.ThrowsExceptionAsync<ArgumentException>(() => service.RestoreAsync(Archive, Destination, credentials));
        await Assert.ThrowsExceptionAsync<AuthenticationTagMismatchException>(() => service.RestoreAsync(Archive, Destination, credentials with { KeyFilePath = wrong }));
        AssertNoRestore();
    }

    [TestMethod]
    [DataRow("ciphertext")]
    [DataRow("salt")]
    [DataRow("truncated")]
    [DataRow("missing-end")]
    [DataRow("appended")]
    [DataRow("oversized-record")]
    [DataRow("version")]
    public async Task CorruptArchivesAreRejected(string corruption)
    {
        await service.CreateAsync([Write("input")], Archive, credentials);
        var data = await File.ReadAllBytesAsync(Archive);
        switch (corruption)
        {
            case "ciphertext": data[^23] ^= 1; break;
            case "salt": data[8] ^= 1; break;
            case "truncated": data = data[..^1]; break;
            case "missing-end": data = data[..^21]; break;
            case "appended": data = [.. data, 42]; break;
            case "oversized-record": BitConverter.GetBytes(int.MaxValue).CopyTo(data, 45); break;
            case "version": data[7] = (byte)'9'; break;
        }
        await File.WriteAllBytesAsync(Archive, data);
        await ExpectFailure(() => service.RestoreAsync(Archive, Destination, credentials));
        AssertNoRestore();
    }

    [TestMethod]
    public async Task ReorderedAuthenticatedRecordsFail()
    {
        await service.CreateAsync([Write("input", RandomNumberGenerator.GetBytes(2 * EncryptedRecords.ChunkSize))], Archive, credentials);
        var data = await File.ReadAllBytesAsync(Archive);
        var start = 45 + 4 + BitConverter.ToInt32(data, 45) + 16;
        var size = EncryptedRecords.ChunkSize + 20;
        var first = data.AsSpan(start, size).ToArray();
        data.AsSpan(start + size, size).CopyTo(data.AsSpan(start, size));
        first.CopyTo(data, start + size);
        await File.WriteAllBytesAsync(Archive, data);
        await ExpectFailure(() => service.RestoreAsync(Archive, Destination, credentials));
        AssertNoRestore();
    }

    [TestMethod]
    [DataRow("../escaped")]
    [DataRow("/absolute")]
    [DataRow("C:/absolute")]
    [DataRow("file:stream")]
    [DataRow("folder\\escaped")]
    [DataRow("CON.txt")]
    [DataRow("trailing. ")]
    [DataRow("a//b")]
    public async Task AuthenticatedUnsafePathsAreRejected(string name)
    {
        MakeArchive((name, 0L));
        await Assert.ThrowsExceptionAsync<InvalidDataException>(() => service.RestoreAsync(Archive, Destination, credentials));
        AssertNoRestore();
        Assert.IsFalse(File.Exists(Path.Combine(root, "escaped")));
    }

    [TestMethod]
    public async Task DuplicateAndCaseCollidingPathsAreRejected()
    {
        MakeArchive(("same", 0L), ("SAME", 0L));
        await Assert.ThrowsExceptionAsync<InvalidDataException>(() => service.RestoreAsync(Archive, Destination, credentials));
        AssertNoRestore();
    }

    [TestMethod]
    public async Task RestoreLimitsAreEnforcedBeforeWritingContents()
    {
        MakeArchive(("huge", 101L));
        await Assert.ThrowsExceptionAsync<InvalidDataException>(() => service.RestoreAsync(Archive, Destination, credentials, limits: new(100)));
        AssertNoRestore();
        File.Delete(Archive);
        MakeArchive(("one", 0L), ("two", 0L));
        await Assert.ThrowsExceptionAsync<InvalidDataException>(() => service.RestoreAsync(Archive, Destination, credentials, limits: new(MaxEntries: 1)));
        AssertNoRestore();
    }

    [TestMethod]
    public async Task CancellationDuringCreationAndRestorationCleansUp()
    {
        var source = Write("large", new byte[3 * EncryptedRecords.ChunkSize]);
        using var createCts = new CancellationTokenSource();
        await Assert.ThrowsExceptionAsync<OperationCanceledException>(() => service.CreateAsync([source], Archive, credentials,
            progress: new CallbackProgress(p => { if (p.BytesProcessed > 0) createCts.Cancel(); }), cancellationToken: createCts.Token));
        Assert.IsFalse(File.Exists(Archive));
        AssertClean();
        await service.CreateAsync([source], Archive, credentials);
        using var restoreCts = new CancellationTokenSource();
        await Assert.ThrowsExceptionAsync<OperationCanceledException>(() => service.RestoreAsync(Archive, Destination, credentials,
            progress: new CallbackProgress(p => { if (p.BytesProcessed > 0) restoreCts.Cancel(); }), cancellationToken: restoreCts.Token));
        AssertNoRestore();
        Assert.AreEqual(3 * EncryptedRecords.ChunkSize, new FileInfo(source).Length);
    }

    [TestMethod]
    public async Task ExistingOutputAndDestinationAreUntouched()
    {
        var input = Write("input");
        await File.WriteAllTextAsync(Archive, "existing backup");
        await Assert.ThrowsExceptionAsync<IOException>(() => service.CreateAsync([input], Archive, credentials));
        Assert.AreEqual("existing backup", await File.ReadAllTextAsync(Archive));
        File.Delete(Archive);
        await service.CreateAsync([input], Archive, credentials);
        Directory.CreateDirectory(Destination);
        await File.WriteAllTextAsync(Path.Combine(Destination, "keep"), "keep");
        await Assert.ThrowsExceptionAsync<IOException>(() => service.RestoreAsync(Archive, Destination, credentials));
        Assert.AreEqual("keep", await File.ReadAllTextAsync(Path.Combine(Destination, "keep")));
    }

    [TestMethod]
    public async Task AmbiguousRootsAndOutputInsideSourceAreRejected()
    {
        var first = Write("a/same.txt");
        var second = Write("b/same.txt");
        await Assert.ThrowsExceptionAsync<ArgumentException>(() => service.CreateAsync([first, second], Archive, credentials));
        await Assert.ThrowsExceptionAsync<ArgumentException>(() => service.CreateAsync([Path.Combine(root, "a")], Path.Combine(root, "a", "self.bcrypt"), credentials));
        AssertClean();
    }

    [TestMethod]
    public async Task EmptyFolderRoundTrips()
    {
        var empty = Path.Combine(root, "empty");
        Directory.CreateDirectory(empty);
        await service.CreateAsync([empty], Archive, credentials);
        await service.RestoreAsync(Archive, Destination, credentials);
        Assert.IsTrue(Directory.Exists(Path.Combine(Destination, "empty")));
    }

    [TestMethod]
    public async Task WeakPasswordAndUnsupportedWorkFactorAreRejected()
    {
        var input = Write("input");
        await Assert.ThrowsExceptionAsync<ArgumentException>(() => service.CreateAsync([input], Archive, new("short")));
        await Assert.ThrowsExceptionAsync<ArgumentOutOfRangeException>(() => service.CreateAsync([input], Archive, credentials, (PasswordWorkFactor)1));
        Assert.IsFalse(File.Exists(Archive));
        AssertClean();
    }

    [TestMethod]
    public async Task LockedSourceFailsWithoutLeavingPartialArchive()
    {
        var input = Write("input");
        using var locked = new FileStream(input, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        await Assert.ThrowsExceptionAsync<IOException>(() => service.CreateAsync([input], Archive, credentials));
        Assert.IsFalse(File.Exists(Archive));
        AssertClean();
    }

    [TestMethod]
    public async Task AlreadyCancelledOperationCreatesNothing()
    {
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();
        try { await service.CreateAsync([Write("input")], Archive, credentials, cancellationToken: cts.Token); Assert.Fail("Expected cancellation."); }
        catch (OperationCanceledException) { }
        Assert.IsFalse(File.Exists(Archive));
        AssertClean();
    }

    [TestMethod]
    public async Task InvalidSelectionsAndKeyFilesLeaveNoOutput()
    {
        await Assert.ThrowsExceptionAsync<ArgumentException>(() => service.CreateAsync([], Archive, credentials));
        await Assert.ThrowsExceptionAsync<FileNotFoundException>(() => service.CreateAsync([Path.Combine(root, "missing")], Archive, credentials));
        var input = Write("input");
        var key = Write("invalid.bkey", [1, 2, 3]);
        await Assert.ThrowsExceptionAsync<ArgumentException>(() => service.CreateAsync([input], Archive, credentials with { KeyFilePath = key }));
        await Assert.ThrowsExceptionAsync<IOException>(() => Task.Run(() => ArchiveService.GenerateKeyFile(key)));
        CollectionAssert.AreEqual(new byte[] { 1, 2, 3 }, await File.ReadAllBytesAsync(key));
        Assert.IsFalse(File.Exists(Archive));
        AssertClean();
    }

    private void MakeArchive(params (string Name, long Length)[] entries)
    {
        using var stream = File.Create(Archive);
        using var records = new EncryptedRecords(stream, credentials, PasswordWorkFactor.Standard);
        foreach (var entry in entries)
        {
            using var memory = new MemoryStream();
            using var writer = new BinaryWriter(memory, Encoding.UTF8, true);
            writer.Write((byte)2);
            var name = Encoding.UTF8.GetBytes(entry.Name);
            writer.Write(name.Length);
            writer.Write(name);
            writer.Write(entry.Length);
            writer.Write(DateTime.UtcNow.Ticks);
            writer.Flush();
            records.Write(memory.ToArray());
        }
        records.Write([0]);
    }
    private static async Task ExpectFailure(Func<Task> action)
    {
        try { await action(); }
        catch (Exception ex) when (ex is InvalidDataException or EndOfStreamException or CryptographicException) { return; }
        Assert.Fail("Expected a damaged archive to fail.");
    }
    private void AssertNoRestore() { Assert.IsFalse(Directory.Exists(Destination)); AssertClean(); }
    private void AssertClean()
    {
        Assert.AreEqual(0, Directory.GetFiles(root, "*.partial").Length);
        Assert.AreEqual(0, Directory.GetDirectories(root, ".backcrypter-*").Length);
    }
    private sealed class CallbackProgress(Action<ArchiveProgress> callback) : IProgress<ArchiveProgress>
    {
        public void Report(ArchiveProgress value) => callback(value);
    }
}
