namespace Backcrypter.Core;

public enum PasswordWorkFactor { Standard = 600_000, Strong = 1_200_000, Maximum = 2_400_000 }

public sealed record ArchiveCredentials(string Password, string? KeyFilePath = null);
public sealed record ArchiveProgress(string Message, long BytesProcessed, long? TotalBytes = null);
public sealed record RestoreLimits(long MaxTotalBytes = 1_099_511_627_776, int MaxEntries = 1_000_000);

public interface IArchiveService
{
    Task CreateAsync(IEnumerable<string> sources, string outputPath, ArchiveCredentials credentials,
        PasswordWorkFactor workFactor = PasswordWorkFactor.Standard,
        IProgress<ArchiveProgress>? progress = null, CancellationToken cancellationToken = default);
    Task RestoreAsync(string archivePath, string destinationPath, ArchiveCredentials credentials,
        IProgress<ArchiveProgress>? progress = null, CancellationToken cancellationToken = default,
        RestoreLimits? limits = null);
}
