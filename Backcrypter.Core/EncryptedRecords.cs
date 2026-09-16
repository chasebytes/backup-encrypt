using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Backcrypter.Core;

// Each record authenticates its position, length, and the complete versioned header.
internal sealed class EncryptedRecords : IDisposable
{
    internal const int ChunkSize = 1024 * 1024;
    private const int HeaderSize = 45;
    private readonly Stream stream;
    private readonly byte[] header;
    private readonly AesGcm aes;
    private ulong sequence;

    internal EncryptedRecords(Stream stream, ArchiveCredentials credentials, PasswordWorkFactor? writing)
    {
        this.stream = stream;
        if (string.IsNullOrWhiteSpace(credentials.Password)) throw new ArgumentException("A password is required.");
        if (writing.HasValue && credentials.Password.Length < 12)
            throw new ArgumentException("Use a password or passphrase of at least 12 characters.");
        header = new byte[HeaderSize];
        if (writing.HasValue)
        {
            if (!Enum.IsDefined(writing.Value)) throw new ArgumentOutOfRangeException(nameof(writing));
            "BCHIVE01"u8.CopyTo(header);
            RandomNumberGenerator.Fill(header.AsSpan(8, 32));
            BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(40), (int)writing.Value);
            header[44] = credentials.KeyFilePath is null ? (byte)0 : (byte)1;
        }
        else stream.ReadExactly(header);
        if (!header.AsSpan(0, 8).SequenceEqual("BCHIVE01"u8) || header[44] > 1)
            throw new InvalidDataException("Unsupported or damaged Backcrypter archive.");
        var iterations = BinaryPrimitives.ReadInt32LittleEndian(header.AsSpan(40));
        if (!Enum.IsDefined((PasswordWorkFactor)iterations)) throw new InvalidDataException("Unsupported password work factor.");
        if ((header[44] == 1) != (credentials.KeyFilePath is not null))
            throw new ArgumentException(header[44] == 1 ? "This archive requires its key file." : "This archive uses only a password; clear the key file.");
        byte[] password = Encoding.UTF8.GetBytes(credentials.Password);
        byte[] key = [];
        try
        {
            key = Rfc2898DeriveBytes.Pbkdf2(password, header.AsSpan(8, 32), iterations, HashAlgorithmName.SHA256, 32);
            if (credentials.KeyFilePath is not null)
            {
                using var file = File.OpenRead(credentials.KeyFilePath);
                if (file.Length != 32) throw new ArgumentException("Key files must contain exactly 32 bytes. Generate one with Backcrypter.");
                byte[] keyFile = new byte[32];
                try
                {
                    file.ReadExactly(keyFile);
                    var combined = HMACSHA256.HashData(keyFile, key);
                    CryptographicOperations.ZeroMemory(key);
                    key = combined;
                }
                finally { CryptographicOperations.ZeroMemory(keyFile); }
            }
            aes = new AesGcm(key, 16);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(password);
            CryptographicOperations.ZeroMemory(key);
        }
        if (writing.HasValue) stream.Write(header);
    }

    private (byte[] Nonce, byte[] Aad) Context(int length)
    {
        if (sequence >= uint.MaxValue) throw new InvalidDataException("Archive record limit exceeded.");
        byte[] nonce = new byte[12];
        BinaryPrimitives.WriteUInt64LittleEndian(nonce.AsSpan(4), sequence++);
        byte[] aad = new byte[HeaderSize + 12];
        header.CopyTo(aad, 0);
        nonce.AsSpan(4).CopyTo(aad.AsSpan(HeaderSize));
        BinaryPrimitives.WriteInt32LittleEndian(aad.AsSpan(HeaderSize + 8), length);
        return (nonce, aad);
    }

    internal void Write(ReadOnlySpan<byte> plain)
    {
        if (plain.Length is < 1 or > ChunkSize) throw new InvalidDataException("Invalid record size.");
        var (nonce, aad) = Context(plain.Length);
        byte[] ciphertext = new byte[plain.Length];
        byte[] tag = new byte[16];
        aes.Encrypt(nonce, plain, ciphertext, tag, aad);
        stream.Write(aad.AsSpan(HeaderSize + 8, 4));
        stream.Write(ciphertext);
        stream.Write(tag);
    }

    internal byte[] Read()
    {
        Span<byte> size = stackalloc byte[4];
        stream.ReadExactly(size);
        int length = BinaryPrimitives.ReadInt32LittleEndian(size);
        if (length is < 1 or > ChunkSize) throw new InvalidDataException("Invalid encrypted record size.");
        byte[] ciphertext = new byte[length];
        byte[] tag = new byte[16];
        stream.ReadExactly(ciphertext);
        stream.ReadExactly(tag);
        var (nonce, aad) = Context(length);
        byte[] plain = new byte[length];
        try { aes.Decrypt(nonce, ciphertext, tag, plain, aad); }
        catch { CryptographicOperations.ZeroMemory(plain); throw; }
        return plain;
    }

    public void Dispose() => aes.Dispose();
}
