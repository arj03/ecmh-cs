using Secp256k1Net;
using System.Security.Cryptography;
using System.Numerics;

namespace ECMH;

public sealed class MultiSet : IDisposable
{
    private static readonly byte[] EMPTY_HASH = new byte[32];
    private static readonly byte[] INFINITY = new byte[33];
    private const byte COMPRESSED_FIRST_BYTE_0 = 0x02;
    private const byte COMPRESSED_FIRST_BYTE_1 = 0x03;

    private readonly Secp256k1 secp256k1;
    private readonly byte[] point; // Store point in compressed format

    public MultiSet()
    {
        secp256k1 = new Secp256k1();
        point = new byte[33]; // Initialize as infinity point
    }

    public void AddItem(byte[] sha256Buffer)
    {
        if (sha256Buffer == null || sha256Buffer.SequenceEqual(EMPTY_HASH))
            return;

        AddPoint(GetPoint(sha256Buffer));
    }

    public void AddSet(MultiSet ms)
    {
        AddPoint(ms.point);
    }

    public void RemoveItem(byte[] sha256Buffer)
    {
        if (sha256Buffer == null || sha256Buffer.SequenceEqual(EMPTY_HASH))
            return;

        RemovePoint(GetPoint(sha256Buffer));
    }

    public void RemoveSet(MultiSet ms)
    {
        RemovePoint(ms.point);
    }

    public string GetHash()
    {
        return BitConverter.ToString(GetHashBytes()).Replace("-", "");
    }

    public void Dispose()
    {
        secp256k1.Dispose();
    }

    private void AddPoint(Span<byte> newPoint)
    {
        if (IsInfinity(point))
        {
            newPoint.CopyTo(point);
        }
        else if (!IsInfinity(newPoint))
        {
            Span<byte> result = stackalloc byte[64]; // Uncompressed point format
            Span<byte> pubKey1 = stackalloc byte[64];
            Span<byte> pubKey2 = stackalloc byte[64];

            // Parse both points
            if (!secp256k1.PublicKeyParse(pubKey1, point) ||
                !secp256k1.PublicKeyParse(pubKey2, newPoint))
                throw new InvalidOperationException("Failed to parse points");

            // Combine the points
            if (!secp256k1.PublicKeysCombine(result, pubKey1, pubKey2))
                throw new InvalidOperationException("Failed to add points");

            // Convert back to compressed format
            Span<byte> compressed = stackalloc byte[33];
            if (!secp256k1.PublicKeySerialize(compressed, result, Flags.SECP256K1_EC_COMPRESSED))
                throw new InvalidOperationException("Failed to compress point");

            compressed.CopyTo(point);
        }
    }

    private void RemovePoint(ReadOnlySpan<byte> pointToRemove)
    {
        if (pointToRemove.SequenceEqual(point))
        {
            Array.Clear(point, 0, point.Length);
        }
        else
        {
            // Negate the point to remove (flip y coordinate
            var negatedPoint = pointToRemove.ToArray();
            negatedPoint[0] ^= 1; // Flip compression byte to change y coordinate sign

            AddPoint(negatedPoint);
        }
    }

    private byte[] GetHashBytes()
    {
        if (IsInfinity(point))
            return EMPTY_HASH;

        Span<byte> uncompressed = stackalloc byte[64];
        if (!secp256k1.PublicKeyParse(uncompressed, point))
            throw new InvalidOperationException("Failed to parse point");

        // BE
        uncompressed.Slice(0, 32).Reverse();
        uncompressed.Slice(32, 32).Reverse();

        return SHA256.HashData(uncompressed);
    }

    private static bool IsInfinity(ReadOnlySpan<byte> pointBytes)
    {
        return pointBytes.SequenceEqual(INFINITY);
    }

    private static bool GetBit(ReadOnlySpan<byte> bytes, int index)
    {
        return (bytes[index >> 3] & (1 << (7 - (index & 7)))) != 0;
    }

    private byte[]? ConvertToPoint(ReadOnlySpan<byte> xBytes)
    {
        // Create compressed point format
        Span<byte> encodedCompressedPoint = stackalloc byte[33];
        bool yCoordinateIsEven = !GetBit(xBytes, 0);
        encodedCompressedPoint[0] = yCoordinateIsEven ? COMPRESSED_FIRST_BYTE_0 : COMPRESSED_FIRST_BYTE_1;
        xBytes.CopyTo(encodedCompressedPoint.Slice(1, 32));

        Span<byte> pubKey = stackalloc byte[64];
        if (!secp256k1.PublicKeyParse(pubKey, encodedCompressedPoint))
            return null;

        return encodedCompressedPoint.ToArray();
    }

    private Span<byte> GetPoint(byte[] sha256Buffer)
    {
        IncrementalHash sha256 = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);

        Span<byte> countBytes = stackalloc byte[8];
        for (BigInteger n = 0; true; n++)
        {
            n.ToByteArray().CopyTo(countBytes);

            sha256.AppendData(countBytes);
            sha256.AppendData(sha256Buffer);

            var point = ConvertToPoint(sha256.GetHashAndReset());

            if (point != null)
                return point;
        }
    }
}