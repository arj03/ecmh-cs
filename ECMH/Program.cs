using Secp256k1Net;
using System.Security.Cryptography;
using System.Numerics;

namespace ECMH;

public class MultiSet : IDisposable
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

    private static bool GetBit(byte[] bytes, int index)
    {
        byte b = bytes[index >> 3];
        byte bitMask = (byte)(0x01 << (7 - (0x07 & index)));
        return (b & bitMask) != 0x00;
    }

    private byte[]? ConvertToPoint(byte[] xBytes)
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

    private byte[] GetPoint(byte[] sha256Buffer)
    {
        IncrementalHash sha256 = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        
        for (BigInteger n = 0; true; n++)
        {
            var countBytes = new byte[8];
            var nBytes = n.ToByteArray();
            Array.Copy(nBytes, countBytes, nBytes.Length);

            sha256.AppendData(countBytes);
            sha256.AppendData(sha256Buffer);

            var point = ConvertToPoint(sha256.GetHashAndReset());

            if (point != null)
                return point;
        }
    }

    public void AddPoint(byte[] newPoint)
    {
        if (IsInfinity(point))
        {
            Array.Copy(newPoint, point, newPoint.Length);
        }
        else if (!IsInfinity(newPoint))
        {
            byte[] result = new byte[64]; // Uncompressed point format
            byte[] pubKey1 = new byte[64];
            byte[] pubKey2 = new byte[64];

            // Parse both points
            if (!secp256k1.PublicKeyParse(pubKey1, point) ||
                !secp256k1.PublicKeyParse(pubKey2, newPoint))
                throw new InvalidOperationException("Failed to parse points");

            // Combine the points
            if (!secp256k1.PublicKeysCombine(result, pubKey1, pubKey2))
                throw new InvalidOperationException("Failed to add points");

            // Convert back to compressed format
            byte[] compressed = new byte[33];
            if (!secp256k1.PublicKeySerialize(compressed, result, Flags.SECP256K1_EC_COMPRESSED))
                throw new InvalidOperationException("Failed to compress point");

            Array.Copy(compressed, point, compressed.Length);
        }
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

    public void RemovePoint(byte[] pointToRemove)
    {
        if (pointToRemove.SequenceEqual(point))
        {
            Array.Clear(point, 0, point.Length);
        }
        else
        {
            // Negate the point to remove (flip y coordinate)
            byte[] negatedPoint = new byte[pointToRemove.Length];
            Array.Copy(pointToRemove, negatedPoint, pointToRemove.Length);
            negatedPoint[0] ^= 1; // Flip compression byte to change y coordinate sign

            AddPoint(negatedPoint);
        }
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

    public byte[] GetHash()
    {
        if (IsInfinity(point))
            return EMPTY_HASH;

        byte[] uncompressed = new byte[64];
        if (!secp256k1.PublicKeyParse(uncompressed, point))
            throw new InvalidOperationException("Failed to parse point");

        // BE
        Array.Reverse(uncompressed, 0, 32);
        Array.Reverse(uncompressed, 32, 32);
        
        return SHA256.HashData(uncompressed);
    }

    public string GetHashHex()
    {
        return BitConverter.ToString(GetHash()).Replace("-", "");
    }

    private static bool IsInfinity(byte[] pointBytes)
    {
        return pointBytes.SequenceEqual(INFINITY);
    }

    public void Dispose()
    {
        secp256k1?.Dispose();
    }
}