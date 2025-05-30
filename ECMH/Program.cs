﻿using Secp256k1Net;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace ECMH;

public sealed class MultiSet : IDisposable
{
    private static readonly byte[] EMPTY_HASH = new byte[32];
    private const byte COMPRESSED_FIRST_BYTE_0 = 0x02;
    private const byte COMPRESSED_FIRST_BYTE_1 = 0x03;

    private readonly Secp256k1 _secp256k1;
    private readonly byte[] _compressedPoint = new byte[33];
    private readonly byte[] _uncompressedPoint = new byte[64];
    private bool _isInfinity = true;

    public MultiSet()
    {
        _secp256k1 = new Secp256k1();
    }

    public void AddItem(ReadOnlySpan<byte> sha256Buffer)
    {
        if (sha256Buffer.IsEmpty|| sha256Buffer.SequenceEqual(EMPTY_HASH))
            return;

        AddPoint(GetPoint(sha256Buffer));
    }

    public void AddSet(MultiSet ms)
    {
        if (!ms._isInfinity)
            AddPoint(ms._compressedPoint);
    }

    public void RemoveItem(ReadOnlySpan<byte> sha256Buffer)
    {
        if (sha256Buffer.IsEmpty || sha256Buffer.SequenceEqual(EMPTY_HASH))
            return;

        RemovePoint(GetPoint(sha256Buffer));
    }

    public void RemoveSet(MultiSet ms)
    {
        if (!ms._isInfinity)
            RemovePoint(ms._compressedPoint);
    }

    public string GetHash()
    {
        return Convert.ToHexString(GetHashBytes());
    }

    public void Dispose()
    {
        _secp256k1.Dispose();
    }

    private void AddPoint(Span<byte> newPoint)
    {
        if (_isInfinity)
        {
            UpdatePoint(newPoint);
            _isInfinity = false;
        }
        else
        {
            Span<byte> pubKey2 = stackalloc byte[64];
            if (!_secp256k1.PublicKeyParse(pubKey2, newPoint))
                return;

            Span<byte> result = stackalloc byte[64];
            if (!_secp256k1.PublicKeysCombine(result, _uncompressedPoint, pubKey2))
                throw new InvalidOperationException("Failed to combine points");

            Span<byte> newCompressed = stackalloc byte[33];
            if (!_secp256k1.PublicKeySerialize(newCompressed, result, Flags.SECP256K1_EC_COMPRESSED))
                throw new InvalidOperationException("Failed to serialize combined point");

            UpdatePoint(newCompressed);
        }
    }

    private void RemovePoint(ReadOnlySpan<byte> pointToRemove)
    {
        if (pointToRemove.SequenceEqual(_compressedPoint))
        {
            ResetToInfinity();
        }
        else
        {
            // Negate the point to remove (flip y coordinate)
            Span<byte> negated = stackalloc byte[33];
            pointToRemove.CopyTo(negated);
            negated[0] ^= 1;
            AddPoint(negated);
        }
    }

    private byte[] GetHashBytes()
    {
        if (_isInfinity)
            return EMPTY_HASH;

        Span<byte> uncompressed = stackalloc byte[64];
        _uncompressedPoint.AsSpan().CopyTo(uncompressed);

        // BE
        uncompressed[..32].Reverse();
        uncompressed.Slice(32, 32).Reverse();

        return SHA256.HashData(uncompressed);
    }

    private Span<byte> GetPoint(ReadOnlySpan<byte> sha256Buffer)
    {
        Span<byte> input = stackalloc byte[40];
        sha256Buffer.CopyTo(input[8..]);

        Span<byte> hash = stackalloc byte[32];
        Span<byte> candidate = stackalloc byte[33];

        for (uint n = 0; ; n++)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(input, n);
            SHA256.HashData(input, hash);

            if (TryCreateValidPoint(hash, candidate))
                return candidate.ToArray();
        }
    }

    private bool TryCreateValidPoint(ReadOnlySpan<byte> xCoord, Span<byte> output)
    {
        output[0] = (xCoord[0] & 0x80) == 0 ? COMPRESSED_FIRST_BYTE_0 : COMPRESSED_FIRST_BYTE_1;
        xCoord.CopyTo(output[1..]);

        Span<byte> pubKey = stackalloc byte[64];
        return _secp256k1.PublicKeyParse(pubKey, output);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private void UpdatePoint(ReadOnlySpan<byte> newCompressed)
    {
        newCompressed.CopyTo(_compressedPoint);
        if (!_secp256k1.PublicKeyParse(_uncompressedPoint, _compressedPoint))
            throw new InvalidOperationException("Failed to update point");
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private void ResetToInfinity()
    {
        Array.Clear(_compressedPoint);
        Array.Clear(_uncompressedPoint);
        _isInfinity = true;
    }
}