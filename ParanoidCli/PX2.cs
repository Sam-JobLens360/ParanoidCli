using Konscious.Security.Cryptography;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace ParanoidCli;

public static class PX2 // shared utils + crypto layers
{
    // ====== Key forge ======
    public static byte[] MixSources(IEnumerable<byte[]> sources, int poolBytes = 64)
    {
        using var sha = SHA512.Create();
        var acc = new byte[poolBytes];
        bool any = false;
        foreach (var s in sources)
        {
            any = true;
            var h = sha.ComputeHash(s ?? Array.Empty<byte>());
            for (int i = 0; i < poolBytes; i++) acc[i] ^= h[i];
        }
        if (!any)
        {
            var sys = new byte[poolBytes]; RandomNumberGenerator.Fill(sys);
            for (int i = 0; i < poolBytes; i++) acc[i] ^= sys[i];
        }
        return acc;
    }

    public static byte[] Argon2id(byte[] pool, byte[] salt, int memMB = 512, int iters = 4, int parallelism = 2, int outLen = 32)
    {
        if (salt == null || salt.Length < 16) throw new ArgumentException("Salt must be at least 16 bytes");
        var a = new Argon2id(pool)
        {
            DegreeOfParallelism = Math.Max(1, parallelism),
            Iterations = Math.Max(1, iters),
            MemorySize = Math.Max(8, memMB) * 1024
        };
        a.Salt = salt;
        return a.GetBytes(outLen);
    }

    public static byte[] HkdfExpand(byte[] master, string label, int outLen)
    {
        var okm = new List<byte>(outLen);
        byte[] t = Array.Empty<byte>();
        int ctr = 1;
        while (okm.Count < outLen)
        {
            using var h = new HMACSHA256(master);
            h.TransformBlock(t, 0, t.Length, null, 0);
            var info = Encoding.UTF8.GetBytes(label);
            h.TransformBlock(info, 0, info.Length, null, 0);
            var c = new[] { (byte)ctr };
            h.TransformFinalBlock(c, 0, 1);
            t = h.Hash!;
            okm.AddRange(t);
            ctr++;
        }
        return okm.Take(outLen).ToArray();
    }

    // ====== Padding wrapper (seal length) ======
    public static byte[] PadSeal(byte[] plaintext, string mode, int blockSize)
    {
        // Inner header: ["PXP\0":4][ver:1=1][origLen:8][padRand:16]
        using var ms = new MemoryStream();
        ms.Write(Encoding.ASCII.GetBytes("PXP\0"));
        ms.WriteByte(1);
        Span<byte> u64 = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(u64, (ulong)plaintext.Length);
        ms.Write(u64);
        byte[] padRand = new byte[16]; RandomNumberGenerator.Fill(padRand);
        ms.Write(padRand);
        ms.Write(plaintext, 0, plaintext.Length);
        var core = ms.ToArray();
        int targetLen = core.Length;

        switch ((mode ?? "none").ToLowerInvariant())
        {
            case "none":
                return core;
            case "block":
                if (blockSize <= 0) throw new ArgumentException("blockSize must be > 0 for pad = block");
                targetLen = ((core.Length + blockSize - 1) / blockSize) *
                blockSize; break;
            case "pow2":
                int pow2 = 1; while (pow2 < core.Length) pow2 <<= 1; targetLen
                = pow2; break;
            default: throw new ArgumentException("pad must be none|block|pow2");
        }

        if (targetLen == core.Length) return core;

        byte[] outBuf = new byte[targetLen];
        Buffer.BlockCopy(core, 0, outBuf, 0, core.Length);
        // pad tail with random bytes
        RandomNumberGenerator.Fill(outBuf.AsSpan(core.Length));
        return outBuf;
    }

    public static byte[] UnpadUnseal(byte[] sealedBuf)
    {
        var s = sealedBuf.AsSpan();
        if (s.Length < 4 + 1 + 8 + 16) throw new
        CryptographicException("sealed length too small");
        if (!s.Slice(0, 4).SequenceEqual(Encoding.ASCII.GetBytes("PXP\0")))
            throw new CryptographicException("bad sealed header");

        if (s[4] != 1) throw new CryptographicException("bad sealed version");

        ulong orig = BinaryPrimitives.ReadUInt64BigEndian(s.Slice(5, 8));
        int hdr = 4 + 1 + 8 + 16;
        if ((long)orig > s.Length - hdr) throw new
        CryptographicException("declared length invalid");
        return s.Slice(hdr, (int)orig).ToArray();
    }

    // ====== Double AES-GCM layer ======
    public static byte[] DoubleAesGcmEncrypt(byte[] plaintext, byte[] master)
    {
        var k1 = HkdfExpand(master, "AES-GCM-outer", 32);
        var k2 = HkdfExpand(master, "AES-GCM-inner", 32);
        byte[] n2 = new byte[12]; RandomNumberGenerator.Fill(n2);
        byte[] t2 = new byte[16];
        byte[] inner = new byte[plaintext.Length];

        using (var a2 = new AesGcm(k2)) a2.Encrypt(n2, plaintext, inner, t2);
        byte[] n1 = new byte[12]; RandomNumberGenerator.Fill(n1);
        byte[] t1 = new byte[16];
        byte[] outer = new byte[inner.Length];

        using (var a1 = new AesGcm(k1)) a1.Encrypt(n1, inner, outer, t1);
        using var ms = new MemoryStream();
        ms.Write(Encoding.ASCII.GetBytes("PX2\0"));
        ms.WriteByte(1); // version
        ms.WriteByte(1); // algo 1 = DoubleAESGCM
        ms.Write(n1);
        ms.Write(t1);
        ms.Write(n2);
        ms.Write(t2);
        Span<byte> len = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(len, (uint)outer.Length);
        ms.Write(len);
        ms.Write(outer);
        return ms.ToArray();
    }

    public static byte[] DoubleAesGcmDecrypt(byte[] blob, byte[] master)
    {
        var s = blob.AsSpan();
        if (s.Length < 66) throw new CryptographicException("blob too small");

        if (!s.Slice(0, 4).SequenceEqual(Encoding.ASCII.GetBytes("PX2\0")))
            throw new CryptographicException("bad magic");

        if (s[4] != 1 || s[5] != 1) throw new CryptographicException("bad header");
        var n1 = s.Slice(6, 12);
        var t1 = s.Slice(18, 16);
        var n2 = s.Slice(34, 12);
        var t2 = s.Slice(46, 16);
        uint ctLen = BinaryPrimitives.ReadUInt32BigEndian(s.Slice(62, 4));
        var ct = s.Slice(66, (int)ctLen);
        var k1 = HkdfExpand(master, "AES-GCM-outer", 32);
        var k2 = HkdfExpand(master, "AES-GCM-inner", 32);
        byte[] inner = new byte[ct.Length];

        using (var a1 = new AesGcm(k1)) a1.Decrypt(n1, ct, t1, inner);
        byte[] pt = new byte[inner.Length];

        using (var a2 = new AesGcm(k2)) a2.Decrypt(n2, inner, t2, pt);
        return pt;
    }
}