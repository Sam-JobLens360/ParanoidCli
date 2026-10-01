using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace ParanoidCli;

public static class FEC
{
    // Encapsulated package format so true length is hidden once encrypted:
    // ["FEC1":4][ver:1=1][shardSize:u32][k:u16][p:u16][seed:u64][origLen:u64][data shards k][parity shards p]
    public static byte[] Pack(byte[] plaintext, int shardSize, int k, int p, ulong seed)
    {
        if (k <= 0 || p < 0) throw new ArgumentException("bad k/p");
        if (shardSize <= 0) throw new ArgumentException("bad shardSize");
        int capacity = k * shardSize;
        int pad = (capacity - (plaintext.Length % capacity)) % capacity;
        byte[] padded = new byte[plaintext.Length + pad];
        Buffer.BlockCopy(plaintext, 0, padded, 0, plaintext.Length);

        if (pad > 0)
            RandomNumberGenerator.Fill(padded.AsSpan(plaintext.Length));
        
        // split into k shards
        int blocks = padded.Length / capacity; // number of k-shard blocks
        
        using var ms = new MemoryStream();
        ms.Write(Encoding.ASCII.GetBytes("FEC1"));
        ms.WriteByte(1);
        Span<byte> u32 = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(u32, (uint)shardSize);
        ms.Write(u32);
        Span<byte> u16 = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(u16, (ushort)k); ms.Write(u16);
        BinaryPrimitives.WriteUInt16BigEndian(u16, (ushort)p); ms.Write(u16);
        Span<byte> u64 = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(u64, seed); ms.Write(u64);
        BinaryPrimitives.WriteUInt64BigEndian(u64, (ulong)plaintext.Length);
        ms.Write(u64);
        var rng = new Random((int)(seed ^ 0x9E3779B97F4A7C15UL));
        
        for (int b = 0; b < blocks; b++)
        {
            // data shards
            var data = new byte[k][];
            for (int i = 0; i < k; i++)
            {
                data[i] = new byte[shardSize];
                Buffer.BlockCopy(padded, b * capacity + i * shardSize, data[i],
                0, shardSize);
                ms.Write(data[i]);
            }

            // parity rows (random binary rows over k, ensure not all-zero)
            var rows = RandomFullRankRows(k, p, rng);
            for (int pi = 0; pi < p; pi++)
            {
                byte[] shard = new byte[shardSize];
                for (int di = 0; di < k; di++)
                {
                    if (rows[pi][di]) XorInPlace(shard, data[di]);
                }
                ms.Write(shard);
            }
        }
        return ms.ToArray();
    }

    public static byte[] Unpack(byte[] package)
    {
        var s = package.AsSpan();
        if (s.Length < 4 + 1 + 4 + 2 + 2 + 8 + 8) 
            throw new CryptographicException("fec too small");

        if (!s.Slice(0, 4).SequenceEqual(Encoding.ASCII.GetBytes("FEC1"))) 
            throw new CryptographicException("bad fec magic");

        if (s[4] != 1) throw new CryptographicException("bad fec ver");

        int shardSize = (int)BinaryPrimitives.ReadUInt32BigEndian(s.Slice(5, 4));
        int k = BinaryPrimitives.ReadUInt16BigEndian(s.Slice(9, 2));
        int p = BinaryPrimitives.ReadUInt16BigEndian(s.Slice(11, 2));
        ulong seed = BinaryPrimitives.ReadUInt64BigEndian(s.Slice(13, 8));
        ulong origLen = BinaryPrimitives.ReadUInt64BigEndian(s.Slice(21, 8));

        int hdr = 29;
        int blockBytes = (k + p) * shardSize;
        int dataBytes = k * shardSize;
        int blocks = (s.Length - hdr) / blockBytes;
        if (hdr + blocks * blockBytes != s.Length) throw new CryptographicException("fec size mismatch");
        // For a sealed package (file), we wrote all shards; recovery not needed.Just strip padding using origLen.
        byte[] outBuf = new byte[(int)origLen];
        int wrote = 0;
        
        for (int b = 0; b < blocks; b++)
        {
            // copy the k data shards directly
            var blockSpan = s.Slice(hdr + b * blockBytes, blockBytes);
            var dataSpan = blockSpan.Slice(0, dataBytes);
            int toCopy = Math.Min(outBuf.Length - wrote, dataBytes);
            dataSpan.Slice(0, toCopy).CopyTo(outBuf.AsSpan(wrote));
            wrote += toCopy;
        }
        return outBuf;
    }

    // Encode to shards for transport (returns dataShards + parityShards per block)
    public static (List<byte[]>, List<bool[]>) EncodeToShards(byte[] plaintext, int shardSize, int k, int p, ulong seed)
    {
        int capacity = k * shardSize;
        int pad = (capacity - (plaintext.Length % capacity)) % capacity;
        byte[] padded = new byte[plaintext.Length + pad];
        Buffer.BlockCopy(plaintext, 0, padded, 0, plaintext.Length);
        if (pad > 0)
            RandomNumberGenerator.Fill(padded.AsSpan(plaintext.Length));

        int blocks = padded.Length / capacity;
        var rng = new Random((int)(seed ^ 0x9E3779B97F4A7C15UL));
        var rows = RandomFullRankRows(k, p, rng);
        var shards = new List<byte[]>(blocks * (k + p));
        var rowset = new List<bool[]>(blocks * p);
        
        for (int b = 0; b < blocks; b++)
        {
            var data = new byte[k][];
            for (int i = 0; i < k; i++)
            {
                data[i] = new byte[shardSize];
                Buffer.BlockCopy(padded, b * capacity + i * shardSize, data[i], 0, shardSize);
                shards.Add(data[i]);
            }

            for (int pi = 0; pi < p; pi++)
            {
                byte[] shard = new byte[shardSize];
                for (int di = 0; di < k; di++) if (rows[pi][di])
                    XorInPlace(shard, data[di]);
                shards.Add(shard);
                rowset.Add(rows[pi]);
            }
        }
        return (shards, rowset); // rowset describes parity composition for each parity shard
    }

    // Attempt recovery when up to p shards per block are missing (GF(2) solve)
    // Provide available shards and which rows they correspond to (first k identity rows for data shards, then given parity rows)
    public static byte[][] RecoverShards(byte[][] available, int[] rowIndices,int k, int p, int shardSize, bool[][] parityRows)
    {
        // Build matrix A (m x k) of available rows; pick any k independent rows then solve A * x = y for x(data shards)
        int m = available.Length;
        var A = new bool[m, k];
        for (int i = 0; i < m; i++)
        {
            int idx = rowIndices[i];
            if (idx < k)
            {
                for (int c = 0; c < k; c++) A[i, c] = (c == idx);
            }
            else
            {
                var row = parityRows[idx - k];
                for (int c = 0; c < k; c++) A[i, c] = row[c];
            }
        }

        // Select k independent rows using Gaussian elimination over GF(2)
        var selected = SelectIndependentRows(A, m, k);
        if (selected.Count < k) throw new CryptographicException("not enough independent shards to recover");

        // Build kxk matrix and invert
        var M = new bool[k, k];
        for (int r = 0; r < k; r++) for (int c = 0; c < k; c++) M[r, c] =
        A[selected[r], c];
        var Minv = InvertBinaryMatrix(M, k);

        // y is k x shardSize bytes from selected shards; x = Minv * y
        var data = new byte[k][]; for (int i = 0; i < k; i++) data[i] = new
        byte[shardSize];
        
        for (int row = 0; row < k; row++)
        {
            for (int col = 0; col < k; col++) if (Minv[row, col])
                XorInPlace(data[row], available[selected[col]]);
        }
        return data;
    }

    // ---- helpers ----
    static void XorInPlace(byte[] dst, byte[] src)
    { 
        for (int i = 0; i < dst.Length; i++) dst[i] ^= src[i]; 
    }
    
    static List<bool[]> RandomFullRankRows(int k, int p, Random rng)
    {
        // Generate p random non-zero rows of length k; ensure resulting (k+p)xk generator has rank k
        var rows = new List<bool[]>();
        while (rows.Count < p)
        {
            var row = new bool[k];
            int ones = 0;
            for (int i = 0; i < k; i++)
            {
                row[i] = rng.Next(2) == 1; if
            (row[i]) ones++;
            }
            if (ones == 0) continue;
            rows.Add(row);
        }
        // Not strictly verifying full-rank of the combined matrix (I_k stacked with rows) because I_k already gives rank k.
        // Parity rows variety affects numerical stability for recovery but is fine for small p.
        return rows;
    }

    static List<int> SelectIndependentRows(bool[,] A, int m, int k)
    {
        var idxs = Enumerable.Range(0, m).ToList();
        var chosen = new List<int>();
        var M = new bool[0, 0]; // dummy
                                // Greedy: prefer identity rows first for simplicity
        for (int i = 0; i < m && chosen.Count < k; i++)
        {
            chosen.Add(i);
            if (RankIsK(A, chosen, k)) continue;

            chosen.RemoveAt(chosen.Count - 1);
        }
        return chosen;
    }

    static bool RankIsK(bool[,] A, List<int> rows, int k)
    {
        // Gaussian elimination over selected rows to estimate rank
        var M = new bool[rows.Count, k];
        for (int r = 0; r < rows.Count; r++) for (int c = 0; c < k; c++) M[r, c] = A[rows[r], c];
        int rank = 0;
        int lead = 0;
        for (int r = 0; r < rows.Count && lead < k; r++)
        {
            int i = r;
            while (i < rows.Count && !M[i, lead]) 
                i++;
            if (i == rows.Count) 
            { 
                lead++; r--; continue; 
            }
            // swap
            if (i != r)
            {
                for (int c = 0; c < k; c++)
                {
                    var tmp = M[r, c]; M[r, c] = M[i, c]; M[i, c] = tmp;
                }
            }
            // eliminate
            for (int j = 0; j < rows.Count; j++) if (j != r && M[j, lead]) for (int c = 0; c < k; c++) M[j, c] ^= M[r, c];                        
            lead++; rank++;
        }
        return rank == Math.Min(k, rows.Count);
    }

    static bool[,] InvertBinaryMatrix(bool[,] M, int n)
    {
        var A = new bool[n, n];
        var I = new bool[n, n];
        for (int r = 0; r < n; r++)
        {
            for (int c = 0; c < n; c++)
            {
                A[r, c] = M[r, c]; I[r, c] = (r == c);
            }
        }
        int lead = 0;
        for (int r = 0; r < n; r++)
        {
            int i = r;
            while (i < n && !A[i, lead]) i++;
            if (i == n) 
            { 
                lead++; 
                if (lead == n) 
                    break; 
                r--; 
                continue; 
            }
            if (i != r) for (int c = 0; c < n; c++)
            {
                var t = A[r, c]; 
                A[r, c] = A[i, c]; 
                A[i, c] = t; 
                var u = I[r, c]; 
                I[r, c] = I[i, c]; 
                I[i, c] = u;
            }
            for (int j = 0; j < n; j++) if (j != r && A[j, lead]) for (int c = 0; c < n; c++) 
            { 
                A[j, c] ^= A[r, c]; 
                I[j, c] ^= I[r, c]; 
            }
            lead++;
        }
        // A should be identity now; I is inverse
        return I;
    }
}