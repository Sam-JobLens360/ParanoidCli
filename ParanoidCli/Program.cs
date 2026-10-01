using Konscious.Security.Cryptography;
using ParanoidCli;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.CommandLine;
using System.CommandLine.Invocation;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using System.Text;
using static System.Runtime.InteropServices.JavaScript.JSType;

class Program
{
    public static int Main(string[] args)
    {
        var root = new RootCommand("Paranoid CLI: forge keys, pad+FEC, encrypt/decrypt(Double AES - GCM)");

        if (args[0] == "encrypt")
        {
            var encrypt = new Command("encrypt", "Encrypt a file with sealed length and optional FEC before crypto");
            Option<string> inOpt = new("--in") { Required = true };
            Option<string> outOpt = new("--out") { Required = true };
            Option<string> saltOpt = new("--salt-hex") { Required = true };
            Option<string[]> srcOpt = new("--src") { Arity = ArgumentArity.ZeroOrMore };
            Option<string> padOpt = new("--pad") { Description = "none|block|pow2" };
            Option<int> blockOpt = new("--block") { Description = "Block size for padding (default 4096)", DefaultValueFactory = _ => 4096, };
            Option<int> kOpt = new("--fec-k") { Description = "data shards (0=disable FEC)", DefaultValueFactory = ParseResult => 0, };
            Option<int> pOpt = new("--fec-p") { Description = "parity shards", DefaultValueFactory = ParseResult => 0, };
            Option<int> sharedOpt = new("--fec-shard") { Description = "shard size for FEC", DefaultValueFactory = ParseResult => 4096, };
            Option<ulong> seedOpt = new("--fec-seed") { Description = "seed for parity pattern", DefaultValueFactory = ParseResult => 0xC0FFEEUL, };

            encrypt.Options.Add(inOpt);
            encrypt.Options.Add(outOpt);
            encrypt.Options.Add(saltOpt);
            encrypt.Options.Add(srcOpt);
            encrypt.Options.Add(padOpt);
            encrypt.Options.Add(blockOpt);
            encrypt.Options.Add(kOpt);
            encrypt.Options.Add(pOpt);
            encrypt.Options.Add(sharedOpt);
            encrypt.Options.Add(seedOpt);

            encrypt.SetAction(parseResult =>
            {
                string input = parseResult.GetValue(inOpt)!;
                string output = parseResult.GetValue(outOpt)!;
                string saltHex = parseResult.GetValue(saltOpt)!;
                string[] srcs = parseResult.GetValue(srcOpt)!;
                string pad = parseResult.GetValue(padOpt)!;
                int block = parseResult.GetValue(blockOpt);
                int k = parseResult.GetValue(kOpt);
                int p = parseResult.GetValue(pOpt);
                int shard = parseResult.GetValue(sharedOpt);
                ulong seed = parseResult.GetValue(seedOpt);

                byte[] plaintext = File.ReadAllBytes(input);
                byte[] sealedLen = PX2.PadSeal(plaintext, pad, block);
                if (k > 0)
                    sealedLen = FEC.Pack(sealedLen, shard, k, p, seed);
                var sources = LoadSources(srcs);
                var master = ForgeMaster(sources, HexToBytes(saltHex));
                var blob = PX2.DoubleAesGcmEncrypt(sealedLen, master);

                File.WriteAllBytes(output, blob);
                Array.Clear(master);
                Console.WriteLine($"[encrypt] wrote {output} ({blob.Length}bytes)");
            });
            root.Add(encrypt);
        }
        else if (args[0] == "decrypt")
        {
            var decrypt = new Command("decrypt", "Decrypt a blob and auto-unpack FEC + unpad");
            Option<string> dInOpt = new("--in") { Required = true };
            Option<string> dOutOpt = new("--out") { Required = true };
            Option<string> dSaltOpt = new("--salt-hex") { Required = true };
            Option<string[]> dSrcOpt = new("--src") { Arity = ArgumentArity.ZeroOrMore };

            decrypt.Options.Add(dInOpt);
            decrypt.Options.Add(dOutOpt);
            decrypt.Options.Add(dSaltOpt);
            decrypt.Options.Add(dSrcOpt);

            decrypt.SetAction(parseResult =>
            {
                string input = parseResult.GetValue(dInOpt)!;
                string output = parseResult.GetValue(dOutOpt)!;
                string saltHex = parseResult.GetValue(dSaltOpt)!;
                string[] srcs = parseResult.GetValue(dSrcOpt)!;

                var sources = LoadSources(srcs);
                var master = ForgeMaster(sources, HexToBytes(saltHex));
                var sealedLen = PX2.DoubleAesGcmDecrypt(File.ReadAllBytes(input), master);

                // Try FEC unpack (detect by magic)
                if (sealedLen.Length >= 5 && sealedLen[0] == (byte)'F' && sealedLen[1] == (byte)'E' && sealedLen[2] == (byte)'C' && sealedLen[3] == (byte)'1' && sealedLen[4] == 1)
                    sealedLen = FEC.Unpack(sealedLen);
                var pt = PX2.UnpadUnseal(sealedLen);
                File.WriteAllBytes(output, pt);
                Array.Clear(master);
                Console.WriteLine($"[decrypt] wrote {output} ({pt.Length} bytes)");
            });
            root.Add(decrypt);
        }
        
        return root.Parse(args).Invoke();
    }

    static byte[][] LoadSources(string[]? srcs)
    {
        var list = new List<byte[]>();
        if (srcs != null)
        {
            foreach (var s in srcs)
            {
                if (!string.IsNullOrEmpty(s) && s[0] == '@')
                    list.Add(File.ReadAllBytes(s.Substring(1)));
                else
                    list.Add(Encoding.UTF8.GetBytes(s ?? string.Empty));
            }
        }
        if (list.Count == 0) 
            Console.Error.WriteLine("[warn] no sources provided; relying on system RNG mixing");
        return list.ToArray();
    }

    static byte[] ForgeMaster(IEnumerable<byte[]> sources, byte[] salt)
    {
        var pool = PX2.MixSources(sources);
        var master = PX2.Argon2id(pool, salt, memMB: 512, iters: 4, parallelism:
        2, outLen: 32);
        Array.Clear(pool);
        return master;
    }

    static byte[] HexToBytes(string hex)
    {
        if (hex.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) 
            hex = hex.Substring(2);

        if (hex.Length % 2 == 1) 
            throw new ArgumentException("hex length must be even");

        var b = new byte[hex.Length / 2];

        for (int i = 0; i < b.Length; i++) 
            b[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        return b;
    }
}