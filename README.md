# ParanoidCli

[![.NET](https://img.shields.io/badge/.NET-10.0-512BD4?logo=dotnet&logoColor=white)](https://dotnet.microsoft.com/)
[![Language](https://img.shields.io/badge/Language-C%23-178600?logo=csharp&logoColor=white)](https://learn.microsoft.com/dotnet/csharp/)
[![Status](https://img.shields.io/badge/Status-Experimental-orange)](https://github.com/Sam-JobLens360/ParanoidCli)
[![Visibility](https://img.shields.io/badge/Repo-Public-success)](https://github.com/Sam-JobLens360/ParanoidCli)

ParanoidCli is an experimental C# command-line project focused on layered file protection, key derivation, and metadata reduction. It combines source mixing, Argon2id, optional sealed-length padding, optional FEC-style packaging, and double AES-GCM encryption into a single workflow.

> This repository is intentionally public and research-oriented. It exists as a portfolio-ready security experiment for exploring cryptographic design, file-format hardening, and CLI implementation patterns.

## Research focus

This project is designed as a practical exploration of:

- key derivation from multiple source inputs
- layered encryption workflows
- file size obfuscation techniques
- error-correction-inspired packaging
- secure command-line application design
- iterative hardening and vulnerability review

## What it does

ParanoidCli can:

- derive a master key from one or more user-supplied sources
- mix source material with SHA-512 before key derivation
- run Argon2id using a required salt
- hide the plaintext length with an internal sealed header
- optionally pad output to a block size or the next power of two
- optionally wrap the payload in an FEC container
- encrypt the result with two layers of AES-GCM
- decrypt the blob and restore the original file

## How it works

### 1. Source mixing

You can pass one or more `--src` values to influence key generation.

Supported source forms:

- plain text values, such as `--src hello`
- file-backed values, such as `--src @path/to/file.txt`

The sources are hashed and XOR-mixed together to create the input pool for Argon2id.

If no sources are provided, the tool falls back to system randomness and prints a warning.

### 2. Key derivation

The mixed source pool is fed into Argon2id along with a user-provided salt.

The project currently uses:

- 512 MB memory
- 4 iterations
- 2-way parallelism
- a 32-byte output key

The salt must be provided as hex and must be at least 16 bytes long.

### 3. Sealed-length padding

Before encryption, the plaintext is wrapped in a small internal header:

- magic: `PXP\0`
- version byte
- original plaintext length
- 16 bytes of random padding metadata
- plaintext bytes

This makes it harder to infer the original file size.

Optional padding modes:

- `none` — keep the sealed payload as-is
- `block` — pad to the next block boundary
- `pow2` — pad to the next power of two

### 4. Optional FEC packaging

If enabled, the sealed payload is packaged into data and parity shards before encryption.

The current implementation stores:

- FEC magic: `FEC1`
- version
- shard size
- data shard count (`k`)
- parity shard count (`p`)
- parity seed
- original plaintext length
- data shards and parity shards

### 5. Double AES-GCM

The final payload is encrypted twice:

1. inner AES-GCM layer
2. outer AES-GCM layer

Separate keys are derived from the master key using HKDF-style expansion with different labels.

## CLI reference

### `encrypt`

Encrypt a file with sealed length and optional FEC before crypto.

| Option | Required | Description | Default |
| --- | --- | --- | --- |
| `--in` | Yes | Input file to encrypt | — |
| `--out` | Yes | Output encrypted blob | — |
| `--salt-hex` | Yes | Salt in hex format | — |
| `--src` | No | Zero or more key source values | none |
| `--pad` | No | Padding mode: `none`, `block`, or `pow2` | `none` |
| `--block` | No | Block size used when `--pad block` is selected | `4096` |
| `--fec-k` | No | Number of data shards; `0` disables FEC | `0` |
| `--fec-p` | No | Number of parity shards | `0` |
| `--fec-shard` | No | Shard size used by FEC | `4096` |
| `--fec-seed` | No | Seed used for parity row generation | `0xC0FFEE` |

### `decrypt`

Decrypt a blob and restore the original file.

| Option | Required | Description | Default |
| --- | --- | --- | --- |
| `--in` | Yes | Encrypted input blob | — |
| `--out` | Yes | Output file for the restored plaintext | — |
| `--salt-hex` | Yes | Same salt used at encryption time | — |
| `--src` | No | Same source values used at encryption time | none |

## Repository layout

- `Program.cs` — CLI entry point and command wiring
- `PX2.cs` — key mixing, Argon2id derivation, padding, and AES-GCM helpers
- `FEC.cs` — FEC packaging and shard helpers
- `ParanoidCli.csproj` — project file and dependencies
- `Properties/launchSettings.json` — local run configuration

## Requirements

- .NET 10 SDK

## Build

```bash
dotnet restore
dotnet build
```

## Run

You can run the app directly from the repository:

```bash
dotnet run -- encrypt --help
dotnet run -- decrypt --help
```

## Encrypt

```bash
dotnet run -- encrypt \
  --in input.bin \
  --out output.enc \
  --salt-hex 00112233445566778899aabbccddeeff \
  --src hello \
  --src @seeds/source.txt \
  --pad block \
  --block 4096 \
  --fec-k 4 \
  --fec-p 2 \
  --fec-shard 4096 \
  --fec-seed 12648430
```

## Decrypt

```bash
dotnet run -- decrypt \
  --in output.enc \
  --out restored.bin \
  --salt-hex 00112233445566778899aabbccddeeff \
  --src hello \
  --src @seeds/source.txt
```

## Example workflow

```bash
# encrypt
dotnet run -- encrypt \
  --in notes.txt \
  --out notes.enc \
  --salt-hex 00112233445566778899aabbccddeeff \
  --src "device-123" \
  --src @secrets/source.txt \
  --pad pow2

# decrypt
dotnet run -- decrypt \
  --in notes.enc \
  --out notes.txt \
  --salt-hex 00112233445566778899aabbccddeeff \
  --src "device-123" \
  --src @secrets/source.txt
```

## FAQ

### Why is this repository public?

It is intentionally public so it can serve as a visible portfolio project for job searches and demonstrate security-oriented C# work.

### Is this meant for production use?

Not yet. The project is experimental and research-focused, so it should be reviewed, tested, and hardened further before production use.

### Why use two AES-GCM layers?

The implementation is exploring layered encryption patterns and how additional structure affects format design, metadata exposure, and key separation.

### Why include FEC if the blob is already encrypted?

In this project, FEC acts as an additional packaging layer and design experiment rather than a standalone backup or recovery system.

### What should I keep consistent between encrypt and decrypt?

Use the same:

- `--salt-hex`
- `--src` values
- optional padding settings if you are reproducing a workflow

### What happens if I do not provide any `--src` values?

The tool will rely on system randomness and print a warning. For repeatable decryption, you should provide the same sources every time.

## Security notes

- Keep the salt and source values consistent between encryption and decryption.
- Use unpredictable source material whenever possible.
- Keep in mind that this project is experimental and should be reviewed carefully before relying on it for production secret protection.
- FEC packaging is an additional structural layer, not a backup strategy.

## Dependencies

- `Konscious.Security.Cryptography.Argon2`
- `System.CommandLine`

## Future improvements

Potential next steps for this project could include:

- richer input validation and help text
- more detailed logging and error messages
- support for shard-based recovery workflows
- stronger documentation around the cryptographic format
- automated tests for encryption/decryption round trips
- benchmarks for key derivation and blob sizes

