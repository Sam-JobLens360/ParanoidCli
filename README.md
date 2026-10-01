# ParanoidCli

ParanoidCli is a C# command-line tool for experimenting with layered file protection and key derivation. It combines source mixing, Argon2id, optional sealed-length padding, optional FEC-style packaging, and double AES-GCM encryption into a single workflow.

> This project is experimental and security-focused. It is intended for learning, prototyping, and iterative hardening.

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

### Encrypt options

- `--in` — input file to encrypt
- `--out` — output encrypted blob
- `--salt-hex` — required salt in hex format
- `--src` — zero or more source values used in key derivation
- `--pad` — one of `none`, `block`, or `pow2`
- `--block` — block size used when `--pad block` is selected
- `--fec-k` — number of data shards; `0` disables FEC
- `--fec-p` — number of parity shards
- `--fec-shard` — shard size used by FEC
- `--fec-seed` — seed used for parity row generation

## Decrypt

```bash
dotnet run -- decrypt \
  --in output.enc \
  --out restored.bin \
  --salt-hex 00112233445566778899aabbccddeeff \
  --src hello \
  --src @seeds/source.txt
```

### Decrypt options

- `--in` — encrypted input blob
- `--out` — output file for the restored plaintext
- `--salt-hex` — same salt used at encryption time
- `--src` — same source values used at encryption time

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

- CLI help and validation improvements
- richer logging and error messages
- support for shard-based recovery workflows
- stronger documentation around the cryptographic format
- automated tests for encryption/decryption round trips

