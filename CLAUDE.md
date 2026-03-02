# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## About

DgNet.Keepass is a .NET 10 class library for reading and writing KeePass `.kdbx` password database files. The implementation is inspired by [KeePassXC](https://github.com/keepassxreboot/keepassxc) (C++), which serves as the reference implementation.

## Commands

```bash
dotnet build          # Build the library
dotnet format         # Format code
dotnet pack           # Create NuGet package
```

There are no tests yet. When a test project is added, run tests with `dotnet test`.

## Architecture

The public API surface is a single class, `Database` (`src/Database.cs`), which accepts a file path and optional password/key file. It exposes `Read()` and `Write()` instance methods and a static `Database.Read(path, password, keyFile?)` factory helper.

Internally, the `Kdbx/` layer handles the binary KDBX format:

- `KdbxReader` — deserializes a `.kdbx` file into the in-memory representation
- `KdbxWriter` — serializes the in-memory representation back to `.kdbx`
- `KdbxHeader` — parses and holds KDBX file header fields (cipher, KDF params, master seed, etc.)
- `KdbxContent` — represents the decrypted, structured database content (groups, entries)

The `Keys/` layer manages the key hierarchy:

- `CompositeKey` — combines password + key file into a SHA-512 composite key
- `DerivedKey` — output of the KDF (AES-KDF or Argon2)
- `EncryptionKey` — final key used for payload encryption: `SHA256(MasterSeed || DerivedKey)`

The `Crypto/` layer contains the cryptographic algorithms:

- `AesKdf` — iterative AES-256-ECB + final SHA-256 (legacy KDF)
- `Argon2Kdf` — Argon2d / Argon2id (recommended KDF for KDBX 4)
- `SymmetricCipher` — payload encryption (AES-256-CBC, ChaCha20, Twofish)
- `ProtectedStream` — inner stream for protected XML fields (Salsa20 / ChaCha20)

The `libs/` directory is excluded from the build via `<DefaultItemExcludes>libs/**</DefaultItemExcludes>` in the `.csproj`; use it for vendored or local dependencies without affecting the build.