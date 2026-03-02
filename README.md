# DgNet.Keepass

A .NET library for reading and writing KeePass (`.kdbx`) password database files.
Inspired by [KeePassXC](https://github.com/keepassxreboot/keepassxc), which serves as the reference implementation.

## Installation

```bash
dotnet add package DgNet.Keepass
```

## Quick start

```csharp
// Open an existing database
var db = Database.Open("vault.kdbx", "password");

// Create a new database
var db = Database.Create("password");
db.Metadata.Name = "My vault";

// Read entries
foreach (var entry in db.RootGroup.Entries)
    Console.WriteLine($"{entry.Title} — {entry.UserName}");

// Search
var entry = db.FindEntry("GitHub");
var all   = db.FindAllEntries(e => e.UserName == "alice").ToList();
var work  = db.FindGroup("Work");

// Add an entry (via direct setters)
var entry = new Entry();   // Uuid auto-generated
entry.Title    = "GitHub";
entry.UserName = "alice";
entry.Password = "s3cr3t!";   // Protected = true by default
db.RootGroup.AddEntry(entry);

// Add a binary attachment
entry.Binaries.Add(new EntryBinary { Name = "id_rsa.pub", Data = File.ReadAllBytes("id_rsa.pub") });

// Save
db.SaveAs("vault.kdbx");

// Generate a key file
KeyFile.Generate("vault.keyx");                        // KeePass XML v1 (default)
KeyFile.Generate("vault.key", KeyFileFormat.Raw);      // 32 raw random bytes

// Open a database protected by password + key file
var db = Database.Open("vault.kdbx", "password", "vault.keyx");
```

## Public API

### `Database`

Main entry point of the library. Implements `IDisposable` — calling `Dispose()` zeroes the cryptographic keys in memory (`CompositeKey.Zeroize()`) and releases all data.

```csharp
// Constructors
new Database()
new Database(CompositeKey key)
new Database(string path)
new Database(string path, CompositeKey key)
new Database(string path, string password)
new Database(string path, string password, string keyFile)

// Factories
Database.Create(string password, Settings? settings = null)
Database.Create(string password, string keyFile, Settings? settings = null)
Database.Open(string path, string password, string? keyFile = null)

// Properties
Metadata   Metadata   { get; }   // throws InvalidOperationException if not open
Group      RootGroup  { get; }   // throws InvalidOperationException if not open
Version    Version    { get; }   // 0.0 before open, e.g. 4.1 / 3.1 after
Settings   Settings   { get; set; }
FileInfo?  FileInfo   { get; }
bool       HasChanges { get; }

// Synchronous methods
void Open()
void Save()
void SaveAs(string path)

// Asynchronous methods
Task OpenAsync(CancellationToken ct = default)
Task SaveAsync(CancellationToken ct = default)
Task SaveAsAsync(string path, CancellationToken ct = default)

bool   IsRecycleBinEnabled()
Group? GetRecycleBin()

// Search (delegates to RootGroup)
Entry?             FindEntry(string title)
Entry?             FindEntry(Func<Entry, bool> predicate)
IEnumerable<Entry> FindAllEntries(Func<Entry, bool> predicate)
Group?             FindGroup(string name)
Group?             FindGroup(Func<Group, bool> predicate)
IEnumerable<Group> FindAllGroups(Func<Group, bool> predicate)
```

### `Entry`

```csharp
// Properties
Database? Database    { get; }
Group?    ParentGroup { get; }
Guid      Uuid        { get; set; }
int       IconId      { get; set; }
string    Tags        { get; set; }
Times     Times       { get; set; }
AutoType  AutoType    { get; set; }
Dictionary<string, EntryString> Strings  { get; set; }
List<EntryBinary>               Binaries { get; set; }
List<Entry>                     History  { get; set; }

// Shortcuts for the 5 standard fields (read + write)
// Setters preserve the existing Protected flag; Password is Protected by default.
string Title    { get; set; }
string UserName { get; set; }
string Password { get; set; }
string Url      { get; set; }
string Notes    { get; set; }

// Operations
void  Delete()            // moves to recycle bin if enabled, otherwise removes
void  MoveTo(Group group)
void  Update(Action<Entry> update)  // snapshot → apply → append to History
Entry Clone()             // deep copy with new UUID and empty History
```

### `Group`

```csharp
// Properties
Database? Database        { get; }
Group?    ParentGroup     { get; }
Guid      Uuid            { get; set; }
string    Name            { get; set; }
string    Notes           { get; set; }
int       IconId          { get; set; }
bool      IsExpanded      { get; set; }
bool?     EnableAutoType  { get; set; }
bool?     EnableSearching { get; set; }
Times     Times           { get; set; }
ReadOnlyCollection<Entry> Entries { get; }
ReadOnlyCollection<Group> Groups  { get; }

// Operations
void  AddEntry(Entry entry)
void  RemoveEntry(Entry entry)
void  AddGroup(Group group)
void  RemoveGroup(Group group)
void  Delete()            // moves to recycle bin if enabled, otherwise removes
void  MoveTo(Group parent)
Group Clone()
bool  IsAncestorOf(Group group)

// Search (recursive within the subtree)
Entry?             FindEntry(string title)
Entry?             FindEntry(Func<Entry, bool> predicate)
IEnumerable<Entry> FindAllEntries(Func<Entry, bool> predicate)
Group?             FindGroup(string name)
Group?             FindGroup(Func<Group, bool> predicate)
IEnumerable<Group> FindAllGroups(Func<Group, bool> predicate)
```

### `Settings`

Database format configuration. Pass to `Database.Create()` to customize.

```csharp
KdbxFormat               Format               // KdbxFormat.Kdbx4 (default) or KdbxFormat.Kdbx3
CipherAlgorithm          Cipher               // AES256, ChaCha20 (default), Twofish
bool                     IsCompressed         // GZip (true by default)
ProtectedStreamAlgorithm InnerStreamAlgorithm // ChaCha20 (default) or Salsa20
IKdf                     Kdf                  // Argon2id (default) or AesKdf
```

Example — create a KDBX 3.x database with AES-KDF:

```csharp
var settings = new Settings {
    Format = KdbxFormat.Kdbx3,
    Cipher = CipherAlgorithm.ChaCha20,
    Kdf    = new AesKdf(RandomNumberGenerator.GetBytes(32), 100_000UL),
};
var db = Database.Create("password", settings);
```

### `Version`

KDBX format version. Initialized to `0.0` (`IsZero == true`) before opening, then populated from the header when reading or derived from `Settings.Format` when calling `Create()`.

```csharp
ushort Major   // 3 or 4
ushort Minor   // e.g. 1
bool   IsZero  // true if not initialized

// Operators: ==, !=, <, <=, >, >=
// ToString()  → "4.1"
```

Examples:

```csharp
var db = Database.Create("pass");    // → db.Version == new Version(4, 1)
var db = Database.Open("v.kdbx", "pass");
if (db.Version >= new Version(4, 0))
    Console.WriteLine("KDBX 4.x");
```

### `CompositeKey`

```csharp
new CompositeKey()
new CompositeKey(string password)
new CompositeKey(string password, string keyFile)
CompositeKey AddPassword(string password)
CompositeKey AddKeyFile(string path)
```

### `KeyFile`

Key file generation. Supported read formats: KeePass XML v1, hex (64 chars), raw 32 bytes, any other file (SHA256 used as key).

```csharp
// Generation
KeyFile.Generate(string path, KeyFileFormat format = KeyFileFormat.Xml)

// Formats
KeyFileFormat.Xml   // KeePass XML v1 — interoperable with KeePassXC (default)
KeyFileFormat.Raw   // 32 raw random bytes
```

## Supported formats

| Format | Read | Write |
|--------|:----:|:-----:|
| KDBX 4.x | ✅ | ✅ |
| KDBX 3.x | ✅ | ✅ |
| GZip compression | ✅ | ✅ |
| HMAC-SHA256 blocks (v4) | ✅ | ✅ |
| Hashed blocks (v3) | ✅ | ✅ |
| Binary attachments (v4 inner header) | ✅ | ✅ |
| Binary attachments (v3 Meta pool) | ✅ | ✅ |
| Protected fields (ProtectedStream) | ✅ | ✅ |

## Cryptographic algorithms

| Algorithm | Role |
|-----------|------|
| Argon2d / Argon2id | KDF for KDBX 4.x (default: Argon2id) |
| AES-KDF | KDF for KDBX 3.x |
| AES-256-CBC | Payload encryption |
| ChaCha20 | Payload encryption (default) |
| Twofish | Payload encryption |
| ChaCha20 / Salsa20 | Protected stream for XML fields |

Single dependency: **BouncyCastle.Cryptography** (Argon2, ChaCha20, Twofish).

## Internal architecture

```
Database
├── KdbxReader(db).ReadFrom(stream)
│   ├── KdbxHeader.Read()          — binary header + KDF parameters
│   ├── DerivedKey.Derive()        — Argon2 / AES-KDF
│   ├── EncryptionKey              — encryption key + HMAC key
│   └── KdbxXmlReader(db, ps, v4).ReadFrom(stream)
│       └── db.SetupLoadedData()   — wires _db + entry index
│
└── KdbxWriter(db).WriteTo(stream)
    ├── KdbxHeader.CreateNew()
    ├── KdbxXmlWriter(db, ps, v4).WriteTo(stream)
    └── HMAC blocks (v4) / Hashed blocks (v3)
```

## Development commands

```bash
dotnet build    # Build
dotnet test     # Run tests
dotnet format   # Format code
dotnet pack     # Create NuGet package
```

## Test coverage

133 passing tests, 1 skipped (manual diagnostic).

### Covered ✓

| Area | What is tested |
|------|----------------|
| Roundtrip V4 | Argon2id + ChaCha20, protected fields, empty database |
| Roundtrip V3 | AES-KDF + ChaCha20 |
| Real files | `SimplePasswordV4.kdbx`, `SimplePasswordV3_ChaCha20.kdbx`, wrong password |
| XML Meta | `Name`, `ProtectPassword` |
| Entry strings | `Title`, `UserName`, `Password`, `Url` (read + write) |
| Binaries V4 | Single, multiple, deduplicated, `IsProtected` |
| Binaries V3 | Single binary via Meta pool |
| Entry CRUD | `Delete()` (with/without recycle bin), `MoveTo()`, `Update()` + history, `Clone()` |
| Group CRUD | `AddEntry/Group`, `RemoveEntry/Group`, `Delete()`, `MoveTo()`, `Clone()`, `IsAncestorOf()` |
| Database | `HasChanges`, `IsRecycleBinEnabled()`, `GetRecycleBin()`, `Version` |
| Search | `FindEntry` / `FindAllEntries` / `FindGroup` / `FindAllGroups` — root, nested, predicate, subtree |
| Times V4 | All date fields, `Expires`, `UsageCount`, `DateTimeKind.Utc`, Group times |
| Times V3 | All date fields, `Expires`, `DateTimeKind.Utc`, Group times |
| `Save` / `SaveAs` | File creation, overwrite, `HasChanges`, roundtrip V4/V3, subgroups |
| Key file | XML, hex, raw 32B, SHA256 fallback, errors, `KeyFile.Generate()` V4/V3 |
| Metadata | `Description`, `DefaultUserName`, `HistoryMaxSize/Items`, `RecycleBinEnabled/Uuid` |
| AutoType | `Enabled`, `DefaultSequence`, `DataTransferObfuscation`, associations (0, 1, N) |
| Ciphers | AES-256-CBC (V4/V3), Twofish-256-CBC (V4/V3), `Settings.Cipher` preserved |
| ProtectedStream | Salsa20 V3 (single + multiple entries), `Settings.InnerStreamAlgorithm` preserved |
| Validations | V3 + Argon2 raises `InvalidOperationException` |

### Not covered ✗

*No known uncovered areas.*

## Roadmap

- [ ] Custom icons (`<Meta><CustomIcons>`)
- [ ] Additional `<Meta>` fields (`Generator`, `MasterKeyChanged`, full `MemoryProtection`…)
- [x] `FindEntry()` / `FindGroup()` — recursive search on `Group` and `Database`
- [ ] Save synchronization — detect if the file was modified between open and save, merge changes instead of overwriting

## Acknowledgements

This library was developed with the assistance of [Claude](https://claude.ai) (Anthropic).
