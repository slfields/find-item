# Find-Item

> A Windows-native, PowerShell-idiomatic equivalent of GNU `findutils`'s
> `find` command — with `du`-style aggregation, NTFS ACL filtering, and
> first-class pipeline integration.

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue)]()
[![Tests](https://img.shields.io/badge/tests-286%2F286-brightgreen)]()
[![Coverage](https://img.shields.io/badge/coverage-comprehensive-brightgreen)]()

---

## Table of contents

- [Overview](#overview)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Syntax](#syntax)
- [Parameters](#parameters)
  - [Path and traversal](#path-and-traversal)
  - [Name and path filters](#name-and-path-filters)
  - [Negation filters](#negation-filters)
  - [Type filter](#type-filter)
  - [Size and Empty](#size-and-empty)
  - [Apparent vs allocated size](#apparent-vs-allocated-size)
  - [Time filters](#time-filters)
  - [Reference-file filter](#reference-file-filter)
  - [Custom predicate](#custom-predicate)
  - [ACL access filters](#acl-access-filters)
  - [Owner filters](#owner-filters)
  - [Output formatting](#output-formatting)
  - [Sorting and limiting](#sorting-and-limiting)
  - [Aggregation](#aggregation)
  - [Actions](#actions)
  - [Behavior modifiers](#behavior-modifiers)
- [Output objects](#output-objects)
- [Examples](#examples)
- [GNU find compatibility](#gnu-find-compatibility)
- [Compound boolean logic](#compound-boolean-logic)
- [Permission filter semantics](#permission-filter-semantics)
- [Security considerations](#security-considerations)
- [Performance and memory](#performance-and-memory)
- [Architecture](#architecture)
- [Testing](#testing)
- [Roadmap](#roadmap)
- [Parameter index](#parameter-index)

---

## Overview

`Find-Item` is a PowerShell function that searches a filesystem tree for
items matching a set of criteria, with first-class support for Windows
NTFS semantics (ACLs, reparse points, attributes). It is designed to be:

- **A GNU `find` equivalent** for users who want `find`'s expressiveness
  on Windows without WSL or Cygwin
- **PowerShell-native** — emits `FileInfo` / `DirectoryInfo` /
  `PSCustomObject` so output composes cleanly with `Sort-Object`,
  `Where-Object`, `Remove-Item`, `Export-Csv`, and the rest of the
  pipeline ecosystem
- **Du-extended** — adds `-Summary`, `-SummaryOnly`, and
  `-DirectoryTotals` for size-rollup queries that `find` alone can't
  answer
- **Safe by default** — pre-compiled regex with ReDoS timeout, safe
  reparse-point deletion, literal-ACL semantics with documented caveats
- **Memory-aware** — streaming output by default; explicit warnings
  when buffering for sort; early-termination for `-First N` queries

The function is a single `.ps1` file plus a companion `.format.ps1xml`
for table rendering. No external dependencies, no native binaries.

---

## Installation

### Option 1 — Dot-source per session

```powershell
. C:\path\to\Find-Item.ps1
Find-Item C:\Logs -Type File -Name *.log
```

### Option 2 — Auto-load from your `$PROFILE`

```powershell
# Add to $PROFILE
. "C:\path\to\Find-Item.ps1"
```

### Option 3 — Convert to a PowerShell module

```powershell
$dst = "$HOME\Documents\PowerShell\Modules\FindItem"
New-Item -ItemType Directory $dst -Force | Out-Null
Copy-Item .\Find-Item.ps1            "$dst\FindItem.psm1"
Copy-Item .\Find-Item.format.ps1xml  "$dst\Find-Item.format.ps1xml"
```

After installing as a module, `Find-Item` and `Get-Help Find-Item` work
in any new PowerShell session — no dot-sourcing or profile changes
needed.

### Option 4 — Direct script invocation

`.\Find-Item.ps1` executes the function directly with the supplied
arguments. Useful for one-off use or shebang-style scripting.

```powershell
.\Find-Item.ps1 C:\Logs -Name "*.log" -LastWriteTime +30d
```

### Requirements

| Component | Minimum | Notes |
|---|---|---|
| PowerShell | **5.1** | Windows PowerShell 5.1 or PowerShell 7+ both supported |
| .NET | 4.5+ | For `Regex` match-timeout and `EnumerateFileSystemInfos` |
| OS | Windows | Uses NTFS-specific concepts (ACLs, reparse points, PATHEXT) |
| Pester | 5.0+ | **Only for running the test suite** |

---

## Quick start

```powershell
# All .log files in a directory tree
Find-Item C:\Logs -Type File -Name "*.log"

# Big files first, top 10
Find-Item C:\Users\me -Type File -SortBy Length -SortOrder Desc -First 10

# Disk usage by directory (du-style)
Find-Item C:\Users\me -DirectoryTotals -SizeUnit Auto -MaxDepth 2

# Security audit: files anyone can write
Find-Item C:\Apps -Type File -WritableBy 'Everyone','BUILTIN\Users'

# Cleanup with audit trail
Find-Item C:\Temp -Name "*.tmp" -LastWriteTime +7d -Delete -PassThru |
    Export-Csv .\cleanup-$(Get-Date -Format yyyyMMdd).csv -NoTypeInformation

# Pipeline composition
Get-Content servers.txt | ForEach-Object { "\\$_\C$\Logs" } |
    Find-Item -Name "*.log" -LastWriteTime -1h
```

---

## Syntax

```powershell
Find-Item
    [[-Path] <String[]>]
    [-Name <String[]>] [-IName <String[]>]
    [-Regex <String[]>] [-IRegex <String[]>]
    [-NotName <String[]>] [-NotIName <String[]>]
    [-NotRegex <String[]>] [-NotIRegex <String[]>]
    [-Type <String[]>]
    [-Filter <ScriptBlock>]
    [-Size <String>]
    [-Empty]
    [-LastWriteTime <String>] [-LastAccessTime <String>] [-CreationTime <String>]
    [-Newer <String>]
    [-ReadableBy <String[]>] [-WritableBy <String[]>] [-AppendableBy <String[]>]
    [-ExecutableBy <String[]>] [-ModifiableBy <String[]>] [-FullControlBy <String[]>]
    [-Owner <String[]>] [-NotOwner <String[]>]
    [-MaxDepth <Int32>] [-MinDepth <Int32>]
    [-Exclude <String[]>]
    [-FollowSymlinks]
    [-Delete] [-PassThru]
    [-FullPath] [-LongList] [-ShowOwner] [-SizeUnit <String>]
    [-AllocatedSize] [-IncludeStreams]
    [-Summary] [-SummaryOnly] [-DirectoryTotals]
    [-SortBy <String>] [-SortOrder <String>]
    [-First <Int32>] [-Last <Int32>]
    [-MaxBufferItems <Int32>]
    [-WhatIf] [-Confirm]
    [<CommonParameters>]
```

All filter parameters are **ANDed** with each other. Multi-valued
parameters use **OR** within the parameter (e.g. `-Name "*.log","*.tmp"`
matches either). See [Compound boolean logic](#compound-boolean-logic)
for full details.

---

## Parameters

### Path and traversal

#### `-Path <String[]>`

Starting paths. Defaults to `.` (current directory). Accepts:

- One or more paths positionally or via `-Path`
- Pipeline input by value: `'C:\dir1','C:\dir2' | Find-Item`
- Pipeline input by property name via `FullName` and `PSPath` aliases,
  so `FileSystemInfo` / PSProvider items pipe directly:

```powershell
Get-ChildItem C:\Repos -Directory | Find-Item -Type File -Name *.log
Get-Content paths.txt              | Find-Item -Type File
```

When piped, all input is collected before the search begins; one
`Find-Item` invocation processes the full set, and the [aggregation
parameters](#aggregation) operate across the combined result.

#### `-MaxDepth <Int32>`

Maximum directory depth to descend. `0` means the starting path itself;
no children. Defaults to `[int]::MaxValue` (unlimited).

Interaction with `-DirectoryTotals`: when `-DirectoryTotals` is set,
`-MaxDepth` limits **emission** only, not counting — the recursion
descends to the bottom so each emitted directory's recursive total is
accurate. This mirrors GNU `du -d N` semantics.

#### `-MinDepth <Int32>`

Minimum depth before emitting results. `0` includes the starting path
itself; `1` excludes the root. Defaults to `0`.

#### `-Exclude <String[]>`

One or more wildcard patterns for directory names to skip entirely
(equivalent to `find -prune`). Matched case-insensitively. Pruned
subtrees do not contribute to `-DirectoryTotals` either.

```powershell
Find-Item . -Exclude ".git", "node_modules", "bin", "obj"
```

#### `-FollowSymlinks`

Descend into symbolic links and junctions. Without this switch,
reparse-point directories are not traversed.

### Name and path filters

#### `-Name <String[]>` / `-IName <String[]>`

Wildcard patterns matched against the item **name**. Array values are
ORed (item matches if ANY pattern matches).

- `-Name` is case-insensitive on Windows (matches NTFS behavior)
- `-IName` is explicitly case-insensitive (identical to `-Name` on Windows)

```powershell
Find-Item . -Name "*.log"
Find-Item . -Name "*.log","*.tmp","*~"   # array = OR
```

#### `-Regex <String[]>` / `-IRegex <String[]>`

Regular expressions matched against the item's **full path**. Patterns
are **pre-compiled** at function-entry time with a 5-second per-match
timeout to defuse ReDoS. A timed-out match emits a warning and is
skipped for that item.

- `-Regex` follows PowerShell defaults (case-insensitive)
- `-IRegex` explicitly case-insensitive
- Array = OR

```powershell
Find-Item . -Regex '\\tests?\\.+\.spec\.ts$'
Find-Item . -Regex '\.log$','\.tmp$'
```

### Negation filters

Mirror the positive name/path filters; item is REJECTED if any listed
pattern matches.

| Parameter | Mirrors | Semantics |
|---|---|---|
| `-NotName <String[]>` | `-Name` | reject if any name wildcard matches |
| `-NotIName <String[]>` | `-IName` | case-insensitive variant |
| `-NotRegex <String[]>` | `-Regex` | reject if any regex matches FullName |
| `-NotIRegex <String[]>` | `-IRegex` | case-insensitive variant |

```powershell
# All files EXCEPT backups and editor temps
Find-Item . -Type File -NotName "*.bak", "*~", ".gitkeep"
```

### Type filter

#### `-Type <String[]>`

Filter by item type. Accepts: `f`/`File`, `d`/`Directory`,
`l`/`SymbolicLink`. Array = OR.

| Value | Matches |
|---|---|
| `f` / `File` | Regular files (not symlinks/junctions) |
| `d` / `Directory` | Regular directories (not symlinks/junctions) |
| `l` / `SymbolicLink` | Any reparse point (junction, symlink, mount point) |

```powershell
Find-Item . -Type File
Find-Item . -Type File, SymbolicLink   # files OR symlinks
```

### Size and Empty

#### `-Size <String>`

Filter files by size. Format: `[+|-]<n>[c|k|M|G]`

- **Prefix:** `+` larger than, `-` smaller than, none = exactly
- **Suffix:** `c` bytes, `k` kibibytes (1024), `M` mebibytes,
  `G` gibibytes, none = 512-byte blocks (GNU find default)

```powershell
Find-Item . -Size +10M     # files larger than 10 MiB
Find-Item . -Size -1k      # files smaller than 1 KiB
Find-Item . -Size 512c     # exactly 512 bytes
```

> **Note:** `-Size` implicitly excludes directories and reparse points
> on Windows (they have no meaningful `Length`). This differs from
> Linux `find`, where directories have an entry-list size.

> **Note:** by default `-Size` filters against the **logical** file
> length. Pass `-AllocatedSize` to filter against on-disk allocation
> instead (a 100-byte file would then match `-Size +1k` on a typical
> 4 KiB-cluster volume). See [Apparent vs allocated size](#apparent-vs-allocated-size).

#### `-Empty`

Match items that are empty: files of length 0, directories with no
entries. Equivalent to GNU find's `-empty`.

```powershell
Find-Item C:\Build -Type Directory -Empty -Delete -WhatIf
Find-Item C:\Temp  -Type File -Empty
```

For directories, the check short-circuits on the first entry; the full
child list is never materialized.

### Apparent vs allocated size

By default, every size-reporting feature uses the **logical (apparent)**
file content size — equivalent to GNU `du --apparent-size`. To report
**on-disk allocation** instead (matching Explorer's "Size on disk" column
and GNU `du`'s default behaviour), pass `-AllocatedSize`.

#### `-AllocatedSize`

Flips size semantics globally — every size-related feature reports
cluster-rounded on-disk bytes via Win32 `GetCompressedFileSize`:

| Feature | Default (logical) | With `-AllocatedSize` |
|---|---|---|
| `-Size` filter | filters on `Length` | filters on cluster-rounded allocation |
| `-LongList` Length column | logical bytes | allocated bytes |
| `-SortBy Length` | sort by logical | sort by allocated |
| `-DirectoryTotals` | sum of logical | sum of allocated |
| `-Summary TotalBytes` | logical sum | allocated sum |
| `-Empty` | logical Length == 0 | **unchanged** — still tests logical |
| Default `FileInfo` output | unchanged | unchanged (can't shadow `.Length`) |

Handles every case correctly:

| File | Logical | Allocated (4 KiB clusters) |
|---|---|---|
| 0-byte empty | 0 | 0 |
| 100-byte normal | 100 | 4,096 |
| 5,000-byte normal | 5,000 | 8,192 |
| 100,000-byte normal | 100,000 | 102,400 |
| 1 MiB all-holes sparse | 1,048,576 | 0 or 1 cluster |
| 5 MiB compressed to 1 MiB | 5,242,880 | 1,048,576 (rounded) |
| Resident-in-MFT (e.g. 200B) | 200 | 4,096 (cluster floor) |

Cached per invocation so combining with `-Size`, `-DirectoryTotals`,
`-Summary`, `-LongList`, and `-SortBy Length` together costs **one**
Win32 call per file (not five). Overhead is ~1-5 μs per file —
negligible compared to ACL operations.

#### `-IncludeStreams`

When combined with `-AllocatedSize`, additionally sum every alternate
data stream (ADS) on each file, not just the main stream.

```powershell
# ADS-aware forensic sweep
Find-Item C:\Forensic -Type File -AllocatedSize -IncludeStreams -Ls -SizeUnit Auto
```

Most files have no ADS, so the typical overhead is one extra
`FindFirstStreamW` per file. For ADS-heavy files (mail spools,
metadata stores), each named stream gets its own
`GetCompressedFileSize` call.

> **Note:** `-Empty` deliberately ignores `-AllocatedSize`. See the
> [Size and Empty](#size-and-empty) section for the rationale (sparse
> file footgun).

### Time filters

`-LastWriteTime`, `-LastAccessTime`, and `-CreationTime` are
Windows-native names; aliases `-MTime`, `-ATime`, `-CTime`, `-BTime`
are provided for GNU `find` muscle memory.

| Parameter | Alias(es) | NTFS attribute |
|---|---|---|
| `-LastWriteTime` | `-MTime` | When content was last written |
| `-LastAccessTime` | `-ATime` | When item was last opened |
| `-CreationTime` | `-CTime`, `-BTime` | When item was first created at this location |

All three accept the same three input forms:

#### Numeric + unit suffix `[+|-]<n>[m|h|d|w]`

| Form | Meaning |
|---|---|
| `+7` or `+7d` | older than 7 days |
| `-7` or `-7d` | newer than 7 days |
| `7` | between 7 and 8 days ago |
| `-5m` | last 5 minutes |
| `-2h` | last 2 hours |
| `-2w` | last 2 weeks |
| `+30m` | more than 30 minutes ago |

A bare number (no suffix) means days, for GNU `find` parity. Suffix
units: `m` minutes, `h` hours, `d` days, `w` weeks. Months/years are
deliberately not supported (ambiguous lengths).

#### Calendar date `[+|-]<date>`

```powershell
-LastWriteTime "2026-01-15"     # modified on that calendar day
-LastWriteTime "+2026-01-15"    # modified after midnight that day
-LastWriteTime "-2026-01-15"    # modified before midnight that day
```

Any culture-recognized format works: `2026-01-15`, `01/15/2026`,
`"Jan 15 2026"`, etc.

#### Date-time `[+|-]<date-time>`

```powershell
-LastWriteTime "2026-01-15 14:30:00"   # within that exact second
-LastWriteTime "+2026-01-15T14:30"     # after that instant (ISO-8601)
-LastWriteTime "-2026-01-15 14:30:00"  # before that instant
```

> **Sign-semantics gotcha:** for numeric input, `-` means "age less
> than threshold" (newer); for absolute dates, `-` means "timestamp
> less than threshold" (older). The mathematical meaning is identical
> (`<`); the plain-English meaning flips because age and timestamp run
> in opposite directions.

> **`-CTime` semantic mismatch:** in GNU `find`, `-ctime` means **inode
> metadata change time**. On Windows, `-CTime` is an alias for
> `-CreationTime`. This matches the convention used by GnuWin32 ports.
> The closest true GNU semantic equivalent would be the NTFS MFT change
> time, which is not exposed by standard .NET APIs.

### Reference-file filter

#### `-Newer <String>`

Match items whose `LastWriteTime` is strictly newer than the
modification time of the file at the given path.

```powershell
Find-Item . -Type File -Newer .\reference.txt
```

### Custom predicate

#### `-Filter <ScriptBlock>`

A `Where-Object`-style scriptblock that runs against each candidate
item. Receives the item as `$_`; truthy result = item passes. Use this
for arbitrary boolean logic the structured parameters can't express.

```powershell
Find-Item C:\Logs -Type File -Filter {
    ($_.Name -like "*.log" -or $_.Name -like "*.tmp") -and
    $_.LastWriteTime -lt (Get-Date).AddDays(-30) -and
    -not ($_.FullName -match '\\archive\\')
}
```

`-Filter` runs **after** all built-in filters (cheap checks short-circuit
first), and **before** ACL and owner filters. The full PowerShell
expression language is available.

> **Security:** `-Filter` is full PowerShell. Never build it from
> untrusted input — that's equivalent to `Invoke-Expression` on the
> input. Use structured parameters for user-supplied filtering. See
> [Security considerations](#security-considerations).

### ACL access filters

The Windows-native analog of GNU `find -perm`. Each filter takes one or
more **principal patterns** matched with `-like` against ACE
`IdentityReference` values (e.g. `'BUILTIN\Administrators'`,
`'Everyone'`, `'CORP\*'`, `'*\alice'`). Array = OR within the
parameter; an item passes if ANY listed principal has the requested
access via an **Allow** ACE.

| Parameter | Matches (file mask) | Matches (dir mask) | Mode |
|---|---|---|---|
| `-ReadableBy` | `ReadData` ∨ `ReadAttributes` ∨ `ReadExtendedAttributes` | `ListDirectory` ∨ `ReadAttributes` ∨ `ReadExtendedAttributes` | any-bit |
| `-WritableBy` | `WriteData` ∨ `WriteAttributes` ∨ `WriteExtendedAttributes` ∨ `Delete` | `CreateFiles` ∨ `CreateDirectories` ∨ `DeleteSubdirectoriesAndFiles` ∨ `WriteAttributes` ∨ `WriteExtendedAttributes` ∨ `Delete` | any-bit |
| `-AppendableBy` | `AppendData` | `CreateDirectories` (same bit) | any-bit |
| `-ExecutableBy` | `ExecuteFile` **+ extension in `$env:PATHEXT`/`.ps1`/`.psm1`/`.psd1`** | `Traverse` (no extension check) | any-bit |
| `-ModifiableBy` | `Modify` composite | `Modify` composite | **all-bits** |
| `-FullControlBy` | `FullControl` composite | `FullControl` composite | **all-bits** |

```powershell
# Classic world-writable audit (Windows-native -perm -o+w)
Find-Item C:\Shared -Type File -WritableBy 'Everyone','BUILTIN\Users'

# All-bits Modify: principal has the FULL Modify composite (not just any constituent)
Find-Item C:\Apps -ModifiableBy 'Everyone' -Ls -ShowOwner
```

See [Permission filter semantics](#permission-filter-semantics) for the
literal-ACL vs effective-access distinction and the complete bit-by-bit
inventory of how `FileSystemRights` values map to filters.

### Owner filters

#### `-Owner <String[]>` / `-NotOwner <String[]>`

The Windows-native analog of GNU `find -user`. Match items whose NTFS
owner matches (`-Owner`) or does not match (`-NotOwner`) ANY listed
wildcard pattern.

```powershell
Find-Item C:\Shared -Type File -Owner '*\alice'
Find-Item C:\Apps -Type File -NotOwner 'NT AUTHORITY\SYSTEM','BUILTIN\Administrators','BUILTIN\TrustedInstaller'
```

Uses the per-invocation ACL cache, so combining `-Owner` with
`-ShowOwner`, `-SortBy Owner`, or any `-*By` access filter costs one
`Get-Acl` per item (not per filter).

### Output formatting

The four output modes are mutually exclusive — choose at most one:

| Mode | Output type | Selected by |
|---|---|---|
| **Default** | `FileInfo` / `DirectoryInfo` | (no switch) |
| **Strings** | `[string]` (full path) | `-FullPath` |
| **Long list** | `PSCustomObject` (table-rendered) | `-LongList` / `-Ls` |
| **Summary** | `PSCustomObject` (Summary type) | `-SummaryOnly` (suppresses per-item output) |

#### `-FullPath`

Output plain `[string]` full paths instead of `FileSystemInfo` objects.
Mutually exclusive with `-LongList`.

```powershell
Find-Item . -Type File -FullPath | Out-File files.txt
```

#### `-LongList` (alias `-Ls`)

Equivalent of GNU `find -ls`. Emits each item as a `PSCustomObject`
with columns: `Mode`, `Length`, `LastWriteTime`, `FullName` (plus
`Owner` when `-ShowOwner` is set). Rendered by the companion
`Find-Item.format.ps1xml` as a table.

#### `-ShowOwner`

Adds an `Owner` column to `-LongList` output, populated from each
file's ACL. Implies `-LongList` if used alone.

> **Performance:** ACL lookup is roughly 50–200 ms per file. Use
> sparingly on large result sets. The per-invocation ACL cache means
> combining `-ShowOwner` with `-Owner`/`-SortBy Owner`/`-*By` filters
> only pays once per item.

#### `-SizeUnit <String>`

Controls how the `Length` column is displayed in `-LongList` output.
Implies `-LongList` when set to anything other than the default.

| Value | Output |
|---|---|
| `Bytes` (default) | Raw `Int64`, no suffix — safe for `Sort-Object Length` |
| `KiB` / `MiB` / `GiB` / `TiB` | Formatted `[string]` like `"1.50 MiB"` |
| `Auto` | Per-row adaptive: smallest unit where value ≥ 1 |

> **Trade-off:** any value other than `Bytes` turns `Length` into a
> formatted **string**, which means downstream `Sort-Object Length`
> sorts lexically, not numerically. Use `-SortBy Length` (which always
> sorts on raw bytes) if you need both pretty display and accurate
> sorting.

### Sorting and limiting

#### `-SortBy <String>` / `-SortOrder <String>`

Sort the output. Always type-aware (numeric, datetime, string) based on
the column.

`-SortBy` accepts: `Name`, `FullName`, `Length`, `LastWriteTime`,
`CreationTime`, `LastAccessTime`, `Extension`, `Mode`, `Owner`, `Type`.

`-SortOrder` accepts `Ascending`/`Asc` (default) or `Descending`/`Desc`.

> **Length-sort note:** `-SortBy Length` always sorts on raw bytes from
> the underlying `FileSystemInfo`, even when `-SizeUnit` formats the
> displayed value as a string. This is the right combination if you
> want both pretty output and correct order.

```powershell
# Top 10 biggest files
Find-Item C:\ -Type File -SortBy Length -SortOrder Desc -First 10

# Most-recently modified .log files first
Find-Item C:\Logs -Type File -Name "*.log" -SortBy LastWriteTime -SortOrder Desc

# Group files by extension
Find-Item . -Type File -SortBy Extension | Group-Object Extension
```

> **Memory:** specifying `-SortBy` switches the function from streaming
> output to buffered. The full result set is collected before sorting.
> Without `-SortBy`, output streams and uses O(1) memory.

#### `-First <Int32>` / `-Last <Int32>`

Cap the result count. Mutually exclusive.

- `-First N` **without** `-SortBy`: early-terminates traversal at item
  N. O(1) memory, minimal I/O.
- `-First N` **with** `-SortBy`: buffer everything, sort, take first N.
- `-Last N` **without** `-SortBy`: sliding-window queue of size N.
  O(N) memory regardless of total matches.
- `-Last N` **with** `-SortBy`: take last N from sorted result.

```powershell
# First 100 .log files in traversal order (early-term: O(1) memory)
Find-Item C:\Logs -Type File -Name "*.log" -First 100

# 5 most recent files (sliding window: O(5) memory)
Find-Item C:\Logs -Type File -Last 5
```

#### `-MaxBufferItems <Int32>`

Soft threshold (default `100000`) for emitting a warning when the
`-SortBy` buffer crosses N items. Set to `0` to silence. Has no effect
unless `-SortBy` is also set.

### Aggregation

du-derived features. None of these have a direct GNU `find` equivalent
— Linux users would compose `find ... | wc -l` and `du -ch`.

#### `-Summary`

Append a single summary record to the END of the output stream with
totals. The summary is a `PSCustomObject` of type `FindItem.Summary`
with columns: `ItemCount`, `FileCount`, `DirectoryCount`,
`SymlinkCount`, `TotalBytes`, `TotalSize`.

```powershell
Find-Item C:\Logs -Type File -Name *.log -Summary
# ... per-file rows ...
# then one summary record at the end
```

> **Mixed-stream caveat:** when `-Summary` is combined with per-item
> output, the stream contains `FileSystemInfo` items followed by one
> `PSCustomObject`. Downstream commands that don't handle the schema
> change cleanly should use `-SummaryOnly` instead.

#### `-SummaryOnly`

Emit only the summary record. Per-item output suppressed entirely.
Implies `-Summary`. Work still happens (traversal, filtering, even
`-Delete`); only the per-item rows are not written to the pipeline.

```powershell
Find-Item C:\AMD -SummaryOnly
# Items Files Dirs Links TotalBytes TotalSize
# ----- ----- ---- ----- ---------- ---------
#   582   420  162     0   87508926 83.46 MiB
```

#### `-DirectoryTotals` (alias `-DirTotals`)

Fill the `Length` column for directories with the recursive byte total
of every file underneath them. Implies `-LongList`. Implicitly sets
`-Type Directory` unless the user explicitly passes `-Type`.

```powershell
# What's eating disk under C:\Users?
Find-Item C:\Users -DirectoryTotals -SizeUnit Auto -SortBy Length -SortOrder Desc -First 20
```

- Pruned subtrees (`-Exclude`) do NOT contribute to parent totals
- `-MaxDepth` interaction: when `-DirectoryTotals` is set, MaxDepth
  limits ONLY emission, not counting (matches `du -d N`)

### Actions

#### `-Delete`

Delete matching items instead of (or alongside, with `-PassThru`)
emitting them. Supports `-WhatIf` and `-Confirm`.

> **Important — subtree deletion:** when a matched item is a
> directory, the ENTIRE subtree under it is removed. Combined with
> broad filters this can be much more destructive than expected.
> Always preview with `-WhatIf` first.

> **Important — reparse-point safety:** junctions and symbolic links
> are deleted as link entries only — the link target is never
> followed. The function uses `[System.IO.Directory]::Delete(path,
> recursive=$false)` for reparse-point directories rather than
> `Remove-Item -Recurse`, which has historically followed links and
> destroyed target contents on Windows PowerShell 5.1.

#### `-PassThru`

When combined with `-Delete`, also emit each deleted item — the same
object that would be emitted in non-delete mode. Standard PowerShell
convention for destructive cmdlets.

```powershell
Find-Item C:\Temp -Name "*.tmp" -Delete -PassThru |
    Export-Csv .\deleted-$(Get-Date -Format yyyyMMdd).csv -NoTypeInformation
```

The emitted object references a now-deleted path; in-memory properties
(`Name`, `FullName`, `Length`, `LastWriteTime`, `Mode`) remain valid
because they were captured before deletion.

### Behavior modifiers

- **`-WhatIf`** — show what `-Delete` would do without doing it
- **`-Confirm`** — prompt before each `-Delete` operation
- **`-Verbose`**, **`-Debug`**, **`-ErrorAction`** etc. — standard
  `CmdletBinding` common parameters

---

## Output objects

Find-Item emits different shapes depending on the output mode:

### Default mode

`System.IO.FileInfo` for files, `System.IO.DirectoryInfo` for
directories. Same objects you get from `Get-ChildItem`.

```powershell
Find-Item C:\ -Type File -Name *.log | Get-Member
# TypeName: System.IO.FileInfo
# ...standard FileInfo members...
```

### `-FullPath`

`System.String`. Full path of each match, one per line.

### `-LongList` (default columns)

`PSCustomObject` with the type name `FindItem.LongListEntry`. Properties:

| Property | Type | Value |
|---|---|---|
| `Mode` | `String` | NTFS attribute summary (`d-----`, `-a----`) |
| `Length` | `Int64` or `String` | File size (formatted per `-SizeUnit`) |
| `LastWriteTime` | `DateTime` | Modification timestamp |
| `FullName` | `String` | Full path |

### `-LongList` + `-ShowOwner`

`PSCustomObject` with the type name `FindItem.LongListEntryWithOwner`.
Adds an `Owner` column.

### `-Summary` / `-SummaryOnly`

`PSCustomObject` with the type name `FindItem.Summary`. Properties:

| Property | Type | Value |
|---|---|---|
| `ItemCount` | `Int32` | Total matched |
| `FileCount` | `Int32` | Files only |
| `DirectoryCount` | `Int32` | Directories only |
| `SymlinkCount` | `Int32` | Reparse points |
| `TotalBytes` | `Int64` | Sum of file sizes (raw numeric) |
| `TotalSize` | `String` | Formatted per `-SizeUnit` (or Auto for default Bytes) |

Custom format views for each PSCustomObject type are registered by
loading the companion `Find-Item.format.ps1xml` at script load time.

---

## Examples

### Quick searches

```powershell
# All files in current dir tree
Find-Item

# All .ps1 files under a path
Find-Item C:\Projects -Type File -Name *.ps1

# Case-insensitive match (Windows default for -Name, explicit here)
Find-Item C:\Docs -Type File -IName "*.DOCX"
```

### Time-based queries

```powershell
# Modified in the last hour
Find-Item C:\Logs -Type File -LastWriteTime -1h

# Modified more than 30 days ago
Find-Item C:\Backups -Type File -LastWriteTime +30d

# Modified within the last 5 minutes (debugging "what just changed?")
Find-Item C:\App -Type File -LastWriteTime -5m

# Files created since a specific date
Find-Item C:\Repos -Type File -CreationTime "+2026-01-01"

# Files created on a specific calendar day
Find-Item C:\Repos -Type File -CreationTime "2026-05-20"

# Files newer than a reference
Find-Item . -Type File -Newer .\release-marker.txt
```

### Size and emptiness

```powershell
# Files larger than 100 MiB
Find-Item C:\ -Type File -Size +100M

# Smallest .log files
Find-Item C:\Logs -Type File -Name *.log -SortBy Length -First 10

# Zero-byte files (broken downloads, failed extracts)
Find-Item C:\Downloads -Type File -Empty

# Empty directories (build artifacts left behind)
Find-Item C:\Build -Type Directory -Empty -Delete -WhatIf
```

### Compound logic

```powershell
# Logs OR temp files (array = OR within parameter)
Find-Item . -Type File -Name "*.log","*.tmp","*~"

# All files EXCEPT backups
Find-Item C:\Source -Type File -NotName "*.bak","*~",".gitkeep"

# Files OR symlinks (Type array)
Find-Item C:\Path -Type File, SymbolicLink

# Nested boolean via -Filter scriptblock
Find-Item C:\Logs -Type File -Filter {
    ($_.Name -like "*.log" -or $_.Name -like "*.tmp") -and
    -not ($_.FullName -match '\\archive\\') -and
    $_.Length -gt 1MB
}
```

### Audit and security

```powershell
# Define your "broad" principal set once
$broad = @(
    'Everyone'
    'BUILTIN\Users'
    'NT AUTHORITY\Authenticated Users'
    'NT AUTHORITY\ANONYMOUS LOGON'
)

# World-writable files
Find-Item C:\Shared -Type File -WritableBy $broad

# World-readable sensitive files
Find-Item C:\Apps -Type File `
    -Name "*.config","*.ini","*.key","*.pem","*.pfx","*.env" `
    -ReadableBy $broad -Ls -ShowOwner

# World-EXECUTABLE programs (extension in PATHEXT + Allow:Execute)
Find-Item C:\ProgramData -Type File -ExecutableBy $broad

# Files NOT owned by trusted system principals
Find-Item C:\Apps -Type File `
    -NotOwner 'NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators', 'BUILTIN\TrustedInstaller'

# Files where a broad principal has full Modify (read+write+delete)
Find-Item C:\Shared -Type File -ModifiableBy $broad -Ls -ShowOwner

# Strictest: FullControl misconfiguration
Find-Item C:\Apps -FullControlBy $broad -Ls
```

### Disk usage / du-style queries

```powershell
# Top-level directory map with sizes
Find-Item C:\Users\me -DirectoryTotals -MaxDepth 1 -SizeUnit Auto |
    Sort-Object FullName

# Biggest directories under a path
Find-Item C:\ -DirectoryTotals -SortBy Length -SortOrder Desc -First 20 -SizeUnit Auto

# Total size of all .log files
Find-Item C:\Logs -Type File -Name *.log -SummaryOnly

# Per-directory roll-up via Group-Object
Find-Item C:\Shared -Type File |
    Group-Object DirectoryName |
    Select-Object Count,
                  @{n='TotalKB';e={[math]::Round((($_.Group | Measure-Object Length -Sum).Sum)/1KB, 1)}},
                  Name |
    Sort-Object TotalKB -Descending
```

### Cleanup

```powershell
# Preview deletion
Find-Item C:\Temp -Name "*.tmp" -Delete -WhatIf

# Delete with audit trail
Find-Item C:\Temp -Name "*.tmp" -LastWriteTime +7d -Delete -PassThru |
    Export-Csv .\cleanup-$(Get-Date -Format yyyyMMdd).csv -NoTypeInformation

# Delete only the first N matches (early-term: minimal I/O)
Find-Item C:\Quarantine -Type File -Delete -First 100 -Confirm:$false

# Recursive empty-dir cleanup
Find-Item C:\Build -Type Directory -Empty -Delete -Confirm:$false
```

### Pipeline composition

```powershell
# Read paths from a file
Get-Content paths.txt | Find-Item -Type File -Name *.log

# Build paths dynamically
Get-Content servers.txt | ForEach-Object { "\\$_\C$\Logs" } |
    Find-Item -Type File -Name "*.log" -LastWriteTime -1h

# Pipe directory objects (auto-binds via FullName alias)
Get-ChildItem C:\Repos -Directory | Find-Item -Type File -Name *.cs

# Chain with native PS cmdlets
Find-Item C:\ -Type File -Size +500M |
    Sort-Object Length -Descending |
    Select-Object -First 50 FullName, Length, LastWriteTime
```

### Direct script invocation

```powershell
# Run the script directly without dot-sourcing
.\Find-Item.ps1 C:\AMD -Type File -SortBy Length -SortOrder Desc -First 10

# Useful in CI / scheduled tasks
& "$PSScriptRoot\Find-Item.ps1" C:\Logs -Name "*.log" -LastWriteTime +30d -Delete -Confirm:$false
```

---

## GNU find compatibility

### Tests (predicates)

| GNU find | Find-Item | Notes |
|---|---|---|
| `-name pattern` | `-Name` | Array = OR |
| `-iname pattern` | `-IName` | (Windows is case-insensitive anyway) |
| `-regex pattern` | `-Regex` | Pre-compiled with ReDoS timeout |
| `-iregex pattern` | `-IRegex` | |
| `-path` / `-wholename` | `-Regex` against `FullName` | |
| `-type f` / `d` / `l` | `-Type File` / `Directory` / `SymbolicLink` | Array = OR |
| `-size N[cwbkMG]` | `-Size` | `c`/`k`/`M`/`G` supported (not `w`/`b`) |
| `-empty` | `-Empty` | |
| `-mtime N` | `-LastWriteTime` (or `-MTime`) | Plus minute/hour/week suffixes |
| `-atime N` | `-LastAccessTime` (or `-ATime`) | |
| `-ctime N` | `-CreationTime` (or `-CTime`/`-BTime`) | Semantic mismatch noted |
| `-mmin N` / `-amin N` / `-cmin N` | `-LastWriteTime -Nm` etc. | Unit suffixes m/h/d/w |
| `-newer FILE` | `-Newer` | |
| `-anewer` / `-cnewer` | (no equivalent) | Reasonably easy add if needed |
| `-perm MODE` | `-ReadableBy` / `-WritableBy` / ... | NTFS ACL equivalent — see [Permission filter semantics](#permission-filter-semantics) |
| `-user NAME` | `-Owner` | Wildcard patterns |
| `-uid N` | (no equivalent) | Windows uses SIDs, not numeric UIDs |
| `-group NAME` / `-gid N` | (no equivalent) | Same |
| `-readable` / `-writable` / `-executable` | `-WritableBy "$env:USERNAME"` etc. | Literal-ACL not effective-access |
| `-links N` | (no equivalent) | Hard links rare on Windows |
| `-fstype TYPE` | (no equivalent) | |
| `-nouser` / `-nogroup` | (no equivalent) | |

### Operators

| GNU find | Find-Item |
|---|---|
| `-and` / `-a` (or implicit) | Multiple parameters are implicitly ANDed |
| `-or` / `-o` | Array values within a parameter; or `-Filter` scriptblock |
| `-not` / `!` | `-Not*` siblings (`-NotName`, etc.); or `-Filter` |
| `\( expr \)` | `-Filter { ... }` |

### Actions

| GNU find | Find-Item | Notes |
|---|---|---|
| `-print` / `-print0` | (default) / `-FullPath` | |
| `-ls` | `-LongList` / `-Ls` | |
| `-delete` | `-Delete` | Plus reparse-point safety, `-PassThru`, `-WhatIf`/`-Confirm` |
| `-prune` | `-Exclude` | Directory pruning |
| `-quit` after N | `-First N` | |
| `-printf FORMAT` | (use `Select-Object` / `Format-Table`) | Different idiom, equivalent outcome |
| `-exec` / `-execdir` | (use pipeline `\| ForEach-Object { ... }`) | **Deliberately not implemented** — pipelines are the safer PS idiom |
| `-ok` / `-okdir` | `-Confirm` on `-Delete` | |
| `-fprint` / `-fls` etc. | (use `Out-File`, `Export-Csv`) | |

### Global options

| GNU find | Find-Item |
|---|---|
| `-maxdepth N` | `-MaxDepth` |
| `-mindepth N` | `-MinDepth` |
| `-follow` / `-L` | `-FollowSymlinks` |
| `-xdev` / `-mount` | (no equivalent) |
| `-depth` (post-order) | (used internally for `-DirectoryTotals`) |

### Extensions (no GNU find analog)

These are Find-Item additions for use cases `find` doesn't directly serve:

| Feature | Inspired by |
|---|---|
| `-Summary` / `-SummaryOnly` | `du -c` / `du -s` |
| `-DirectoryTotals` | `du` default behavior |
| `-AllocatedSize` | `du` default (vs `du --apparent-size`) |
| `-IncludeStreams` | NTFS-specific (no Linux analog) |
| `-SizeUnit` (KiB/MiB/GiB/TiB/Auto) | `du -h` |
| `-SortBy` / `-SortOrder` | PowerShell `Sort-Object` |
| `-First` / `-Last` | PowerShell `Select-Object` |
| `-PassThru` | PowerShell convention for destructive cmdlets |
| `-MaxBufferItems` | Memory-warning guardrail (no precedent) |
| `-Filter` scriptblock | PowerShell `Where-Object` |

### `du` equivalence table

| GNU `du` command | Find-Item form |
|---|---|
| `du -s /path` | `Find-Item /path -SummaryOnly -AllocatedSize` |
| `du --apparent-size -s /path` | `Find-Item /path -SummaryOnly` |
| `du -h /path` | `-DirectoryTotals -AllocatedSize -SizeUnit Auto` |
| `du -hd 1 /path` | `-DirectoryTotals -AllocatedSize -SizeUnit Auto -MaxDepth 1` |
| `du -h --apparent-size /path` | `-DirectoryTotals -SizeUnit Auto` (no `-AllocatedSize`) |

---

## Compound boolean logic

GNU `find` uses a positional expression language where filters and
operators chain into an expression tree:

```bash
find . \( -name "*.log" -or -name "*.tmp" \) -and -not -newer ref
```

PowerShell parameters are key/value bindings and cannot express
operators between them. Find-Item provides three composable
mechanisms:

### 1. Array values = OR within one parameter

Pass multiple values to `-Name`, `-IName`, `-Regex`, `-IRegex`, `-Type`,
`-Exclude`, `-NotName`, `-NotIName`, `-NotRegex`, `-NotIRegex`,
`-Owner`, `-NotOwner`, or any `-*By` filter. Item matches if it
satisfies ANY listed value.

```powershell
Find-Item . -Name "*.log","*.tmp"        # OR within Name
Find-Item . -Type File,SymbolicLink      # OR within Type
```

### 2. Negation parameters = NOT

`-NotName` / `-NotIName` / `-NotRegex` / `-NotIRegex` / `-NotOwner`
reject any item matching their listed patterns. Combine with arrays
for "not in a set":

```powershell
Find-Item . -Type File -NotName "*.bak","*~",".gitkeep"
```

### 3. `-Filter` scriptblock = arbitrary boolean logic

For anything the structured parameters can't express:

```powershell
Find-Item . -Filter {
    ($_.Name -like "*.log" -or $_.Name -like "*.tmp") -and
    -not ($_.FullName -match '\\archive\\')
}
```

The scriptblock receives each candidate as `$_`, and you have the full
PowerShell expression language available.

### Equivalence table

| GNU find expression | Find-Item form |
|---|---|
| `-name "*.log" -o -name "*.tmp"` | `-Name "*.log","*.tmp"` |
| `-type f -and -name "*.log"` | `-Type File -Name "*.log"` |
| `-not -name "*.bak"` | `-NotName "*.bak"` |
| `\( A -or B \) -and -not C` | `-Filter { (A -or B) -and -not C }` |

Different parameters are still ANDed together — `-Name "x" -Type File`
means "matches `*x*` AND is a file". This matches GNU `find`'s default
(juxtaposition implies `-and`); it's only `-or` that needs explicit
syntax.

---

## Permission filter semantics

> **TL;DR:** Find-Item's permission filters check the **literal ACL**
> (does the DACL contain an Allow ACE granting this right to this
> principal?). They do NOT do a full Windows effective-access
> evaluation (no group expansion, no Deny-ACE precedence). For most
> security audits, literal-ACL is exactly what you want.

### Complete NTFS rights → filter mapping

Every `FileSystemRights` value mapped to the filter(s) that catch it.

#### Atomic rights (single-bit)

| Right | Hex bit | File/Dir name | Caught by |
|---|---|---|---|
| `ReadData` / `ListDirectory` | `0x1` | same | `-ReadableBy` |
| `WriteData` / `CreateFiles` | `0x2` | same | `-WritableBy` |
| `AppendData` / `CreateDirectories` | `0x4` | same | `-AppendableBy`, `-WritableBy` (dirs) |
| `ReadExtendedAttributes` | `0x8` | (same name) | `-ReadableBy` |
| `WriteExtendedAttributes` | `0x10` | (same name) | `-WritableBy` |
| `ExecuteFile` / `Traverse` | `0x20` | same | `-ExecutableBy` |
| `DeleteSubdirectoriesAndFiles` | `0x40` | dir-only | `-WritableBy` (dirs) |
| `ReadAttributes` | `0x80` | (same name) | `-ReadableBy` |
| `WriteAttributes` | `0x100` | (same name) | `-WritableBy` |
| `Delete` | `0x10000` | (same name) | `-WritableBy` |
| `ReadPermissions` | `0x20000` | (same name) | ❌ no filter — too widely granted |
| `ChangePermissions` | `0x40000` | (same name) | ❌ only `-FullControlBy` |
| `TakeOwnership` | `0x80000` | (same name) | ❌ only `-FullControlBy` |
| `Synchronize` | `0x100000` | (same name) | ❌ infrastructure right |

#### Composite rights (multi-bit aggregates)

| Right | Composition | Caught by |
|---|---|---|
| `Read` | `ReadData` + `ReadEA` + `ReadAttrs` + `ReadPerms` | `-ReadableBy` |
| `ReadAndExecute` | `Read` + `ExecuteFile` | `-ReadableBy` + `-ExecutableBy` |
| `Write` | `WriteData` + `AppendData` + `WriteEA` + `WriteAttrs` | `-WritableBy` + `-AppendableBy` |
| `Modify` | `ReadAndExecute` + `Write` + `Delete` | all 4 capability filters + `-ModifiableBy` |
| `FullControl` | `Modify` + `DeleteSubdirs` + `ChangePerms` + `TakeOwnership` + `Synchronize` | all 6 filters incl. `-FullControlBy` |

### File vs directory bit meanings

NTFS rights are stored as bit values; the same bit has different names
depending on whether the item is a file or a directory. Find-Item
applies the type-appropriate meaning of each bit:

| Bit value | File name | Directory name |
|---|---|---|
| `1` | `ReadData` | `ListDirectory` |
| `2` | `WriteData` | `CreateFiles` |
| `4` | `AppendData` | `CreateDirectories` |
| `32` | `ExecuteFile` | `Traverse` |
| `64` | (n/a) | `DeleteSubdirectoriesAndFiles` |

For directories, `-WritableBy` expands to ANY of `CreateFiles`,
`CreateDirectories`, or `DeleteSubdirectoriesAndFiles` — because a
principal that can do any of those can change the directory's contents
in some way.

### Composite-rights matching (`-ModifiableBy`, `-FullControlBy`)

These filters use **all-bits** matching rather than any-bit: the ACE
must grant every constituent bit of the composite right. This is
required because composites like `Modify` are unions:

- `Modify = ReadAndExecute | Write | Delete` (plus attrs/perms/sync)
- `FullControl = all rights` including `ChangePermissions`, `TakeOwnership`

Any-bit matching on `Modify` would return true for any ACE granting
even just `Read` (since `Read`'s bits are a subset of `Modify`'s),
making the filter useless. All-bits matching correctly answers "is the
principal at least at the Modify level on this item?"

### Workaround for the unmapped administrative rights

To find files where a specific principal has `ChangePermissions` or
`TakeOwnership` granted (without requiring `FullControl`):

```powershell
$rights = [System.Security.AccessControl.FileSystemRights]
Find-Item C:\App -Type File -Filter {
    ($_ | Get-Acl).Access | Where-Object {
        $_.AccessControlType -eq 'Allow' -and
        $_.IdentityReference -ilike 'Everyone' -and
        ($_.FileSystemRights -band $rights::ChangePermissions)
    }
}
```

This bypasses the function's ACL cache; it's fine for one-off audits
but slower on large trees.

### Literal-ACL vs effective-access

The filters check ACE contents directly. They do NOT replicate the
full Windows access-check evaluation, which would require:

- Expanding group memberships transitively
- Applying Deny ACEs with their precedence rules
- Honoring inheritance order, integrity levels, mandatory access

Doing that properly requires `AuthzAccessCheck` /
`GetEffectiveRightsFromAcl`, which is well beyond the scope of a
single-file utility. The literal-ACL check is exactly what security
audits want ("find every file whose ACL grants Write to Everyone") but
is NOT a guarantee that the named principal can effectively perform
the action on the file.

For authoritative answers on a specific finding, run `icacls <file>`
or call `AuthzAccessCheck` directly.

---

## Security considerations

This is an interactive tool; the user invoking it runs with their own
privileges and sees their own data. The notes below matter mainly to
**automation / service callers** that wrap Find-Item and expose it to
less-privileged input.

### 1. `-Filter` accepts arbitrary PowerShell code

The scriptblock is executed with the caller's full privileges and can
do anything — write files, make network calls, delete data, etc.
Find-Item is safe as long as the scriptblock comes from the caller
themselves; it is **UNSAFE** if a caller does something like:

```powershell
# DANGEROUS - equivalent to Invoke-Expression on $userInput
Find-Item . -Filter ([scriptblock]::Create($userInput))
```

Never build `-Filter` from untrusted input. Use the structured
parameters (`-Name`, `-Regex`, `-Size`, `-Type`, etc.) instead.

### 2. `-Delete` is recursive on matched directories

A matched directory's ENTIRE subtree is deleted, even files that
didn't match the filter. Always run broad `-Delete` queries with
`-WhatIf` first.

### 3. Reparse points (junctions, symbolic links) are never followed by `-Delete`

The function uses `[System.IO.Directory]::Delete(path, recursive=$false)`
rather than `Remove-Item -Recurse` when the matched item is a reparse
point. This avoids the well-known PS 5.1 / 7.0 bug where
`Remove-Item -Recurse` on a junction destroys the link target's
contents.

For traversal, reparse points are skipped by default. Use
`-FollowSymlinks` to descend into them, with the understanding that
doing so may cross into directories outside the intended scope (and
may loop on circular links).

### 4. Regex patterns have a 5-second match timeout

`-Regex` / `-IRegex` / `-NotRegex` / `-NotIRegex` patterns are
compiled once with a 5s per-match timeout, so a pathological pattern
(e.g. `(a+)+$` against long input — "ReDoS") cannot hang the
traversal. A timed-out match is reported via `Write-Warning`, skipped
for that item, and the walk continues.

### 5. `-ShowOwner` bulk-exposes identity metadata

The `Owner` column contains identity information (`DOMAIN\username`,
`BUILTIN\group`, etc.) for every file. Avoid logging `-ShowOwner`
output to locations readable by lower-privileged principals — it
amounts to bulk metadata disclosure across whatever subtree was
searched.

ACL-read failures are silently rendered as `'?'` (not as an error) so
a single inaccessible file won't abort the run; this also means the
column does not distinguish "no owner" from "permission denied".

### 6. Path arguments are not sandboxed

Find-Item operates wherever `-Path` points. If you build a caller
that accepts a path from untrusted input, validate and canonicalize
the path **before** passing it — Find-Item does not and cannot
enforce a "stay within X" boundary on the caller's behalf.

---

## Performance and memory

### Per-mode characteristics

| Mode | Memory | Notes |
|---|---|---|
| Default output | **O(1)** | Streams items as the tree is walked |
| `-FullPath` | **O(1)** | Same as default |
| `-LongList` | **O(1)** | Same as default |
| `-Summary` / `-SummaryOnly` | **O(1)** | Just counters |
| `-DirectoryTotals` | **O(depth)** | Accumulator per recursion level |
| `-First N` (no `-SortBy`) | **O(1)** | Early-termination, recursion unwinds at item N |
| `-Last N` (no `-SortBy`) | **O(N)** | Sliding-window queue of fixed size |
| `-SortBy` | **O(matches)** | Buffer required for sort |
| `-SortBy + -First N` / `-Last N` | O(matches) buffer, O(N) result | Convenient but still buffers |

When `-SortBy` is in effect, a warning fires once the buffer crosses
`-MaxBufferItems` (default `100000`) so you find out before memory
becomes a problem. Set `-MaxBufferItems 0` to silence.

### Strategies for huge trees

Three options when `-SortBy` on millions of files isn't feasible:

1. **Filter first.** The cheapest fix — `-Name`, `-Size`, `-Type`,
   `-Filter` all reduce what reaches the sort buffer. A targeted
   query with `-SortBy` is usually fine.

2. **PowerShell 7+: pipe to `Sort-Object -Top N`.** PS7 added `-Top`
   to `Sort-Object`, which maintains only N items in memory via heap
   selection as items stream through. End-to-end memory is O(N):

   ```powershell
   # PowerShell 7+ only:
   Find-Item C:\Users -Type File |
       Sort-Object -Property Length -Top 10 -Descending
   ```

   You give up `-DirectoryTotals` / `-SizeUnit` / `-LongList`
   formatting (apply those manually after).

3. **Windows PowerShell 5.1: no streaming partial sort.** `Sort-Object`
   always buffers in 5.1. Filter aggressively (option 1), accept the
   memory cost, or upgrade to PowerShell 7+.

### ACL operations dominate when used

`Get-Acl` is roughly 50–200 ms per file. Any feature that needs ACL
info (`-ShowOwner`, `-SortBy Owner`, `-Owner`, `-NotOwner`,
`-ReadableBy`, `-WritableBy`, etc.) pays this cost. **The
per-invocation ACL cache** means combining e.g. `-ShowOwner` with
`-SortBy Owner` with `-WritableBy` only pays once per item, not three
times.

For 1M items in plain walk mode: ~200 seconds. With ACL fetches per
item: 10+ minutes. Use `-First N` or aggressive filtering for
interactive responsiveness on large trees.

### Performance improvements landed

1. `EnumerateFileSystemInfos` (lazy enumeration; better memory profile
   on huge directories)
2. `switch`-with-scriptblock-conditions → `if`/`elseif` chain for Type
   check (faster on hot path)
3. Deferred `$childRef` hashtable allocation (only when actually
   recursing)
4. Regex patterns pre-compiled with timeout (one compile per
   invocation, not per item)
5. ACL cache shared across all ACL-touching features
6. Early-termination flag propagates upward through nested `Traverse`
   calls for `-First N`

---

## Architecture

### File layout

```
PowerShell Utilities/
├── Find-Item.ps1               # The function (single file)
├── Find-Item.format.ps1xml     # Table-rendering views (PSCustomObject types)
├── docs/
│   └── Find-Item.md            # This document
└── tests/                      # Pester v5 test suite
    ├── Find-Item.*.Tests.ps1   # Per-feature test files
    ├── Helpers/
    │   └── TestHelpers.psm1    # Shared fixture builders
    ├── PesterConfiguration.ps1
    ├── Invoke-Tests.ps1        # Convenience runner
    └── README.md               # Test plan + coverage matrix
```

### Function structure

`Find-Item` uses an advanced-function pattern with explicit
`begin`/`process`/`end` blocks to support pipeline input on `-Path`:

```
function Find-Item {
    [CmdletBinding(SupportsShouldProcess)]
    param( ... )

    begin {
        # Initialise the piped-paths collector
    }

    process {
        # Accumulate paths from each pipeline invocation
    }

    end {
        # All the real work happens here:
        #   - validation + pre-parse filter specs
        #   - nested helper functions (TestItem, Traverse, Emit, ...)
        #   - per-invocation state (ACL cache, tally, sort buffer)
        #   - the foreach-path loop
        #   - sort flush + summary emission
    }
}
```

Inside `end`, the function defines a set of nested helpers and runs a
recursive `Traverse` over each starting path:

| Helper | Purpose |
|---|---|
| `ParseTimeSpec` | Parse `[+/-]<n>[m/h/d/w]` or absolute date strings |
| `TestTimeSpec` | Evaluate a time spec against a `DateTime` |
| `IsReparsePoint` | Single-bit check on `Attributes` |
| `GetCachedAcl` | Per-invocation `Get-Acl` cache |
| `HasExecutableExtension` | PATHEXT check for `-ExecutableBy` files |
| `TestAclAccess` | Generic principal+rights check against a DACL |
| `MatchAnyRegex` | Pre-compiled regex matcher with timeout handling |
| `FormatSize` | Bytes → formatted string per `-SizeUnit` |
| `FormatOutput` | Wraps an item in default / FullPath / LongList shape |
| `TestItem` | Apply all filters; return pass/fail |
| `Traverse` | Recursive walker |
| `Emit` | Stream OR buffer (sort) OR sliding window (Last) |
| `BumpEmitCount` | Track emissions for `-First N` early-termination |
| `TallyItem` | Update summary counters |
| `SafeDelete` | Reparse-point-safe deletion |
| `GetSortKey` | Extract the sort comparison value per `-SortBy` |

### Per-invocation state

| Variable | Purpose |
|---|---|
| `$aclCache` | Hashtable, full-path → `FileSecurity` (or `$null` on error) |
| `$tally` | Hashtable of running counters (ItemCount, FileCount, etc.) |
| `$emitBuffer` | `List<hashtable>` when `-SortBy`; otherwise `$null` |
| `$lastQueue` | `Queue<hashtable>` when `-Last N` and no `-SortBy` |
| `$emitState` | `{ EmittedCount; StopWalk; WarnedBuffer }` |
| `$compiledRegex`/etc. | Pre-compiled `Regex` instances (one set per invocation) |
| `$parsedSize`/`$parsedLastWrite`/etc. | Pre-parsed filter specs |

### Traversal model

`Traverse` is a recursive function with an explicit early-termination
flag. Two ordering modes:

- **Pre-order** (default): emit each item BEFORE recursing into it.
  Files emit immediately as they're encountered.
- **Post-order** (when `-DirectoryTotals` is set, for directories
  only): recurse first to compute the directory's byte total, then
  emit the directory with its `Length` column populated.

Files always emit in pre-order; the post-order branch applies only to
directories under `-DirectoryTotals`. The traversal-state byte counter
is returned via a hashtable `[ref]`-like wrapper to avoid commingling
with pipeline output.

---

## Testing

The function ships with a comprehensive Pester v5 test suite.

### Install Pester

```powershell
Install-Module Pester -MinimumVersion 5.0.0 -Force -SkipPublisherCheck
```

### Run all tests

```powershell
cd tests
.\Invoke-Tests.ps1
```

### Run a specific feature area

```powershell
.\Invoke-Tests.ps1 -Tag Permissions
.\Invoke-Tests.ps1 -File Find-Item.Permissions.Tests.ps1
```

### Skip slow performance tests

```powershell
.\Invoke-Tests.ps1 -ExcludeTag Performance
```

### With code coverage

```powershell
.\Invoke-Tests.ps1 -CodeCoverage
```

### Test inventory

| File | Tests | Coverage |
|---|---|---|
| `Find-Item.Parameters.Tests.ps1` | 31 | Parameter binding, validation, aliases, mutual exclusion, defaults, implicit-enable rules |
| `Find-Item.Filters.Tests.ps1` | 44 | `-Name`, `-IName`, `-Regex`, `-IRegex`, `-Type`, `-Size`, time filters, `-Newer`, `-Filter`, `-Exclude`, negation siblings |
| `Find-Item.Traversal.Tests.ps1` | 22 | `-Path`, `-MaxDepth`, `-MinDepth`, `-FollowSymlinks`, root-item handling, multi-path |
| `Find-Item.Output.Tests.ps1` | 27 | Default `FileInfo`, `-FullPath`, `-LongList`, `-ShowOwner`, `-SizeUnit` |
| `Find-Item.Sorting.Tests.ps1` | 20 | `-SortBy` (all columns), `-SortOrder` (long/short), `-First`, `-Last`, buffer warning |
| `Find-Item.Aggregation.Tests.ps1` | 20 | `-Summary`, `-SummaryOnly`, `-DirectoryTotals`, du-style semantics |
| `Find-Item.Permissions.Tests.ps1` | 35 | All 15 `FileSystemRights` values → 6 filters, file/dir masks, composite cascade, principal wildcards, ACL cache |
| `Find-Item.Delete.Tests.ps1` | 12 | Basic delete, WhatIf, **CRITICAL: junction-target-preservation** |
| `Find-Item.Security.Tests.ps1` | 8 | ReDoS timeout, format-file warning, mutex errors |
| `Find-Item.Integration.Tests.ps1` | 10 | End-to-end scenarios + direct invocation + Get-Help |
| `Find-Item.NewFeatures.Tests.ps1` | 37 | `-Empty`, `-PassThru`, `-Owner`/`-NotOwner`, time-suffix units, ValueFromPipeline |
| `Find-Item.Performance.Tests.ps1` | 17 | Benchmarks with regression thresholds |

**Current status:** **286 / 286 passing** as of the most recent run.

---

## Roadmap

Features deliberately **not** implemented and the reasoning:

| Feature | Why skipped |
|---|---|
| `-exec` / `-execdir` | Pipeline composition (`\| ForEach-Object`) is the safer PS idiom; explicit `-exec` would be an injection vector if callers ever built it from input |
| `-printf` / `-fprintf` | PowerShell uses `Select-Object` and `Format-Table`; different idiom is the right one |
| Effective access check (`-readable` style) | Requires `AuthzAccessCheck` P/Invoke; out of scope for a single-file utility |
| `-mount` / `-xdev` | Doable via volume-serial check; rarely needed on Windows; adds complexity |
| `-lname` / `-ilname` | Symlink target matching; niche on Windows |
| `-anewer` / `-cnewer` | Easy symmetry add if requested |
| Argument completer for principals | Polish; would tab-complete `'Eve...'` to `'Everyone'` |
| Parallel traversal (`ForEach-Object -Parallel`) | Major architectural change for marginal benefit on typical I/O-bound workloads; PS 7+ only |

---

## Parameter index

Alphabetical quick-reference. Click each to jump to the detailed
description.

| Parameter | Type | Default | Group |
|---|---|---|---|
| `-AllocatedSize` | switch | — | [Apparent vs allocated](#apparent-vs-allocated-size) |
| `-AppendableBy` | `String[]` | — | [ACL access](#acl-access-filters) |
| `-ATime` | `String` (alias for `-LastAccessTime`) | — | [Time](#time-filters) |
| `-BTime` | `String` (alias for `-CreationTime`) | — | [Time](#time-filters) |
| `-Confirm` | switch | — | [Modifier](#behavior-modifiers) |
| `-CreationTime` | `String` | — | [Time](#time-filters) |
| `-CTime` | `String` (alias for `-CreationTime`) | — | [Time](#time-filters) |
| `-Delete` | switch | — | [Action](#actions) |
| `-DirectoryTotals` (alias `-DirTotals`) | switch | — | [Aggregation](#aggregation) |
| `-Empty` | switch | — | [Size and Empty](#size-and-empty) |
| `-Exclude` | `String[]` | — | [Traversal](#path-and-traversal) |
| `-ExecutableBy` | `String[]` | — | [ACL access](#acl-access-filters) |
| `-Filter` | `ScriptBlock` | — | [Custom predicate](#custom-predicate) |
| `-First` | `Int32` | `0` | [Limit](#sorting-and-limiting) |
| `-FollowSymlinks` | switch | — | [Traversal](#path-and-traversal) |
| `-FullControlBy` | `String[]` | — | [ACL access](#acl-access-filters) |
| `-FullPath` | switch | — | [Output](#output-formatting) |
| `-IName` | `String[]` | — | [Name](#name-and-path-filters) |
| `-IncludeStreams` | switch | — | [Apparent vs allocated](#apparent-vs-allocated-size) |
| `-IRegex` | `String[]` | — | [Name](#name-and-path-filters) |
| `-Last` | `Int32` | `0` | [Limit](#sorting-and-limiting) |
| `-LastAccessTime` | `String` | — | [Time](#time-filters) |
| `-LastWriteTime` | `String` | — | [Time](#time-filters) |
| `-LongList` (alias `-Ls`) | switch | — | [Output](#output-formatting) |
| `-MaxBufferItems` | `Int32` | `100000` | [Limit](#sorting-and-limiting) |
| `-MaxDepth` | `Int32` | `[int]::MaxValue` | [Traversal](#path-and-traversal) |
| `-MinDepth` | `Int32` | `0` | [Traversal](#path-and-traversal) |
| `-ModifiableBy` | `String[]` | — | [ACL access](#acl-access-filters) |
| `-MTime` | `String` (alias for `-LastWriteTime`) | — | [Time](#time-filters) |
| `-Name` | `String[]` | — | [Name](#name-and-path-filters) |
| `-Newer` | `String` | — | [Reference](#reference-file-filter) |
| `-NotIName` | `String[]` | — | [Negation](#negation-filters) |
| `-NotIRegex` | `String[]` | — | [Negation](#negation-filters) |
| `-NotName` | `String[]` | — | [Negation](#negation-filters) |
| `-NotOwner` | `String[]` | — | [Owner](#owner-filters) |
| `-NotRegex` | `String[]` | — | [Negation](#negation-filters) |
| `-Owner` | `String[]` | — | [Owner](#owner-filters) |
| `-PassThru` | switch | — | [Action](#actions) |
| `-Path` | `String[]` | `.` | [Traversal](#path-and-traversal) |
| `-ReadableBy` | `String[]` | — | [ACL access](#acl-access-filters) |
| `-Regex` | `String[]` | — | [Name](#name-and-path-filters) |
| `-ShowOwner` | switch | — | [Output](#output-formatting) |
| `-Size` | `String` | — | [Size](#size-and-empty) |
| `-SizeUnit` | `String` | `Bytes` | [Output](#output-formatting) |
| `-SortBy` | `String` | — | [Sort](#sorting-and-limiting) |
| `-SortOrder` | `String` | `Ascending` | [Sort](#sorting-and-limiting) |
| `-Summary` | switch | — | [Aggregation](#aggregation) |
| `-SummaryOnly` | switch | — | [Aggregation](#aggregation) |
| `-Type` | `String[]` | — | [Type](#type-filter) |
| `-WhatIf` | switch | — | [Modifier](#behavior-modifiers) |
| `-WritableBy` | `String[]` | — | [ACL access](#acl-access-filters) |

---

## See also

- [`Get-Help Find-Item -Full`](../Find-Item.ps1) — comment-based help
  with every parameter and example
- [`tests/README.md`](../tests/README.md) — test plan and coverage matrix
- [GNU findutils](https://www.gnu.org/software/findutils/) — the
  reference implementation Find-Item maps to
