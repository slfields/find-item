# Register Win32 native bindings used by -AllocatedSize. These are needed
# to report on-disk allocation (instead of logical content size) for files
# whose physical storage differs from their apparent size: sparse files,
# NTFS-compressed files, resident-in-MFT files, deduplicated files, and
# files with alternate data streams.
#
#   GetCompressedFileSize   - main-stream allocated bytes (handles
#                             compression, sparse, dedup correctly)
#   GetDiskFreeSpace        - per-volume cluster size, used to floor
#                             non-empty resident files
#   FindFirstStreamW etc.   - enumerate alternate data streams when
#                             -IncludeStreams is set
#
# Guard against double-registration when the script is re-dot-sourced.
if (-not ('FindItem.Native' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

namespace FindItem {
    public static class Native {
        public const int FindStreamInfoStandard = 0;
        public static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
        public const uint INVALID_FILE_SIZE = 0xFFFFFFFF;

        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
        public static extern uint GetCompressedFileSize(
            string lpFileName, out uint lpFileSizeHigh);

        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetDiskFreeSpace(
            string lpRootPathName,
            out uint lpSectorsPerCluster,
            out uint lpBytesPerSector,
            out uint lpNumberOfFreeClusters,
            out uint lpTotalNumberOfClusters);

        [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
        public struct WIN32_FIND_STREAM_DATA {
            public long StreamSize;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst=296)]
            public string StreamName;
        }

        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
        public static extern IntPtr FindFirstStreamW(
            string lpFileName, int InfoLevel,
            out WIN32_FIND_STREAM_DATA lpFindStreamData, uint dwFlags);

        [DllImport("kernel32.dll", SetLastError=true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool FindNextStreamW(
            IntPtr hFindStream, out WIN32_FIND_STREAM_DATA lpFindStreamData);

        [DllImport("kernel32.dll", SetLastError=true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool FindClose(IntPtr hFindFile);
    }
}
'@ -ErrorAction SilentlyContinue
}

# Register the companion format file so -LongList output always renders as a
# table (otherwise PowerShell's default formatter switches to list view at 5+
# properties, which makes -ShowOwner unreadable). Safe to call repeatedly;
# format-data registration is idempotent.
#
# Failures are surfaced as warnings (not silently swallowed) so genuine
# corruption / tampering of the format file is visible to the user.
$script:_FindItemFormatPath = Join-Path $PSScriptRoot 'Find-Item.format.ps1xml'
if (Test-Path -LiteralPath $script:_FindItemFormatPath) {
    try {
        Update-FormatData -PrependPath $script:_FindItemFormatPath -ErrorAction Stop
    }
    catch {
        Write-Warning ("Find-Item: failed to load format file '{0}': {1} " +
            "Long-list output will fall back to PowerShell's default " +
            "formatter (list view at 5+ columns)." -f
            $script:_FindItemFormatPath, $_.Exception.Message)
    }
}

function Find-Item {
    <#
    .SYNOPSIS
        Searches for files and directories matching specified criteria.

    .DESCRIPTION
        A PowerShell-native equivalent of GNU findutils 'find'. Outputs
        FileInfo/DirectoryInfo objects so results pipeline naturally into
        Sort-Object, Remove-Item, Select-Object, etc.

        All filter parameters are ANDed together. For complex logic (OR, NOT),
        pipe the output into Where-Object.

    .PARAMETER Path
        One or more starting paths. Defaults to the current directory.

        Accepts pipeline input by VALUE (`'path1','path2' | Find-Item`) and
        by PROPERTY NAME via the FullName / PSPath aliases, so any cmdlet
        that emits FileSystemInfo / PSProvider items can pipe directly:

          Get-ChildItem C:\Repos -Directory | Find-Item -Type File -Name *.log
          Get-Content paths.txt | Find-Item -Type File

        When piped, all pipeline items are collected before the search
        begins (a single Find-Item invocation processes the full set).

    .PARAMETER Name
        One or more wildcard patterns matched against the item name. Pass an
        array for an implicit OR (item matches if it satisfies ANY pattern).
        Examples:
          -Name "*.log"
          -Name "*.log","*.tmp","*~"        # any of these extensions

    .PARAMETER IName
        Like -Name but explicitly case-insensitive. Same array semantics.

    .PARAMETER Regex
        One or more regular expressions matched against the item's full path.
        Case-insensitive by default (PowerShell convention); use inline (?-i)
        for case-sensitive matching. Array = OR.

    .PARAMETER IRegex
        Same as -Regex but explicitly case-insensitive.

    .PARAMETER NotName
        One or more wildcard patterns; item is REJECTED if it matches ANY of
        them. Equivalent to GNU find's '-not -name PAT' with implicit OR.
        Example: -Type File -NotName "*.bak","*~"   (files except backups)

    .PARAMETER NotIName
        Like -NotName but explicitly case-insensitive.

    .PARAMETER NotRegex
        One or more regular expressions; item is REJECTED if any matches its
        full path.

    .PARAMETER NotIRegex
        Like -NotRegex but explicitly case-insensitive.

    .PARAMETER Type
        Filter by item type. Pass an array for an implicit OR (item matches
        if it is ANY of the listed types).
          f / File          - regular files (not symlinks or junctions)
          d / Directory     - regular directories (not symlinks or junctions)
          l / SymbolicLink  - any reparse point (symlink, junction, mount point)
        Examples:
          -Type File
          -Type File,SymbolicLink           # files OR symlinks

    .PARAMETER ReadableBy
        Match items whose NTFS DACL grants ANY form of read access to ANY
        listed principal via an Allow ACE. Array = OR (passes if any
        pattern hits).

        Principals are matched with -like wildcards against the ACE's
        IdentityReference value, e.g.:
          -ReadableBy 'Everyone'
          -ReadableBy 'BUILTIN\Administrators','BUILTIN\Users'
          -ReadableBy 'CORP\*'           # any user/group in CORP domain
          -ReadableBy '*\alice'          # alice in any domain
          -ReadableBy "$env:USERDOMAIN\$env:USERNAME"   # current user

        "Read access" is satisfied by an ACE whose FileSystemRights include
        ANY of:
            ReadData / ListDirectory       (read file content / list dir)
            ReadAttributes                 (see Hidden, Read-only, etc.)
            ReadExtendedAttributes         (see EAs)
        All higher composites (Read, ReadAndExecute, Modify, FullControl)
        include ReadData, so they cascade automatically.

        ReadPermissions (read the ACL itself) is NOT considered for this
        filter - it's granted to virtually every principal by default and
        including it would make the filter match almost everything. To
        audit ReadPermissions specifically, use a -Filter scriptblock.

        LITERAL-ACL semantics: this filter checks ACE contents directly;
        it does NOT perform a full Windows effective-access evaluation
        (no group-membership expansion, no Deny-ACE precedence walk).
        See NOTES > PERMISSION-FILTER SEMANTICS.

    .PARAMETER WritableBy
        Match items whose DACL grants ANY form of write or destructive
        access to ANY listed principal. Same principal-matching as
        -ReadableBy.

        "Write access" is satisfied by an ACE whose FileSystemRights include
        ANY of:
          Files       : WriteData | WriteAttributes |
                        WriteExtendedAttributes | Delete
          Directories : CreateFiles | CreateDirectories |
                        DeleteSubdirectoriesAndFiles | WriteAttributes |
                        WriteExtendedAttributes | Delete

        i.e. anything that can alter or destroy the item's data, metadata,
        or existence. All higher composites (Write, Modify, FullControl)
        include these bits and cascade automatically.

        Delete is included because deletion is destructive write - a
        principal with Delete-only on a file can destroy it even without
        being able to modify its content. The audit answer for "who can
        damage this thing" should catch them.

        ChangePermissions and TakeOwnership are NOT considered for this
        filter - they're administrative privilege-escalation rights, not
        write-class operations. Only -FullControlBy catches a principal
        granted those specifically. See NOTES > NTFS RIGHTS MAPPED TO
        FILTERS for the full inventory.

        Common security audit:
          Find-Item C:\Shared -WritableBy 'Everyone','BUILTIN\Users'
          # The classic 'world-writable' query.

    .PARAMETER AppendableBy
        Match items whose DACL grants Append-only access to ANY listed
        principal. Distinct from -WritableBy: AppendData allows adding
        to the END only.

          Files       : matches AppendData (append to end of file).
          Directories : matches CreateDirectories (same bit value;
                        create subdirectories).

        Commonly granted on log files for least-privilege writers.

    .PARAMETER ExecutableBy
        Match items whose DACL grants execute-class access to ANY listed
        principal. Semantics differ by type:

          Files       : two-part check - extension must be in the Windows
                        shell's executable list (the contents of
                        $env:PATHEXT, plus .PS1 / .PSM1 / .PSD1) AND DACL
                        must grant ExecuteFile.
          Directories : DACL grants Traverse (same bit value; allows
                        cd-ing into the directory). No extension check.

    .PARAMETER ModifiableBy
        Match items where ANY listed principal has the COMPOSITE 'Modify'
        right granted via an Allow ACE - meaning the ACE includes every
        bit of Modify (ReadAndExecute + Write + Delete + Read attributes/
        permissions). Equivalent to "principal can read, edit, and delete
        this item, but cannot change its ACL or take ownership."

        This is the most realistic 'effective edit access' check the
        function offers. A principal with only Write but not Delete (or
        vice versa) will NOT match - they're missing required bits.

        Stronger than -WritableBy: WritableBy matches any ACE granting
        the WriteData bit (even just append). ModifiableBy requires the
        full Modify composite.

    .PARAMETER FullControlBy
        Match items where ANY listed principal has the COMPOSITE
        'FullControl' right granted via an Allow ACE - meaning the ACE
        includes every bit of FullControl, which is everything: read,
        write, delete, change permissions, take ownership.

        The strictest of the access filters. Use to find files with
        over-permissive ACLs, e.g.:
          Find-Item C:\App -FullControlBy 'Everyone','BUILTIN\Users'
          # World-FullControl - typically a misconfiguration.

    .PARAMETER Filter
        A scriptblock that runs against each candidate item. Receives the
        item as $_ (Where-Object convention). Truthy result = item passes.
        Use this for arbitrary boolean logic that the structured parameters
        can't express; the full PowerShell expression language is available.

        Runs AFTER all built-in tests, so cheap filters (Name, Type, Size,
        etc.) short-circuit first - the scriptblock only sees items that
        already passed everything else.

        Unlike piping to Where-Object after the fact, -Filter runs DURING
        traversal: the test fires against each candidate item and is part
        of TestItem, so it composes naturally with pruning, depth limits,
        and -Delete.

        Examples:
          -Filter { $_.Name -like "*.log" -or $_.Name -like "*.tmp" }
          -Filter { $_.Length -gt 1MB -and $_.Extension -in '.log','.txt' }
          -Filter { $_.LastWriteTime.DayOfWeek -eq 'Sunday' }

    .PARAMETER Empty
        Match items that are empty:
          Files       : Length is exactly 0 bytes.
          Directories : enumerate yields zero entries.

        For directories the check short-circuits on the first child entry,
        so it does NOT materialise the full child list (memory-friendly
        even on directories with millions of items, in the sense that the
        check itself is O(1) - though listing such a directory still costs
        an OS round-trip).

        Equivalent to GNU find's '-empty'.

        IMPORTANT: -Empty is INDEPENDENT of -AllocatedSize. It always tests
        the LOGICAL file Length (the natural meaning of "empty file" - the
        file has no content to read). This matches GNU find -empty parity
        and avoids the footgun of sparse / NTFS-compressed-to-nothing files
        looking "empty" by allocation but actually carrying logical content
        the application depends on (think VM disk images, preallocated logs,
        mail spool files - none of these are empty in any meaningful sense).
        To find files using zero disk space, use -AllocatedSize -Size 0c
        instead. See .NOTES > APPARENT SIZE vs ALLOCATED SIZE.

    .PARAMETER Size
        Filter files by size. By default filters against the LOGICAL
        (apparent) file length; pass -AllocatedSize to filter against
        on-disk allocation instead (cluster-rounded, sparse/compressed-
        aware). See .NOTES > APPARENT SIZE vs ALLOCATED SIZE.

        Format: [+|-]<n>[c|k|M|G]
          Prefix: + larger than, - smaller than, (none) exactly
          Suffix: c bytes, k kibibytes (1024), M mebibytes, G gibibytes,
                  (none) 512-byte blocks (GNU find default)
        Examples: +10M  -1k  512c

        NOTE: On Windows, directories and reparse points have no meaningful
        Length, so specifying -Size implicitly excludes them - only files
        can match. (This differs from Linux find, where directories have
        a Length representing their entry-list size and can match -size.)

    .PARAMETER LastWriteTime
        Filter by the file's content modification time (the time NTFS records
        when the file's data was last written). Windows-native name; aliased
        as -MTime for Linux find compatibility (same meaning on both OSes).

        Accepts three input forms (with an optional leading + or - sign):

          NUMERIC + UNIT        [+|-]<n>[m|h|d|w]
            +7    OR  +7d       older than 7 days
            -7    OR  -7d       newer than 7 days
             7                  between 7 and 8 days ago
            -5m                 last 5 minutes
            -2h                 last 2 hours
            -2w                 last 2 weeks
            +30m                more than 30 minutes ago
          A bare number (no suffix) is days for GNU find parity. Suffixes
          map to: m=minutes, h=hours, d=days, w=weeks (no months/years -
          those would have ambiguous lengths).

          CALENDAR DATE         [+|-]<date>
            "2026-01-15"        modified on that calendar day (any time)
            "+2026-01-15"       modified after 2026-01-15 00:00:00
            "-2026-01-15"       modified before 2026-01-15 00:00:00
            Any culture-recognised date string works: 2026-01-15,
            01/15/2026, "Jan 15 2026", etc.

          DATE-TIME             [+|-]<date-time>
            "2026-01-15 14:30:00"   modified within that exact second
            "+2026-01-15T14:30"     modified after that instant
            "-2026-01-15 14:30:00"  modified before that instant
            ISO-8601 ('T' separator) or "date space time" both accepted.

        SIGN SEMANTICS GOTCHA: for numeric input the sign refers to AGE
        (-7 means "age less than 7 days" = newer); for absolute dates the
        sign refers to the TIMESTAMP itself (-<date> means "timestamp less
        than date" = older). The mathematical meaning (< or >) is the
        same; the plain-English meaning flips because age and timestamp
        run in opposite directions.

    .PARAMETER LastAccessTime
        Filter by the file's last-access time. Windows-native name; aliased
        as -ATime for Linux find compatibility (same meaning on both OSes).
        Same input formats as -LastWriteTime.

        IMPORTANT (Windows): Since Windows Vista, NTFS last-access-time
        updates are disabled by default for performance reasons. Run
        'fsutil behavior query DisableLastAccess' to check the current
        setting. Unless updates are enabled, this timestamp will be stale
        or equal to CreationTime, and -LastAccessTime / -ATime filtering
        will return misleading results.

    .PARAMETER CreationTime
        Filter by the time the file was first created at its current
        location. Windows-native name. Same input formats as -LastWriteTime.

        Aliased as:
          -BTime  (matches Linux find's "birth time" - same meaning)
          -CTime  (kept for GNU find muscle memory, but BEWARE: on Linux,
                   -ctime means "inode metadata change time", NOT creation
                   time. The two are unrelated concepts. NTFS does track a
                   metadata-change time in the MFT, but it is not surfaced
                   by standard .NET / PowerShell APIs.)

    .PARAMETER Newer
        Match items whose modification time is strictly newer than the
        modification time of the file at this path.

    .PARAMETER MaxDepth
        Maximum depth to descend. 0 = starting path only (no children).

    .PARAMETER MinDepth
        Minimum depth before emitting results. 1 = skip the starting path
        itself.

    .PARAMETER Exclude
        One or more name patterns for directories to skip entirely (like
        -prune). Matched case-insensitively.
        Example: -Exclude ".git","node_modules","bin","obj"

    .PARAMETER Delete
        Delete matching items instead of emitting them. Supports -WhatIf
        and -Confirm. Combine with -PassThru to also emit each deleted
        item (useful for audit trails).

        SUBTREE DELETION: when a matched item is a directory, the ENTIRE
        SUBTREE under it is removed - including files that themselves
        wouldn't have matched the filter. Combined with broad filters this
        can be much more destructive than expected. Examples:

          Find-Item C:\Repos -Type Directory -Name "build" -Delete
          # Deletes every 'build' folder AND everything inside it,
          # regardless of file-level filters elsewhere.

        Always preview broad -Delete queries with -WhatIf first.

        REPARSE POINTS: junctions and symbolic links are deleted as link
        entries only - the link target is never followed. (Find-Item uses
        .NET Directory.Delete(path, recursive=$false) for reparse-point
        directories rather than Remove-Item -Recurse, which has historically
        followed links and destroyed target contents on Windows
        PowerShell 5.1.)

    .PARAMETER PassThru
        Standard PowerShell convention for destructive cmdlets: when
        combined with -Delete, also emit each item that was deleted (the
        same FileInfo / DirectoryInfo / LongList object that would have
        been emitted in non-delete mode). This makes Find-Item -Delete
        composable with the rest of the pipeline:

          Find-Item C:\Temp -Name "*.tmp" -Delete -PassThru |
              Export-Csv .\deleted-$(Get-Date -Format yyyyMMdd).csv -NoTypeInformation

        The emitted object references the now-deleted path - its in-memory
        properties (Name, FullName, Length, LastWriteTime, Mode) remain
        valid because they were captured before deletion. Without
        -PassThru, -Delete emits nothing (only the summary if -Summary).

    .PARAMETER Owner
        One or more wildcard patterns matched against each item's NTFS
        owner. The Windows-native analog of GNU find's -user. Patterns
        use -like semantics:
          -Owner 'BUILTIN\Administrators'
          -Owner '*\alice'
          -Owner 'CORP\*'
          -Owner "$env:USERDOMAIN\$env:USERNAME"   # files owned by me

        Array values are ORed (item passes if owner matches ANY listed
        pattern). Owner is read via Get-Acl, routed through the per-
        invocation ACL cache so combining -Owner with -ShowOwner,
        -SortBy Owner, or any -*By filter pays Get-Acl once per item.

    .PARAMETER NotOwner
        Mirror of -Owner: REJECT items whose owner matches ANY listed
        pattern. Useful for "everything not owned by the system":

          Find-Item C:\Apps -Type File -NotOwner 'NT AUTHORITY\SYSTEM','BUILTIN\Administrators','BUILTIN\TrustedInstaller'

    .PARAMETER FollowSymlinks
        Follow symbolic links and junctions when descending into directories
        (equivalent to find -L). Without this switch, reparse-point
        directories are not traversed.

    .PARAMETER FullPath
        Output full path strings instead of FileInfo/DirectoryInfo objects.
        Useful for display, logging, or passing paths to external tools.
        Without this switch, rich objects are returned so results pipeline
        naturally into Sort-Object, Where-Object, Remove-Item, etc.

        Mutually exclusive with -LongList.

    .PARAMETER LongList
        Windows-native equivalent of GNU find's '-ls' action. Outputs each
        result as a PSCustomObject with these columns, ready for the default
        table formatter:

          Mode           NTFS attribute summary (e.g. 'd-----', '-a----')
          Owner          (only when -ShowOwner is also specified; see below)
          Length         file size in bytes; blank for directories
          LastWriteTime  modification timestamp
          FullName       full path

        Aliased as -Ls for GNU find muscle memory. Mutually exclusive with
        -FullPath. Output is still piped as objects, so Sort-Object,
        Where-Object, Export-Csv, etc. all work on the result.

    .PARAMETER ShowOwner
        When combined with -LongList, adds an Owner column populated from
        each file's ACL. Implies -LongList if specified alone.

        WARNING: ACL lookup is roughly 50-200ms per file. For result sets
        of more than a few hundred items this is noticeably slow. Only use
        when you actually need ownership information.

        NOTE: This switch only changes OUTPUT (adds a column). To FILTER
        results by owner (analogous to GNU find's -user), a separate -Owner
        parameter is reserved for future use.

        SECURITY: the Owner column contains identity information
        (DOMAIN\username, BUILTIN\group, etc.) for every file. Avoid
        logging -ShowOwner output to locations readable by lower-privileged
        principals, since it amounts to bulk metadata disclosure across
        whatever subtree was searched. ACL-read failures are silently
        rendered as '?' (not as an error) so a single inaccessible file
        won't abort the run; this also means the column does not
        distinguish "no owner" from "permission denied".

    .PARAMETER SortBy
        Sort the output by one of the underlying FileSystemInfo properties.
        Sorting is type-aware: numeric columns compare numerically, dates
        chronologically, strings lexically - regardless of how the column
        is displayed. (For example, -SortBy Length always sorts by raw byte
        count, even with -SizeUnit Auto where the displayed value is the
        string "1.50 MiB".)

        Accepted columns:
          Name            file/dir name (string)
          FullName        full path (string)
          Length          file size in bytes; for directories with
                          -DirectoryTotals, the recursive byte total; else 0
          LastWriteTime   modification time (DateTime)
          CreationTime    creation time (DateTime)
          LastAccessTime  access time (DateTime)
          Extension       file extension including dot (string)
          Mode            attribute string like '-a----' or 'd-----' (string)
          Owner           NTFS owner from ACL (string) - SLOW: triggers a
                          per-item Get-Acl, and double-charges when combined
                          with -ShowOwner
          Type            'Directory', 'SymbolicLink', or 'File' (groups
                          like items together)

        Specifying -SortBy switches output from streaming to buffered: the
        entire result set is collected, sorted, then emitted. For very
        large trees this uses memory proportional to the match count. If
        you don't need a global sort, prefer leaving -SortBy unset and
        piping to Sort-Object yourself (which can also stream if your
        sort key allows).

    .PARAMETER SortOrder
        Direction for -SortBy. Has no effect when -SortBy is unset.
        Accepts both long and short forms:
          Ascending  / Asc   (default)
          Descending / Desc

    .PARAMETER First
        Cap the output to the first N items. Mutually exclusive with -Last.

        Without -SortBy: traversal stops as soon as N items have been
        emitted. The recursion unwinds early - no items beyond the cutoff
        are read from disk. Memory: O(1).

        With -SortBy: the entire matched set is still buffered for sorting,
        then truncated to N. The result is bounded but the buffer is not -
        see NOTES for the memory-bounded streaming alternative.

    .PARAMETER Last
        Mirror of -First: keep only the last N items.

        Without -SortBy: a fixed-size queue tracks the most recently emitted
        items as traversal proceeds. Items that fall out of the window are
        discarded immediately. Memory: O(N), independent of total matches.

        With -SortBy: same as -First but takes the last N from the sorted
        result.

    .PARAMETER MaxBufferItems
        Soft threshold (default 100,000) for emitting a warning when the
        -SortBy buffer grows large enough to be a memory concern. Set to 0
        to silence the warning. Has no effect unless -SortBy is also set.

    .PARAMETER DirectoryTotals
        Fills the Length column for directories with the recursive byte total
        of every file underneath them (regardless of file-level filters like
        -Name or -Size). Without this switch, directories show a blank
        Length. Implies -LongList. Aliased as -DirTotals.

        Also implicitly filters output to directories only (matching GNU du's
        default: 'du /path' shows directory totals; files require -a). To
        include files anyway, pass an explicit -Type:
          -DirectoryTotals -Type File       (files only - DirectoryTotals
                                             becomes a no-op)
          -DirectoryTotals -Type SymbolicLink   (reparse points only)
        There is no current way to ask for "both files and dirs with totals"
        in one call - run twice if you need both.

        Pruned subtrees (-Exclude) are NOT counted toward parent totals.

        -MaxDepth interaction (matches GNU du -d N): when -DirectoryTotals
        is set, MaxDepth limits ONLY what gets emitted - the recursion
        always goes to the bottom of the tree so each emitted directory's
        total reflects everything beneath it. Without -DirectoryTotals,
        MaxDepth caps recursion too (as a performance feature).

        NOTE: This is the core feature of GNU 'du', not 'find'. Use it for
        the "what's eating my disk?" workflow:

          Find-Item C:\Users -Type Directory -MaxDepth 2 -DirectoryTotals |
              Sort-Object Length -Descending

        (Length stays numeric when -SizeUnit is the default Bytes, so
        Sort-Object Length works correctly. Switch to -SizeUnit Auto for
        human-readable display, but be aware Length becomes a string.)

    .PARAMETER AllocatedSize
        Report ON-DISK ALLOCATION (cluster-rounded bytes physically stored)
        instead of LOGICAL file content size in every size-reporting feature.
        Affects:
          -Size                  : filter against allocation, not Length
          -LongList Length       : displayed value is allocation
          -SortBy Length         : sort by allocated bytes
          -DirectoryTotals       : sum allocations across subtrees
          -Summary TotalBytes    : sum of allocations
          -SummaryOnly TotalSize : formatted allocation total

        NOT affected:
          -Empty                 : always tests LOGICAL Length (see notes
                                   on that parameter for the rationale)
          The default output     : raw FileInfo.Length unchanged - that's
            FileInfo.Length         a .NET property we can't (and shouldn't)
                                   shadow. Apply -LongList or -SizeUnit to
                                   see allocated values in the table.

        Backed by Win32 GetCompressedFileSize, which correctly handles:
          - NORMAL files (rounded UP to the volume's cluster size)
          - NTFS-compressed files (compressed bytes, cluster-rounded)
          - SPARSE files (data bytes only, cluster-rounded)
          - RESIDENT-IN-MFT files (1 cluster minimum for non-empty)
          - DEDUPLICATED files (the shared block size)

        Results are cached per invocation, so combining -AllocatedSize with
        -Size / -DirectoryTotals / -Summary / -LongList / -SortBy Length
        costs ONE Win32 call per file (not one per feature). Overhead is
        ~1-5 microseconds per file, negligible compared to ACL operations.

        See .NOTES > APPARENT SIZE vs ALLOCATED SIZE for the full GNU 'du'
        compatibility story.

    .PARAMETER IncludeStreams
        When combined with -AllocatedSize, additionally sum the allocated
        bytes of every alternate data stream (ADS) on each file, not just
        the main stream. Default is OFF (main stream only).

        ADS are a Windows-specific feature where a single file can have
        multiple named data streams (e.g. 'file.txt:metadata.dat'). They
        consume disk space but are invisible to most directory listings
        and to GetCompressedFileSize's default behaviour. Auditing tools
        and forensic analyses often want ADS-aware totals; everyday
        cleanup queries usually do not.

        Has no effect without -AllocatedSize. Adds one extra Win32 call
        per file (via FindFirstStreamW), so the overhead grows with ADS
        density - in practice negligible because most files have no ADS.

    .PARAMETER Summary
        Appends a single summary record to the end of the output stream
        with the totals across all matched items:

          ItemCount       total items matched
          FileCount       of which were regular files
          DirectoryCount  of which were regular directories
          SymlinkCount    of which were reparse points
          TotalBytes      sum of file sizes (raw, numeric long)
          TotalSize       same, formatted per -SizeUnit (or 'Auto' if the
                          unit is the default Bytes - a single aggregate
                          number reads better with an adaptive unit)

        The summary is emitted as a PSCustomObject with type name
        'FindItem.Summary'; the registered format view renders it as a
        compact table.

        NOTE: This is NOT a GNU find feature. The closest GNU equivalent
        is the 'du' command (specifically 'du -c' / --total, which prints
        a grand total). It's included here because the question "how big
        is this set of files?" is asked often enough that piping to a
        separate 'du' is friction worth removing.

        CAVEAT: when combined with normal per-item output, the stream
        contains a mix of FileSystemInfo objects and one trailing
        PSCustomObject. Downstream commands that don't handle that shape
        change cleanly should use -SummaryOnly instead.

    .PARAMETER SummaryOnly
        Emits ONLY the summary record - per-item output is suppressed
        entirely. Implies -Summary. The work (traversal, filtering,
        counting, even -Delete) still happens; just the per-item rows are
        not written to the pipeline.

        NOTE: Like -Summary, this is borrowed from GNU 'du -s' / --summarize,
        not from find.

    .PARAMETER SizeUnit
        Controls how the Length column is displayed in long-list output.
        Specifying any value other than Bytes implicitly enables -LongList
        (the default FileInfo formatter has no hook for overriding the
        Length column, so formatted sizes require the LongList view).

        Has no effect on filtering: -Size still parses its own [+|-]<n>[c|k|M|G]
        spec independently.

        Accepted values (IEC binary prefixes, base 2):

          Bytes  (default)  raw byte count, no suffix (e.g. 524288)
                            Length stays numeric - safe for Sort-Object
          KiB               value / 1024, e.g. "512.00 KiB"
          MiB               value / 1024^2, e.g. "1.50 MiB"
          GiB               value / 1024^3
          TiB               value / 1024^4
          Auto              picks the smallest unit where value >= 1
                            (uses "B" for sub-KiB values)

        TRADE-OFF: any value other than Bytes turns the Length column into
        a formatted STRING. Sort-Object Length and numeric comparisons
        downstream will then sort lexically, not by actual size. If you
        need both pretty display and accurate sorting, sort first then
        format: ... | Sort-Object Length | <pipe to a renderer>.

    .EXAMPLE
        Find-Item -Path C:\Projects -Name "*.ps1" -Type File
        All PowerShell scripts under C:\Projects (returns FileInfo objects).

    .EXAMPLE
        Find-Item . -Name "*.ps1" -Type File -FullPath
        Same search, but outputs full path strings like GNU find.

    .EXAMPLE
        Find-Item C:\Logs -Name "*.log" -Type File -LongList
        Like 'find C:\Logs -name *.log -ls' on Linux. Tabular output with
        Mode, Length, LastWriteTime, FullName columns. -Ls is an alias.

    .EXAMPLE
        Find-Item C:\Shared -Type File -LongList -ShowOwner | Sort-Object Owner
        Adds an Owner column (slow - one ACL read per file) and sorts by
        owner. Useful for "who owns what in this share?" audits.

    .EXAMPLE
        Find-Item C:\Logs -Type File -Ls -SizeUnit Auto
        Long-list output with file sizes formatted in the most-readable
        binary unit per row (e.g. "847 B", "12.34 KiB", "1.50 MiB").

    .EXAMPLE
        Find-Item C:\Users\me -Type Directory -MaxDepth 2 -DirectoryTotals -SizeUnit Auto |
            Sort-Object FullName
        Two-level directory map with human-readable subtree sizes. The
        'du -sh */' workflow.

    .EXAMPLE
        Find-Item C:\AMD -DirectoryTotals -SortBy Length -SortOrder Desc -SizeUnit Auto
        Biggest directories first - what's eating disk? Sort is by the
        recursive byte total (numeric), so '83.46 MiB' correctly ranks
        above '2.18 MiB' rather than alphabetically.

    .EXAMPLE
        Find-Item C:\Logs -Type File -Name "*.log" -SortBy LastWriteTime -SortOrder Desc
        Most recently modified .log files first.

    .EXAMPLE
        Find-Item C:\Source -Type File -SortBy Extension | Group-Object Extension
        Group files by extension after sorting - useful for "what kinds of
        files are in this project?" surveys.

    .EXAMPLE
        Find-Item C:\Users -Type File -SortBy Length -SortOrder Desc -First 10
        Top 10 biggest files. With -SortBy, the buffer still holds all
        matched files; the truncation happens at the end.

    .EXAMPLE
        Find-Item C:\Logs -Type File -First 100
        First 100 log files in traversal order. Traversal stops at item
        100 - no further disk I/O. Memory: O(1).

    .EXAMPLE
        Find-Item C:\Backups -Type File -Last 5
        Last 5 files in traversal order. Memory: O(5) - a sliding-window
        queue, regardless of how many files total.

    .EXAMPLE
        # PowerShell 7+ only:
        Find-Item C:\Users -Type File | Sort-Object Length -Top 10 -Descending
        Memory-efficient alternative to '-SortBy Length -First 10' for huge
        trees: Sort-Object's -Top is a streaming heap-selection, so total
        memory is O(10) even across millions of files. Not available on
        Windows PowerShell 5.1 - see NOTES > STRATEGIES FOR HUGE TREES.

    .EXAMPLE
        Find-Item C:\AMD -Type File -SummaryOnly
        Just the total: how many files, how many bytes - no per-file noise.
        Useful for "how big is this tree?" questions.

    .EXAMPLE
        Find-Item C:\Logs -Name "*.log" -Ls -Summary
        Long-list every matching log file, then a summary row at the end
        showing the count and total size.

    .EXAMPLE
        Find-Item C:\Backups -Type File -Size +1G -Ls -SizeUnit GiB
        Files larger than 1 GiB, sizes shown in GiB. Note: -Size still
        accepts its own +/- prefixes and units; -SizeUnit only affects
        DISPLAY of the Length column.

    .EXAMPLE
        Find-Item . -LastWriteTime -7 -Type File | Select-Object FullName, LastWriteTime
        Files modified in the last 7 days. The Linux alias -MTime -7 is equivalent.

    .EXAMPLE
        Find-Item . -CreationTime +30 -Type File
        Files that were created more than 30 days ago. Aliases: -BTime +30 (Linux
        birth-time semantics) or -CTime +30 (GNU muscle memory - see NOTES).

    .EXAMPLE
        Find-Item . -LastWriteTime "+2026-01-15" -Type File
        Files modified after Jan 15, 2026 (00:00:00 local time).

    .EXAMPLE
        Find-Item . -LastWriteTime "2026-05-20" -Type File
        Files modified on May 20, 2026 (any time during that calendar day).

    .EXAMPLE
        Find-Item C:\Logs -CreationTime "-2025-01-01" -Type File
        Files created BEFORE Jan 1, 2025 - useful for archival cleanup.

    .EXAMPLE
        Find-Item . -LastWriteTime "+2026-05-20T09:00:00" -Type File
        Files modified after 9 AM on May 20, 2026 (ISO-8601 timestamp).

    .EXAMPLE
        Find-Item . -Size +100M -Type File | Sort-Object Length -Descending
        Files larger than 100 MiB, biggest first.

    .EXAMPLE
        Find-Item . -Name "*.tmp" -Delete -WhatIf
        Preview which .tmp files would be deleted.

    .EXAMPLE
        Find-Item . -Type Directory -Exclude ".git","node_modules","bin","obj"
        All subdirectories, skipping common noise directories.

    .EXAMPLE
        Find-Item . -Type File -Newer .\reference.txt
        Files modified more recently than reference.txt.

    .EXAMPLE
        Find-Item C:\Logs -Name "*.log" | Where-Object { $_.Length -gt 1MB -or $_.LastWriteTime -lt (Get-Date).AddDays(-90) }
        Complex conditions via Where-Object.

    .EXAMPLE
        Find-Item . -Regex '\\tests?\\'  -Type File
        Files whose path contains a 'test' or 'tests' directory segment.

    .EXAMPLE
        Find-Item . -Name "*.log","*.tmp","*~" -Type File
        Files matching ANY of those wildcard patterns (implicit OR within
        the -Name parameter). Equivalent to GNU find's
        '\( -name "*.log" -or -name "*.tmp" -or -name "*~" \)'.

    .EXAMPLE
        Find-Item C:\Source -Type File -NotName "*.bak","*~",".gitkeep"
        All files EXCEPT those matching the listed backup/junk patterns.
        Equivalent to GNU find's '-not \( -name "*.bak" -o -name "*~" \)'.

    .EXAMPLE
        Find-Item . -Type File,SymbolicLink
        Files OR symlinks (but not regular directories).

    .EXAMPLE
        Find-Item C:\Shared -Type File -WritableBy 'Everyone','BUILTIN\Users'
        Security audit: "find every file in C:\Shared whose ACL grants Write
        to Everyone or to BUILTIN\Users". The classic 'world-writable'
        query - the Windows-native analog of 'find -perm -o+w'.

    .EXAMPLE
        Find-Item C:\Shared -Type Directory -WritableBy 'Everyone'
        World-writable DIRECTORIES - matches dirs where Everyone has any
        of CreateFiles, CreateDirectories, or DeleteSubdirectoriesAndFiles.
        Often more dangerous than world-writable files because attackers
        can drop new payloads into them.

    .EXAMPLE
        Find-Item C:\Apps -ModifiableBy 'Everyone','BUILTIN\Users' -Ls -ShowOwner
        Items where a broad principal has the full Modify composite right
        (read + write + delete). Stricter than -WritableBy; matches only
        ACEs granting Modify or FullControl, not partial-write ACEs.

    .EXAMPLE
        Find-Item C:\Apps -FullControlBy 'Everyone' -Ls
        Items where Everyone has the FullControl composite - the strictest
        misconfiguration check. Includes ability to change the ACL itself.

    .EXAMPLE
        Find-Item C:\Program Files -Type File -ExecutableBy 'Users' -NotName "*.dll"
        Executables (PATHEXT extension + ExecuteFile in ACL) granted to
        BUILTIN\Users, excluding .dll files.

    .EXAMPLE
        Find-Item C:\Users\me -DirectoryTotals -AllocatedSize -SizeUnit Auto -MaxDepth 1
        Disk-usage map of immediate subdirectories, showing what they
        actually consume on disk (cluster-rounded). Equivalent to
        'du -hd 1 ~' on Linux.

    .EXAMPLE
        Find-Item C:\Source -Type File -SummaryOnly -AllocatedSize
        Total disk footprint of a code tree. Compare to the same query
        without -AllocatedSize to see how much cluster slack you're
        paying for (especially noticeable on trees with many small files).

    .EXAMPLE
        $logical   = Find-Item C:\Source -Type File -SummaryOnly
        $allocated = Find-Item C:\Source -Type File -SummaryOnly -AllocatedSize
        "Cluster slack: $($allocated.TotalBytes - $logical.TotalBytes) bytes"
        Compute the cluster overhead of a tree (how many bytes are wasted
        to block alignment vs the logical content size). Useful for
        capacity planning on small-file-heavy directories.

    .EXAMPLE
        Find-Item C:\Forensic -Type File -AllocatedSize -IncludeStreams -Ls -SizeUnit Auto
        List every file with its total on-disk footprint INCLUDING
        alternate data streams. Useful for forensic / steganography
        sweeps where ADS may be hiding payloads. (Combine with
        -SortBy Length -SortOrder Desc -First N to surface the biggest
        ADS-bearing files.)

    .EXAMPLE
        Find-Item C:\Temp -Empty -Type File
        All zero-byte files - typical post-build cleanup target.

    .EXAMPLE
        Find-Item C:\Build -Empty -Type Directory -Delete -WhatIf
        Preview deletion of every empty directory under C:\Build.

    .EXAMPLE
        Find-Item C:\Logs -Name "*.log" -LastWriteTime +30d -Delete -PassThru |
            Export-Csv .\purged.csv -NoTypeInformation
        Delete .log files older than 30 days AND keep a CSV audit trail
        of what was removed.

    .EXAMPLE
        Find-Item C:\Logs -Type File -LastWriteTime -15m
        Files modified in the last 15 minutes - useful for "what just
        changed?" while debugging. Minute-grain time spec is the analog
        of GNU find's -mmin.

    .EXAMPLE
        Find-Item C:\Shared -Type File -Owner '*\alice' -NotOwner 'BUILTIN\Administrators'
        Files owned by anyone called alice, excluding admin-owned items.

    .EXAMPLE
        Get-Content servers.txt | ForEach-Object { "\\$_\C$\Logs" } |
            Find-Item -Type File -Name "*.log" -LastWriteTime -1h
        Pipeline composition: build paths from a text file and run a
        single Find-Item against all of them. Requires -Path to accept
        pipeline input (it does).

    .EXAMPLE
        Find-Item C:\Logs -Type File -Name "*.log" -AppendableBy "$env:USERDOMAIN\$env:USERNAME"
        Log files the current user can append to. AppendData is granted
        independently of WriteData on NTFS, so this isolates the "logger"
        access pattern.

    .EXAMPLE
        Find-Item C:\Logs -Type File -Filter {
            ($_.Name -like "*.log" -or $_.Name -like "*.tmp") -and
            $_.LastWriteTime -lt (Get-Date).AddDays(-30) -and
            -not ($_.FullName -match '\\archive\\')
        }
        Arbitrary nested boolean logic via a scriptblock. Equivalent to a
        complex GNU find expression with parentheses, -and, -or, and -not.

    .NOTES
        APPARENT SIZE vs ALLOCATED SIZE (GNU 'du' / 'du --apparent-size' parity)

        Every size figure Find-Item reports comes in two flavours:

          LOGICAL / APPARENT (default)
            What FileInfo.Length returns and Explorer shows as "Size".
            The number of content bytes you'd get if you read the file
            top-to-bottom. Independent of how those bytes are physically
            stored. Equivalent to 'du --apparent-size' on Linux.

          ALLOCATED / ON-DISK (with -AllocatedSize)
            The number of bytes physically consumed on disk. Computed
            via Win32 GetCompressedFileSize, then rounded UP to the
            file's volume cluster size. Matches Explorer's "Size on
            disk" column. Equivalent to GNU 'du' default behaviour.

        WHEN THEY DIFFER

          File                          Logical     Allocated (4K clusters)
          ----------------------------  ----------  -----------------------
          0-byte (truly empty)                   0                       0
          100-byte normal file                 100                    4096
          5,000-byte normal file             5,000                    8192
          1 MiB sparse file (all holes)  1,048,576                       0
                                                                or 1 cluster
          NTFS-compressed 5MB -> 1MB     5,242,880               compressed
                                                                + rounded
          File w/ alternate streams      main only           sum, if
                                                            -IncludeStreams

        WHICH FEATURES ARE AFFECTED

          Affected by -AllocatedSize:
            -Size            (filter against allocated bytes)
            -DirectoryTotals (sum allocations across subtree)
            -Summary         (TotalBytes / TotalSize reflect allocation)
            -LongList Length (displayed column shows allocation)
            -SortBy Length   (sort key is allocation)

          NOT affected (intentional):
            -Empty             always tests LOGICAL Length - see notes on
                               that parameter for the rationale
            Default FileInfo   .Length is a .NET property we cannot shadow;
              output           use -LongList or -SizeUnit to surface
                               allocated values explicitly

        ADS HANDLING

          The default -AllocatedSize reports the MAIN stream's allocation
          only. NTFS files can carry additional named data streams (e.g.
          'file.txt:secret.dat') that consume disk but are invisible to
          GetCompressedFileSize and to 'dir' output. Pass -IncludeStreams
          to sum ALL streams per file. Most files have no ADS; the cost
          for files that do is one extra FindFirstStream call.

        GNU DU EQUIVALENCE TABLE

          GNU du command                 Find-Item form
          -----------------------------  --------------------------------
          du -s /path                    Find-Item /path -SummaryOnly -AllocatedSize
          du --apparent-size -s /path    Find-Item /path -SummaryOnly
          du -h /path                    -DirectoryTotals -AllocatedSize -SizeUnit Auto
          du -hd 1 /path                 -DirectoryTotals -AllocatedSize
                                         -SizeUnit Auto -MaxDepth 1
          du -h --apparent-size /path    -DirectoryTotals -SizeUnit Auto (no -AllocatedSize)

        PERMISSION-FILTER SEMANTICS (Windows-native -perm equivalent)

        GNU find's '-perm' tests the file's mode bits. Windows has no mode
        bits - access is controlled by NTFS ACLs, which are per-trustee
        access-rule lists. The closest equivalent is a set of filters that
        ask "does this file's DACL grant <right> to <principal>?":

          GNU find idiom              Find-Item analog
          --------------------------  -----------------------------------
          -perm -o+r (world-readable) -ReadableBy 'Everyone'
          -perm -o+w (world-writable) -WritableBy 'Everyone','BUILTIN\Users'
          -perm -u+w                  -WritableBy "$env:USERDOMAIN\$env:USERNAME"
          -perm /a+x                  -ExecutableBy 'Everyone'
          (no Unix analog)            -AppendableBy 'Everyone'  (NTFS distinguishes
                                      AppendData from WriteData; logs often grant
                                      only append)
          (no Unix analog)            -ModifiableBy 'Everyone'  (composite right:
                                      principal has full read/write/delete)
          (no Unix analog)            -FullControlBy 'Everyone' (composite right:
                                      everything including ACL changes)

        NTFS RIGHTS MAPPED TO FILTERS (complete inventory)

        Every FileSystemRights value mapped to the filter(s) that catch it.
        For atomic bits, "caught by" means the filter's mask includes that
        bit (any-bit matching). For composites, "caught by" means an ACE
        granting that composite will match because the composite's bit
        pattern includes the relevant bit(s).

        ATOMIC RIGHTS (single-bit)
          Right                        Hex      File/Dir name           Caught by
          ---------------------------  -------  ----------------------  -----------------------
          ReadData / ListDirectory      0x1     same                    -ReadableBy
          WriteData / CreateFiles       0x2     same                    -WritableBy
          AppendData / CreateDirs       0x4     same                    -AppendableBy, -WritableBy(dirs)
          ReadExtendedAttributes        0x8     (same name)             -ReadableBy
          WriteExtendedAttributes       0x10    (same name)             -WritableBy
          ExecuteFile / Traverse        0x20    same                    -ExecutableBy
          DeleteSubdirectoriesAndFiles  0x40    (dir-only)              -WritableBy(dirs)
          ReadAttributes                0x80    (same name)             -ReadableBy
          WriteAttributes               0x100   (same name)             -WritableBy
          Delete                        0x10000 (same name)             -WritableBy
          ReadPermissions               0x20000 (same name)             ❌ no filter (see below)
          ChangePermissions             0x40000 (same name)             ❌ only -FullControlBy
          TakeOwnership                 0x80000 (same name)             ❌ only -FullControlBy
          Synchronize                   0x100000 (same name)            ❌ no filter (see below)

        COMPOSITE RIGHTS (multi-bit aggregates)
          Right          Composition                                     Caught by
          -------------  ----------------------------------------------  ----------------------
          Read           ReadData + ReadEA + ReadAttrs + ReadPerms       -ReadableBy
          ReadAndExecute Read + ExecuteFile                              -ReadableBy + -ExecutableBy
          Write          WriteData + AppendData + WriteEA + WriteAttrs   -WritableBy + -AppendableBy
          Modify         ReadAndExecute + Write + Delete                 all 4 capability filters + -ModifiableBy
          FullControl    Modify + DeleteSubdirs + ChangePerms +          all 6 filters (incl. -FullControlBy)
                          TakeOwnership + Synchronize

        RIGHTS NOT MAPPED TO ANY CAPABILITY FILTER (and why)

          ReadPermissions      Granted by default to virtually every
                               principal on every file. Including it in
                               -ReadableBy would dilute the filter to
                               "matches almost everything". Audit via
                               -Filter scriptblock if needed.

          ChangePermissions    Administrative right - can rewrite the ACL
                               itself. Not a read/write/append/execute
                               operation. Only -FullControlBy catches it,
                               and only when granted alongside everything
                               else. A standalone grant of just
                               ChangePermissions is a privilege-escalation
                               configuration that current filters DO NOT
                               flag. Audit via -Filter.

          TakeOwnership        Administrative right - become the file
                               owner. Same situation as ChangePermissions:
                               privilege-escalation, not data access.
                               Standalone grants slip through; audit via
                               -Filter.

          Synchronize          Infrastructure right needed for sync I/O on
                               file handles. Granted to every principal by
                               default. Not user-facing.

        AUDIT WORKAROUND FOR THE UNMAPPED ADMINISTRATIVE RIGHTS

        To find files where a specific principal has ChangePermissions or
        TakeOwnership granted (without requiring FullControl):

          $rights = [System.Security.AccessControl.FileSystemRights]
          Find-Item C:\App -Type File -Filter {
              ($_ | Get-Acl).Access | Where-Object {
                  $_.AccessControlType -eq 'Allow' -and
                  $_.IdentityReference -ilike 'Everyone' -and
                  ($_.FileSystemRights -band $rights::ChangePermissions)
              }
          }

        (This bypasses the function's ACL cache; it's fine for one-off
        audits but slower on large trees.)

        FILE vs DIRECTORY BIT MEANINGS

        NTFS rights are stored as bit values; the same bit has different
        names depending on whether the item is a file or a directory.
        Find-Item's filters apply the type-appropriate meaning of each bit:

          Bit value  File name      Directory name              Used by
          ---------  -------------  --------------------------  ---------------
                 1   ReadData       ListDirectory               -ReadableBy
                 2   WriteData      CreateFiles                 -WritableBy
                 4   AppendData     CreateDirectories           -AppendableBy
                32   ExecuteFile    Traverse                    -ExecutableBy
                64   (n/a)          DeleteSubdirectoriesAndFiles -WritableBy (dirs)

        For directories, -WritableBy expands to ANY of CreateFiles,
        CreateDirectories, or DeleteSubdirectoriesAndFiles - because a
        principal that can do any of those can change the directory's
        contents in some way. -AppendableBy on a directory specifically
        means "can create subdirectories" (the parallel to AppendData
        on files).

        COMPOSITE-RIGHTS MATCHING (-ModifiableBy, -FullControlBy)

        These filters use ALL-bits matching rather than ANY-bit matching:
        the ACE must grant every constituent bit of the composite right.
        This is required because composites like Modify are unions:

          Modify      = ReadAndExecute | Write | Delete  (plus attrs/perms/sync)
          FullControl = all rights including ChangePermissions, TakeOwnership

        ANY-bit matching on Modify would return true for any ACE granting
        even just Read (since Read's bits are a subset of Modify's), which
        would make the filter useless. ALL-bits matching correctly answers
        "is the principal at least at the Modify level on this item?"

        Each -*By filter takes one or more wildcard patterns ('Everyone',
        'BUILTIN\*', '*\alice'); array = OR; multiple -*By filters are
        ANDed with each other and with everything else.

        LITERAL-ACL vs EFFECTIVE-ACCESS

        These filters check the DACL's ACEs directly. They do NOT replicate
        the full Windows access-check evaluation, which would require:

          - expanding group memberships transitively (a user gets every
            permission granted to every group they're in, recursively),
          - applying Deny ACEs with their precedence rules (a Deny on a
            group the user is in overrides an Allow on the user themself),
          - honoring inheritance order, integrity levels, and SACL/
            mandatory-access constraints.

        Doing that properly requires AuthzAccessCheck / GetEffectiveRights,
        which is well beyond the scope of a single-file utility. The
        literal-ACL check is exactly what security audits want ("find
        every file whose ACL grants Write to Everyone") but is NOT a
        guarantee that the named principal can effectively perform the
        action on the file (a Deny ACE elsewhere may block them).

        For an authoritative answer, run 'icacls <file>' or the .NET
        AuthzAccessCheck API on a specific file after Find-Item narrows
        the candidate list.

        PERFORMANCE

        Each -*By filter requires a Get-Acl per item (50-200ms each on
        local NTFS, more on network shares). For large trees, filter
        cheaply FIRST (-Type / -Name / -Size) and let the permission
        check run against the survivors. The function maintains a per-
        invocation ACL cache, so combining e.g. -WritableBy with
        -ShowOwner or -SortBy Owner pays the Get-Acl cost only once.

        EXECUTABLE-EXTENSION LIST

        -ExecutableBy treats a file as executable only if its extension is
        in the Windows shell's PATHEXT list at function-load time, plus
        .PS1 / .PSM1 / .PSD1. The default PATHEXT is roughly
        '.COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC' but is
        machine-configurable. Files outside that set are never matched by
        -ExecutableBy regardless of their ACL.

        SECURITY CONSIDERATIONS

        This is an interactive tool; the user invoking it runs with their
        own privileges and sees their own data. The notes below matter
        mainly to AUTOMATION / SERVICE callers that wrap Find-Item and
        expose it to less-privileged input.

        1) -Filter ACCEPTS ARBITRARY POWERSHELL CODE.
           The scriptblock is executed with the caller's full privileges
           and can do anything (write files, make network calls, delete
           data, etc.). Find-Item is safe as long as the scriptblock comes
           from the caller themselves; it is UNSAFE if a caller does
           something like:

               Find-Item . -Filter ([scriptblock]::Create($userInput))

           That is equivalent to Invoke-Expression on $userInput. Never
           build -Filter from untrusted input - use the structured
           parameters (-Name / -Regex / -Size / -Type / etc.) instead.

        2) -Delete IS RECURSIVE ON MATCHED DIRECTORIES.
           A matched directory's ENTIRE subtree is deleted, even files
           that didn't match the filter. Always run broad -Delete queries
           with -WhatIf first. See .PARAMETER Delete for details.

        3) REPARSE POINTS (junctions, symbolic links) ARE NEVER FOLLOWED
           BY -Delete.
           The function uses .NET Directory.Delete(path, recursive=$false)
           rather than Remove-Item -Recurse when the matched item is a
           reparse point. This avoids the well-known PS 5.1 / 7.0 bug
           where Remove-Item -Recurse on a junction destroys the link
           target's contents.

           For TRAVERSAL, reparse points are skipped by default. Use
           -FollowSymlinks to descend into them, with the understanding
           that doing so may cross into directories outside the intended
           scope (and may loop on circular links).

        4) REGEX PATTERNS HAVE A 5-SECOND MATCH TIMEOUT.
           -Regex / -IRegex / -NotRegex / -NotIRegex patterns are compiled
           once with a 5s per-match timeout, so a pathological pattern
           (e.g. '(a+)+$' against long input - "ReDoS") cannot hang the
           traversal. A timed-out match is reported via Write-Warning,
           skipped for that item, and the walk continues.

        5) -ShowOwner BULK-EXPOSES IDENTITY METADATA.
           See .PARAMETER ShowOwner for details. Avoid logging the output
           to locations readable by lower-privileged principals.

        6) PATH ARGUMENTS ARE NOT SANDBOXED.
           Find-Item operates wherever -Path points. If you build a
           caller that accepts a path from untrusted input, validate /
           canonicalize the path BEFORE passing it - Find-Item does not
           and cannot enforce a "stay within X" boundary on the caller's
           behalf.

        MEMORY CHARACTERISTICS

        Most modes stream: items are emitted to the pipeline as the tree is
        walked, so memory stays O(1) regardless of how many files match.

          Default output                           O(1)
          -FullPath                                O(1)
          -LongList                                O(1)
          -Summary / -SummaryOnly (counters only)  O(1)
          -DirectoryTotals (per-recursion accum.)  O(depth)
          -First N (no -SortBy)                    O(1) + early termination
          -Last  N (no -SortBy)                    O(N) sliding window

        -SortBy is the one mode that requires buffering the full matched
        set, since sorting needs every item in hand. Memory is O(matches);
        for very large trees this can be hundreds of MB or more.

          -SortBy alone                            O(matches)
          -SortBy + -First N / -Last N             O(matches) buffer, O(N) result

        When -SortBy is in effect, a warning fires once the buffer crosses
        -MaxBufferItems (default 100,000) so you find out before memory
        becomes a problem. Set -MaxBufferItems 0 to silence.

        STRATEGIES FOR HUGE TREES

        Three options when -SortBy on millions of files isn't feasible:

        1) FILTER FIRST. The cheapest fix - the more aggressive your
           -Name / -Size / -Type / -Filter filters, the fewer items reach
           the sort buffer. A targeted query with -SortBy is usually fine.

        2) PowerShell 7+: PIPE TO 'Sort-Object -Top N'. PS7 added -Top /
           -Bottom to Sort-Object, which maintain only N items in memory
           via heap selection as items stream through. End-to-end memory
           is O(N) regardless of input size:

              # PowerShell 7+ only:
              Find-Item C:\Users -Type File |
                  Sort-Object -Property Length -Top 10 -Descending

           This works because Find-Item's default output streams and
           Sort-Object consumes the pipeline incrementally. The cost: you
           give up -DirectoryTotals / -SizeUnit / -LongList formatting
           (apply those manually with Select-Object / Format-Table after).

        3) WINDOWS POWERSHELL 5.1: there is no built-in streaming partial
           sort. Sort-Object always buffers in 5.1. Practical options:
              - Filter aggressively (option 1 above), OR
              - Accept the memory cost (the -MaxBufferItems warning will
                tell you when the buffer gets large), OR
              - Upgrade to PowerShell 7+ for the streaming workaround.

        COMPOUND BOOLEAN LOGIC (GNU find's -and / -or / -not / parentheses)

        GNU find uses a positional expression language where filters and
        operators chain into an expression tree:
          find . \( -name "*.log" -or -name "*.tmp" \) -and -not -newer ref

        PowerShell parameters are key/value bindings and cannot express
        operators between them. Find-Item provides three composable
        mechanisms instead, listed in order of how often you'll reach for
        each:

        1) ARRAY VALUES = OR WITHIN ONE PARAMETER
           Pass multiple values to -Name / -IName / -Regex / -IRegex /
           -Type / -Exclude / -NotName / -NotIName / etc. An item matches
           the parameter if it matches ANY listed value. Covers most "or"
           cases without operator syntax:
              Find-Item . -Name "*.log","*.tmp"
              Find-Item . -Type File,SymbolicLink

        2) NEGATION PARAMETERS = NOT
           -NotName / -NotIName / -NotRegex / -NotIRegex reject any item
           matching their listed patterns. Combine with arrays for "not in
           a set":
              Find-Item . -Type File -NotName "*.bak","*~",".gitkeep"

        3) -Filter SCRIPTBLOCK = ARBITRARY BOOLEAN LOGIC
           For anything the structured parameters can't express - nested
           ANDs/ORs/NOTs, comparisons against derived properties, etc:
              -Filter {
                  ($_.Name -like "*.log" -or $_.Name -like "*.tmp") -and
                  -not ($_.FullName -match '\\archive\\')
              }
           The scriptblock receives each candidate as $_, and you have the
           full PowerShell expression language available.

        DIFFERENT PARAMETERS ARE STILL ANDed TOGETHER. -Name "x" -Type File
        means "matches *x AND is a file". This is the same model as GNU
        find's default (juxtaposition implies -and); it's only -or that
        needs explicit syntax. With arrays + -Filter, the only thing you
        truly can't express compactly is OR-across-different-test-kinds
        (e.g. "name matches X OR type is Directory"). Use -Filter for that.

        EQUIVALENCE TABLE

          GNU find expression                  Find-Item form
          ---------------------------------    --------------------------------
          -name "*.log" -o -name "*.tmp"       -Name "*.log","*.tmp"
          -type f -and -name "*.log"           -Type File -Name "*.log"
          -not -name "*.bak"                   -NotName "*.bak"
          \( A -or B \) -and -not C            -Filter { (A -or B) -and -not C }


        WINDOWS vs LINUX TIMESTAMP SEMANTICS

        Windows (NTFS) tracks three timestamps that are surfaced by .NET /
        PowerShell, plus a fourth that is not:

          CreationTime    - when the file was first created at this location
          LastWriteTime   - when the file's contents were last written
          LastAccessTime  - when the file was last opened/read
          (MFT change time - tracked internally; not exposed by standard APIs)

        Mapping to Linux find:

          Find-Item parameter   Linux alias   Linux find equivalent
          -------------------   -----------   ---------------------
          -LastWriteTime        -MTime        -mtime    (true equivalent)
          -LastAccessTime       -ATime        -atime    (true equivalent)
          -CreationTime         -BTime        -Btime    (true equivalent)
          -CreationTime         -CTime        -ctime    (SEMANTIC MISMATCH!)

        The -CTime alias is provided for GNU find muscle memory only. On
        Linux, ctime is the "inode change time" - updated whenever metadata
        (permissions, ownership, link count, etc.) changes. On Windows,
        no equivalent is exposed by .NET, so -CTime maps to CreationTime
        instead. This matches the convention used by GnuWin32 and other
        Windows ports of find, but the semantics are different.

        LAST-ACCESS-TIME IS USUALLY STALE ON WINDOWS

        Since Windows Vista, NTFS access-time updates are disabled by
        default for performance. Check with:

          fsutil behavior query DisableLastAccess

        Values 1 or 3 mean updates are off. Unless you have enabled them,
        -LastAccessTime / -ATime filtering will return misleading results
        (often equal to CreationTime, or stale by weeks).
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([System.IO.FileSystemInfo], ParameterSetName = 'Default')]
    [OutputType([string],                   ParameterSetName = 'FullPath')]
    [OutputType([pscustomobject],           ParameterSetName = 'LongList')]
    param(
        # Position 0 binds positionally; ValueFromPipeline lets you pipe
        # strings directly (e.g. 'C:\dir1','C:\dir2' | Find-Item);
        # ValueFromPipelineByPropertyName lets you pipe FileSystemInfo etc.
        # since they expose .FullName (aliased here). PSPath is the
        # PSProvider-friendly property name (e.g. Get-ChildItem output).
        [Parameter(Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('FullName', 'PSPath')]
        [string[]] $Path = '.',

        # --- Name / path filters (arrays = OR within the parameter) ---
        [string[]] $Name,
        [string[]] $IName,
        [string[]] $Regex,
        [string[]] $IRegex,

        # --- Negation siblings (item REJECTED if any element matches) ---
        [string[]] $NotName,
        [string[]] $NotIName,
        [string[]] $NotRegex,
        [string[]] $NotIRegex,

        # --- Type filter (array = OR; item matches if it is ANY of the types) ---
        [ValidateSet('f', 'd', 'l', 'File', 'Directory', 'SymbolicLink')]
        [string[]] $Type,

        # --- Free-form predicate scriptblock (Where-Object style) ---
        # Receives each candidate item as $_; truthy result = item passes.
        # Runs after all built-in tests so cheap filters short-circuit first.
        [scriptblock] $Filter,

        # --- ACL-based access filters (Windows-native equivalent of GNU find's
        # -perm). Each takes one or more principal patterns matched with -like
        # against the ACE's IdentityReference (e.g. 'BUILTIN\Administrators',
        # 'Everyone', 'CORP\*', '*\alice'). Item passes if ANY listed
        # principal has the requested access via an Allow ACE in the DACL.
        # Semantics are LITERAL-ACL, not effective-access; see NOTES. ---
        [string[]] $ReadableBy,
        [string[]] $WritableBy,
        [string[]] $AppendableBy,
        [string[]] $ExecutableBy,
        [string[]] $ModifiableBy,
        [string[]] $FullControlBy,

        # --- Owner filters (analogous to GNU find -user). Match items whose
        # NTFS owner matches (or does NOT match) any listed principal pattern.
        # Patterns use -like wildcards: 'CORP\*', '*\alice', 'BUILTIN\Administrators'.
        # Uses the per-invocation ACL cache - free when combined with -ShowOwner
        # / -SortBy Owner / other -*By filters. ---
        [string[]] $Owner,
        [string[]] $NotOwner,

        # --- Size filter ---
        [string] $Size,

        # --- Empty-item filter (files of length 0 OR directories with no entries) ---
        [switch] $Empty,

        # --- Time filters (Windows-native names; Linux aliases provided) ---
        [Alias('MTime')]
        [string] $LastWriteTime,

        [Alias('ATime')]
        [string] $LastAccessTime,

        [Alias('BTime', 'CTime')]
        [string] $CreationTime,

        # --- Reference-file time ---
        [string] $Newer,

        # --- Depth ---
        [ValidateRange(0, [int]::MaxValue)]
        [int] $MaxDepth = [int]::MaxValue,

        [ValidateRange(0, [int]::MaxValue)]
        [int] $MinDepth = 0,

        # --- Directory exclusions (prune) ---
        [string[]] $Exclude,

        # --- Actions ---
        [switch] $Delete,

        # When combined with -Delete, also EMIT each item that was deleted,
        # so the caller can capture an audit trail. Standard PowerShell
        # convention for destructive cmdlets. The emitted FileInfo / DirectoryInfo
        # reference a now-deleted path - properties read at emission time
        # (Name, FullName, Length, LastWriteTime, Mode) remain valid.
        [switch] $PassThru,

        # --- Symlink handling ---
        [switch] $FollowSymlinks,

        # --- Output format (mutually exclusive: pick at most one of FullPath / LongList) ---
        [switch] $FullPath,

        [Alias('Ls')]
        [switch] $LongList,

        [switch] $ShowOwner,

        # Display unit for the Length column when -LongList is in effect.
        # Default 'Bytes' preserves numeric output; other values produce
        # formatted strings with an IEC binary-prefix suffix.
        [ValidateSet('Bytes', 'KiB', 'MiB', 'GiB', 'TiB', 'Auto')]
        [string] $SizeUnit = 'Bytes',

        # When set, every size-reporting feature uses ON-DISK ALLOCATION
        # instead of logical (apparent) file content size. Affects -Size,
        # -LongList Length, -SortBy Length, -DirectoryTotals, and
        # -Summary TotalBytes. Default = off (logical bytes).
        # -Empty is intentionally NOT affected - it always tests logical
        # Length to match the natural meaning of "empty file" and GNU find
        # -empty parity. See .NOTES > APPARENT SIZE vs ALLOCATED SIZE.
        [switch] $AllocatedSize,

        # When -AllocatedSize is set, additionally sum all alternate data
        # streams (ADS) per file, not just the main stream. Default = off
        # (main stream only). Has no effect without -AllocatedSize.
        [switch] $IncludeStreams,

        # Append a summary record at the end of the output stream showing
        # totals (item / file / dir / symlink counts, total bytes).
        [switch] $Summary,

        # Emit ONLY the summary record - suppress per-item output entirely.
        # Implies -Summary.
        [switch] $SummaryOnly,

        # When emitting a directory in -LongList view, fill its Length column
        # with the recursive byte-total of all files under it (du semantics).
        # Implies -LongList.
        [Alias('DirTotals')]
        [switch] $DirectoryTotals,

        # Sort the output. Sort operates on the underlying FileSystemInfo
        # properties so the comparison is always type-aware (strings, numbers,
        # DateTime), even when the displayed form is a formatted string.
        [ValidateSet('Name','FullName','Length','LastWriteTime',
                     'CreationTime','LastAccessTime','Extension',
                     'Mode','Owner','Type')]
        [string] $SortBy,

        # Sort direction. Both long and short aliases are accepted.
        [ValidateSet('Ascending','Asc','Descending','Desc')]
        [string] $SortOrder = 'Ascending',

        # Cap the number of items returned to the first N. Mutually exclusive
        # with -Last. Without -SortBy, this early-terminates the traversal as
        # soon as N items have been emitted - O(1) memory and minimal I/O.
        # With -SortBy, the full result set is still buffered for sorting,
        # then truncated to N (use the streaming workaround in NOTES for
        # bounded memory on enormous trees).
        [int] $First = 0,

        # Mirror of -First: keep only the last N items. Without -SortBy,
        # uses a sliding-window queue so memory stays bounded at N. With
        # -SortBy, takes the last N from the sorted result.
        [int] $Last = 0,

        # Soft threshold for warning when the sort buffer crosses N items.
        # Set to 0 to silence the warning. Default 100,000 gives a heads-up
        # before memory becomes a problem on very large trees.
        [int] $MaxBufferItems = 100000
    )

    # =========================================================================
    #  Pipeline support.
    #  -Path is ValueFromPipeline so callers can compose Find-Item into
    #  larger pipelines (Get-ChildItem | Find-Item, 'path1','path2' | Find-Item,
    #  etc.). The process block accumulates piped paths into a list; the end
    #  block does all the actual work against the final path set.
    # =========================================================================
    begin {
        $pipedPaths = [System.Collections.Generic.List[string]]::new()
        $pathWasBound = $PSBoundParameters.ContainsKey('Path')
    }

    process {
        # Collect each piped path (or the parameter-bound array, exactly once).
        if ($null -ne $Path) {
            foreach ($p in $Path) { $pipedPaths.Add($p) }
        }
    }

    end {

    # Resolve final path set. If anything came through the pipeline OR the
    # parameter was bound, use the accumulated list; otherwise fall back to
    # the default '.'. The accumulation deduplicates 'default + piped' weirdness.
    if ($pipedPaths.Count -gt 0) {
        $Path = $pipedPaths.ToArray()
    }
    elseif (-not $pathWasBound) {
        $Path = @('.')
    }

    # -------------------------------------------------------------------------
    #  Output-format validation. -FullPath and -LongList are mutually exclusive
    #  (they produce different shapes). -Owner without -LongList implicitly
    #  enables -LongList, since an owner column makes no sense in isolation.
    # -------------------------------------------------------------------------
    if ($FullPath -and $LongList) {
        $PSCmdlet.ThrowTerminatingError(
            [System.Management.Automation.ErrorRecord]::new(
                [System.ArgumentException]::new(
                    "-FullPath and -LongList are mutually exclusive. Pick one."),
                'ConflictingOutputFormat',
                [System.Management.Automation.ErrorCategory]::InvalidArgument,
                $null))
    }
    if ($ShowOwner -and -not $LongList) { $LongList = $true }
    if ($SizeUnit -ne 'Bytes' -and -not $LongList) { $LongList = $true }
    if ($DirectoryTotals -and -not $LongList) { $LongList = $true }
    if ($SummaryOnly -and -not $Summary) { $Summary = $true }

    # -DirectoryTotals implicitly restricts to directories (matches GNU du's
    # default: 'du /path' shows only directory totals - files require -a).
    # If the user explicitly passed -Type, their choice wins.
    if ($DirectoryTotals -and -not $PSBoundParameters.ContainsKey('Type')) {
        $Type = @('Directory')
    }

    # -First and -Last are mutually exclusive (semantically conflict).
    if ($First -gt 0 -and $Last -gt 0) {
        $PSCmdlet.ThrowTerminatingError(
            [System.Management.Automation.ErrorRecord]::new(
                [System.ArgumentException]::new(
                    "-First and -Last are mutually exclusive. Pick one."),
                'ConflictingTakeLimit',
                [System.Management.Automation.ErrorCategory]::InvalidArgument,
                $null))
    }

    # -------------------------------------------------------------------------
    #  Pre-parse filter specs (done once, not per item)
    # -------------------------------------------------------------------------

    $parsedSize = $null
    if ($Size) {
        if ($Size -notmatch '^([+\-]?)(\d+(?:\.\d+)?)([ckMG]?)$') {
            $PSCmdlet.ThrowTerminatingError(
                [System.Management.Automation.ErrorRecord]::new(
                    [System.ArgumentException]::new(
                        "Invalid -Size '$Size'. Expected [+|-]<n>[c|k|M|G]."),
                    'InvalidSizeSpec',
                    [System.Management.Automation.ErrorCategory]::InvalidArgument,
                    $Size))
        }
        $sizeSign  = $Matches[1]    # '', '+', or '-'
        $sizeN     = [double]$Matches[2]
        $sizeBytes = [long]$(switch ($Matches[3]) {
            'c'     { $sizeN }
            'k'     { $sizeN * 1024 }
            'M'     { $sizeN * 1024 * 1024 }
            'G'     { $sizeN * 1024 * 1024 * 1024 }
            default { $sizeN * 512 }
        })
        $parsedSize = @{ Sign = $sizeSign; Bytes = $sizeBytes }
    }

    function ParseTimeSpec([string] $spec, [string] $paramName) {
        # Extract optional leading sign, leave the rest to interpret as either
        # a numeric day count or an absolute date / date-time.
        $sign = ''
        $rest = $spec
        if ($spec -match '^([+\-])(.+)$') {
            $sign = $Matches[1]
            $rest = $Matches[2]
        }

        # Try numeric with optional unit suffix (m=minutes, h=hours, d=days,
        # w=weeks). Bare numeric (no suffix) is days for backward compatibility
        # and GNU find parity (-mtime is in days).
        #   -LastWriteTime -5m       last 5 minutes
        #   -LastWriteTime -2h       last 2 hours
        #   -LastWriteTime +7d       older than 7 days (explicit unit)
        #   -LastWriteTime -2w       last 2 weeks
        if ($rest -match '^(\d+(?:\.\d+)?)([mhdw])?$') {
            $n = [double]::Parse(
                $Matches[1],
                [System.Globalization.CultureInfo]::InvariantCulture)
            $unit = if ($Matches[2]) { $Matches[2] } else { 'd' }
            $days = switch ($unit) {
                'm' { $n / 1440.0 }   # 24 * 60 minutes per day
                'h' { $n / 24.0 }     # 24 hours per day
                'w' { $n * 7.0 }      # 7 days per week
                default { $n }         # 'd' or default
            }
            return @{ Mode = 'Days'; Sign = $sign; Days = $days }
        }

        # Otherwise try absolute date / date-time. Accept any culture-recognised
        # format (e.g. 2026-01-15, 01/15/2026, 2026-01-15T14:30:00, 'Jan 15 2026').
        [datetime] $dt = [datetime]::MinValue
        if ([datetime]::TryParse($rest, [ref] $dt)) {
            # If the input has any time component, treat 'no sign' as 'exact
            # second match'; otherwise treat it as 'this calendar day'.
            $hasTime = $rest -match '\d:\d' -or $rest -match '[Tt]\d'
            return @{ Mode = 'DateTime'; Sign = $sign; DateTime = $dt; HasTime = $hasTime }
        }

        throw "Invalid -$paramName '$spec'. Expected one of:`n" +
              "  [+|-]<n>            numeric days  (e.g. -7, +30, 1.5)`n" +
              "  [+|-]<date>         calendar date (e.g. 2026-01-15, 01/15/2026)`n" +
              "  [+|-]<date-time>    timestamp     (e.g. '2026-01-15 14:30:00', 2026-01-15T14:30)"
    }

    try {
        $parsedLastWrite  = if ($LastWriteTime)  { ParseTimeSpec $LastWriteTime  'LastWriteTime'  } else { $null }
        $parsedLastAccess = if ($LastAccessTime) { ParseTimeSpec $LastAccessTime 'LastAccessTime' } else { $null }
        $parsedCreation   = if ($CreationTime)   { ParseTimeSpec $CreationTime   'CreationTime'   } else { $null }
    }
    catch {
        $PSCmdlet.ThrowTerminatingError(
            [System.Management.Automation.ErrorRecord]::new(
                $_.Exception, 'InvalidTimeSpec',
                [System.Management.Automation.ErrorCategory]::InvalidArgument, $null))
    }

    $newerRef = $null
    if ($Newer) {
        $newerRef = Get-Item -LiteralPath $Newer -ErrorAction Stop
    }

    # ---- Pre-compile regex patterns with an explicit match timeout. ----
    # PowerShell's -match / -imatch operators use .NET Regex with NO timeout
    # by default, which means a pathological pattern like '(a+)+$' against a
    # long input causes exponential backtracking and a process hang (ReDoS).
    # Compiling each pattern once with a 5s timeout caps the worst case at
    # 5s per item rather than potentially forever.
    $regexTimeout = [TimeSpan]::FromSeconds(5)
    $compileRx = {
        param([string[]] $patterns, [System.Text.RegularExpressions.RegexOptions] $opts)
        $patterns | ForEach-Object {
            [System.Text.RegularExpressions.Regex]::new($_, $opts, $regexTimeout)
        }
    }
    # Explicit if/else assignments here (NOT '$x = if (...) {...} else {...}')
    # for the same pipeline-enumeration reason documented for $emitBuffer below.
    if ($Regex)     { $compiledRegex     = & $compileRx $Regex     'None'       } else { $compiledRegex     = $null }
    if ($IRegex)    { $compiledIRegex    = & $compileRx $IRegex    'IgnoreCase' } else { $compiledIRegex    = $null }
    if ($NotRegex)  { $compiledNotRegex  = & $compileRx $NotRegex  'None'       } else { $compiledNotRegex  = $null }
    if ($NotIRegex) { $compiledNotIRegex = & $compileRx $NotIRegex 'IgnoreCase' } else { $compiledNotIRegex = $null }

    $now = [datetime]::Now

    # -------------------------------------------------------------------------
    #  Helper: evaluate a time spec against a datetime.
    #  Two modes:
    #    Days     - numeric age in days; '+' = older, '-' = newer (Linux find)
    #    DateTime - absolute date/time;  '+' = after,  '-' = before
    #               (no sign = same calendar day for date-only input, or
    #                same second for date-time input)
    # -------------------------------------------------------------------------
    function TestTimeSpec([datetime] $timestamp, [hashtable] $spec) {
        if ($spec.Mode -eq 'Days') {
            $ageDays = ($now - $timestamp).TotalHours / 24.0
            switch ($spec.Sign) {
                '+'     { return $ageDays -gt $spec.Days }
                '-'     { return $ageDays -lt $spec.Days }
                default { return [Math]::Floor($ageDays) -eq [Math]::Floor($spec.Days) }
            }
        }
        # Mode = DateTime
        switch ($spec.Sign) {
            '+'     { return $timestamp -gt $spec.DateTime }
            '-'     { return $timestamp -lt $spec.DateTime }
            default {
                if ($spec.HasTime) {
                    # Same second granularity (file timestamps are sub-second,
                    # so an exact-tick equality is almost never useful).
                    $a = [datetime]::new($timestamp.Year, $timestamp.Month, $timestamp.Day,
                                         $timestamp.Hour, $timestamp.Minute, $timestamp.Second)
                    $b = [datetime]::new($spec.DateTime.Year, $spec.DateTime.Month, $spec.DateTime.Day,
                                         $spec.DateTime.Hour, $spec.DateTime.Minute, $spec.DateTime.Second)
                    return $a -eq $b
                }
                else {
                    return $timestamp.Date -eq $spec.DateTime.Date
                }
            }
        }
    }

    # -------------------------------------------------------------------------
    #  Allocation cache and helpers (used only when -AllocatedSize is set).
    #
    #  $allocCache maps full path -> on-disk allocated bytes for that file
    #  (main stream + optional alternate streams, with cluster floor applied
    #  to non-empty resident files). Shared across -Size, -DirectoryTotals,
    #  -Summary, -LongList, -SortBy Length, so each file pays at most one
    #  GetCompressedFileSize per invocation.
    #
    #  $clusterCache maps a volume root (e.g. "C:\") to its cluster size in
    #  bytes (one GetDiskFreeSpace per unique volume per invocation).
    # -------------------------------------------------------------------------
    $allocCache   = @{}
    $clusterCache = @{}

    function GetClusterSizeFor([string] $path) {
        $root = [System.IO.Path]::GetPathRoot($path)
        if ([string]::IsNullOrEmpty($root)) { return [long]4096 }
        if ($clusterCache.ContainsKey($root)) { return $clusterCache[$root] }

        $size = try {
            $sectorsPerCluster = [uint32]0
            $bytesPerSector    = [uint32]0
            $freeClusters      = [uint32]0
            $totalClusters     = [uint32]0
            $ok = [FindItem.Native]::GetDiskFreeSpace(
                $root, [ref]$sectorsPerCluster, [ref]$bytesPerSector,
                [ref]$freeClusters, [ref]$totalClusters)
            if ($ok) { [long]($sectorsPerCluster * $bytesPerSector) }
            else     { [long]4096 }   # fallback: typical NTFS cluster size
        }
        catch { [long]4096 }

        $clusterCache[$root] = $size
        $size
    }

    function GetStreamsAllocation([string] $path) {
        # Sum the allocated bytes of every ALTERNATE data stream (not the
        # main stream - that is counted separately in GetCachedAllocation).
        # Same compressed-bytes-then-cluster-round logic as the main stream.
        $sum  = [long]0
        $data = New-Object FindItem.Native+WIN32_FIND_STREAM_DATA
        $h    = [FindItem.Native]::FindFirstStreamW(
            $path, [FindItem.Native]::FindStreamInfoStandard, [ref]$data, 0)
        if ($h -eq [FindItem.Native]::INVALID_HANDLE_VALUE) { return $sum }
        try {
            do {
                # Main unnamed stream comes back as '::$DATA' - skip it.
                if ($data.StreamName -eq '::$DATA') { continue }
                # Skip empty alternate streams (no bytes contributed).
                if ($data.StreamSize -le 0) { continue }

                $streamPath = $path + $data.StreamName
                $hi = [uint32]0
                $lo = [FindItem.Native]::GetCompressedFileSize($streamPath, [ref]$hi)
                if ($lo -eq [FindItem.Native]::INVALID_FILE_SIZE) {
                    # Can't query this stream's compressed size; use logical.
                    $sum += RoundUpToCluster ([long]$data.StreamSize) $path
                }
                else {
                    $compressedBytes = ([long]$hi -shl 32) -bor [long]$lo
                    if ($compressedBytes -eq 0) {
                        # Resident alternate stream
                        $sum += GetClusterSizeFor $path
                    }
                    else {
                        $sum += RoundUpToCluster $compressedBytes $path
                    }
                }
            } while ([FindItem.Native]::FindNextStreamW($h, [ref]$data))
        }
        finally { [void] [FindItem.Native]::FindClose($h) }
        $sum
    }

    # Helper: round a byte count UP to the next cluster boundary on the
    # file's volume. Matches Explorer's "Size on disk" calculation:
    # non-empty files allocate at least one cluster, and cluster boundaries
    # apply regardless of compression / sparse storage.
    function RoundUpToCluster([long] $bytes, [string] $path) {
        if ($bytes -le 0) { return [long]0 }
        $cluster = GetClusterSizeFor $path
        [long]([Math]::Ceiling([double]$bytes / [double]$cluster)) * $cluster
    }

    function GetCachedAllocation([System.IO.FileInfo] $item) {
        if ($allocCache.ContainsKey($item.FullName)) {
            return $allocCache[$item.FullName]
        }

        $bytes = try {
            if ($item.Length -eq 0) {
                # Truly empty: no clusters allocated, period.
                [long]0
            }
            else {
                $hi = [uint32]0
                $lo = [FindItem.Native]::GetCompressedFileSize($item.FullName, [ref]$hi)

                # 'Compressed bytes' from this API is:
                #   - normal files       : same as logical Length
                #   - sparse files       : just the data bytes (excludes holes)
                #   - NTFS-compressed    : the compressed byte count
                #   - resident-in-MFT    : 0
                # In all cases we ROUND UP to the cluster boundary to match
                # the value Explorer reports as "Size on disk".
                $compressedBytes = if ($lo -eq [FindItem.Native]::INVALID_FILE_SIZE) {
                    # Win32 error (access denied, locked file). Fall back
                    # to logical Length so cluster rounding still applies.
                    [long]$item.Length
                }
                else {
                    ([long]$hi -shl 32) -bor [long]$lo
                }

                if ($compressedBytes -eq 0) {
                    # Resident file or all-holes sparse: still occupies
                    # one cluster minimum (Fork 1 = B).
                    GetClusterSizeFor $item.FullName
                }
                else {
                    RoundUpToCluster $compressedBytes $item.FullName
                }
            }
        }
        catch { [long]$item.Length }

        # Fork 2 = C: add alternate-stream allocations only when opted in.
        if ($IncludeStreams) {
            $bytes += GetStreamsAllocation $item.FullName
        }

        $allocCache[$item.FullName] = $bytes
        $bytes
    }

    # The single helper called from every site that asks "how big is this
    # item?". Returns logical bytes by default, allocated bytes when
    # -AllocatedSize is set. Directories have no inherent size and return 0.
    function GetSizeBytes([System.IO.FileSystemInfo] $item) {
        if ($item -isnot [System.IO.FileInfo]) { return [long]0 }
        if ($AllocatedSize) { return GetCachedAllocation $item }
        return [long]$item.Length
    }

    # -------------------------------------------------------------------------
    #  Helper: true when item has the ReparsePoint attribute
    # -------------------------------------------------------------------------
    function IsReparsePoint([System.IO.FileSystemInfo] $item) {
        ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
    }

    # -------------------------------------------------------------------------
    #  ACL cache. Get-Acl is 50-200ms per file; any feature that needs ACL
    #  info (-ShowOwner, -SortBy Owner, -ReadableBy/-WritableBy/-AppendableBy/
    #  -ExecutableBy) goes through GetCachedAcl so we pay the cost once per
    #  item per Find-Item invocation. Returns $null on access denied; that
    #  null result is itself cached to avoid re-trying.
    # -------------------------------------------------------------------------
    $aclCache = @{}
    function GetCachedAcl([System.IO.FileSystemInfo] $item) {
        $key = $item.FullName
        if ($aclCache.ContainsKey($key)) { return $aclCache[$key] }
        try {
            $acl = Get-Acl -LiteralPath $key -ErrorAction Stop
        }
        catch {
            $acl = $null
        }
        $aclCache[$key] = $acl
        return $acl
    }

    # -------------------------------------------------------------------------
    #  Set of file extensions Windows treats as directly executable. Built
    #  from $env:PATHEXT plus a few PowerShell-relevant additions. Used by
    #  -ExecutableBy: a file has to have an executable extension AND an ACE
    #  granting ExecuteFile rights to be considered "executable".
    # -------------------------------------------------------------------------
    $executableExtensions = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    foreach ($e in ($env:PATHEXT -split ';')) {
        $e = $e.Trim()
        if ($e) { [void] $executableExtensions.Add($e) }
    }
    # PowerShell scripts and modules are executables for our purposes too.
    foreach ($e in '.PS1','.PSM1','.PSD1') { [void] $executableExtensions.Add($e) }

    function HasExecutableExtension([System.IO.FileSystemInfo] $item) {
        if ($item -isnot [System.IO.FileInfo]) { return $false }
        $executableExtensions.Contains($item.Extension)
    }

    # -------------------------------------------------------------------------
    #  Test an item's DACL: does ANY listed principal have the requested
    #  FileSystemRights granted via an Allow ACE?
    #
    #  Takes SEPARATE file and directory rights masks because the same bit
    #  values have different meanings on files vs directories:
    #    bit 1  ReadData     <==>  ListDirectory
    #    bit 2  WriteData    <==>  CreateFiles
    #    bit 4  AppendData   <==>  CreateDirectories
    #    bit 32 ExecuteFile  <==>  Traverse
    #  Additionally, directories have a unique 'DeleteSubdirectoriesAndFiles'
    #  right (bit 64) that has no file analog. Callers pass each mask
    #  shaped for its type so e.g. "writable directory" can include the
    #  broader concept of "can change directory contents".
    #
    #  Match modes:
    #    any-bit (default)  - ACE matches if it grants ANY bit in the mask.
    #                         Correct for atomic single-bit rights and for
    #                         "OR of related rights" masks.
    #    -RequireAllBits    - ACE matches only if it grants ALL bits in
    #                         the mask. Required for composite rights like
    #                         Modify or FullControl, where the question is
    #                         "does the principal have at least this LEVEL
    #                         of access" rather than "is this single bit set".
    #
    #  This is a LITERAL-ACL check, not a Windows effective-access check.
    #  See NOTES > PERMISSION-FILTER SEMANTICS.
    # -------------------------------------------------------------------------
    function TestAclAccess(
        [System.IO.FileSystemInfo] $item,
        [string[]] $principals,
        [System.Security.AccessControl.FileSystemRights] $fileMask,
        [System.Security.AccessControl.FileSystemRights] $dirMask,
        [switch] $RequireAllBits)
    {
        $acl = GetCachedAcl $item
        if ($null -eq $acl) { return $false }  # access denied or unreadable

        $isDir    = $item -is [System.IO.DirectoryInfo]
        $required = if ($isDir) { [int] $dirMask } else { [int] $fileMask }

        foreach ($ace in $acl.Access) {
            if ($ace.AccessControlType -ne 'Allow') { continue }
            $aceRights = [int] $ace.FileSystemRights
            if ($RequireAllBits) {
                # ACE must grant EVERY bit of the requested capability.
                if (($aceRights -band $required) -ne $required) { continue }
            }
            else {
                # ACE must grant AT LEAST ONE bit of the requested capability.
                if (($aceRights -band $required) -eq 0) { continue }
            }
            $aceName = $ace.IdentityReference.Value
            foreach ($p in $principals) {
                if ($aceName -ilike $p) { return $true }
            }
        }
        return $false
    }

    # -------------------------------------------------------------------------
    #  Helper: test a value against a list of pre-compiled Regex objects,
    #  catching RegexMatchTimeoutException so a single bad pattern can't
    #  hang the traversal. Returns $true if ANY pattern matches.
    # -------------------------------------------------------------------------
    function MatchAnyRegex([string] $value, $compiled, [string] $paramName) {
        foreach ($rx in $compiled) {
            try {
                if ($rx.IsMatch($value)) { return $true }
            }
            catch [System.Text.RegularExpressions.RegexMatchTimeoutException] {
                Write-Warning ("Find-Item: -$paramName pattern '{0}' timed " +
                    "out matching '{1}'. Skipping this pattern for this item; " +
                    "consider rewriting to avoid catastrophic backtracking." `
                    -f $rx.ToString(), $value)
            }
        }
        return $false
    }

    # -------------------------------------------------------------------------
    #  Helper: delete an item safely, distinguishing reparse points from
    #  real directories. Remove-Item -Recurse on a junction or directory
    #  symlink has historically followed the link and destroyed the TARGET's
    #  contents (Windows PowerShell 5.1; also some PowerShell 7 edge cases).
    #  Using .NET's Directory.Delete(path, recursive=$false) for reparse-
    #  point directories deletes the link entry alone, leaving the target
    #  untouched.
    #
    #  We call .Refresh() immediately before the attribute check to minimize
    #  the TOCTOU window between TestItem (which may have happened earlier)
    #  and the delete action.
    # -------------------------------------------------------------------------
    function SafeDelete([System.IO.FileSystemInfo] $item) {
        try { $item.Refresh() } catch { }
        $isLink = IsReparsePoint $item

        try {
            if ($isLink) {
                if ($item -is [System.IO.DirectoryInfo]) {
                    # Link entry only; never follows into target.
                    [System.IO.Directory]::Delete($item.FullName, $false)
                }
                else {
                    [System.IO.File]::Delete($item.FullName)
                }
            }
            elseif ($item -is [System.IO.DirectoryInfo]) {
                Remove-Item -LiteralPath $item.FullName -Recurse -Force -ErrorAction Stop
            }
            else {
                Remove-Item -LiteralPath $item.FullName -Force -ErrorAction Stop
            }
        }
        catch {
            Write-Warning ("Find-Item: could not delete '{0}': {1}" -f
                $item.FullName, $_.Exception.Message)
        }
    }

    # -------------------------------------------------------------------------
    #  Helper: format a byte count per the -SizeUnit selection.
    #  Returns:
    #    - the original [long] when unit = Bytes        (numeric, no suffix)
    #    - a formatted [string] like "1.50 MiB"         (every other unit)
    #    - $null when bytes is $null (e.g. for directories)
    # -------------------------------------------------------------------------
    function FormatSize($bytes, [string] $unit) {
        if ($null -eq $bytes) { return $null }
        switch ($unit) {
            'Bytes' { return $bytes }
            'KiB'   { return ('{0:N2} KiB' -f ($bytes / 1KB)) }
            'MiB'   { return ('{0:N2} MiB' -f ($bytes / 1MB)) }
            'GiB'   { return ('{0:N2} GiB' -f ($bytes / 1GB)) }
            'TiB'   { return ('{0:N2} TiB' -f ($bytes / 1TB)) }
            'Auto'  {
                if     ($bytes -lt 1KB) { return "$bytes B" }
                elseif ($bytes -lt 1MB) { return ('{0:N2} KiB' -f ($bytes / 1KB)) }
                elseif ($bytes -lt 1GB) { return ('{0:N2} MiB' -f ($bytes / 1MB)) }
                elseif ($bytes -lt 1TB) { return ('{0:N2} GiB' -f ($bytes / 1GB)) }
                else                    { return ('{0:N2} TiB' -f ($bytes / 1TB)) }
            }
        }
    }

    # -------------------------------------------------------------------------
    #  Helper: shape the output according to -FullPath / -LongList / default.
    # -------------------------------------------------------------------------
    function FormatOutput([System.IO.FileSystemInfo] $item, $recursiveBytes = $null) {
        if ($LongList) {
            # GetSizeBytes returns logical OR allocated bytes per -AllocatedSize.
            $len = if ($item -is [System.IO.FileInfo]) {
                FormatSize (GetSizeBytes $item) $SizeUnit
            }
            elseif ($null -ne $recursiveBytes) {
                FormatSize $recursiveBytes $SizeUnit
            }
            else { $null }
            if ($ShowOwner) {
                # Routed through the per-invocation ACL cache so we don't pay
                # Get-Acl twice when -SortBy Owner or a permission filter
                # already fetched it for this item.
                $acl = GetCachedAcl $item
                $ownerName = if ($null -ne $acl) { $acl.Owner } else { '?' }
                $obj = [pscustomobject][ordered]@{
                    Mode          = $item.Mode
                    Owner         = $ownerName
                    Length        = $len
                    LastWriteTime = $item.LastWriteTime
                    FullName      = $item.FullName
                }
                $obj.PSObject.TypeNames.Insert(0, 'FindItem.LongListEntryWithOwner')
                return $obj
            }
            $obj = [pscustomobject][ordered]@{
                Mode          = $item.Mode
                Length        = $len
                LastWriteTime = $item.LastWriteTime
                FullName      = $item.FullName
            }
            $obj.PSObject.TypeNames.Insert(0, 'FindItem.LongListEntry')
            return $obj
        }
        if ($FullPath) { return $item.FullName }
        return $item
    }

    # -------------------------------------------------------------------------
    #  Helper: true when all active filters match the item
    # -------------------------------------------------------------------------
    function TestItem([System.IO.FileSystemInfo] $item) {
        $isDir  = $item -is [System.IO.DirectoryInfo]
        $isLink = IsReparsePoint $item

        # --- Type test (array = OR; item must match at least one listed type) ---
        # Plain if/elseif rather than a switch-with-scriptblock-conditions:
        # switch evaluates each scriptblock condition for every item, which
        # is measurably slower in the hot path. if/elseif short-circuits.
        if ($Type) {
            $pass = $false
            foreach ($t in $Type) {
                if ($t -eq 'f' -or $t -eq 'File') {
                    if (-not $isDir -and -not $isLink) { $pass = $true; break }
                }
                elseif ($t -eq 'd' -or $t -eq 'Directory') {
                    if ($isDir -and -not $isLink) { $pass = $true; break }
                }
                elseif ($t -eq 'l' -or $t -eq 'SymbolicLink') {
                    if ($isLink) { $pass = $true; break }
                }
            }
            if (-not $pass) { return $false }
        }

        # --- Positive name/path tests: pass if ANY listed pattern matches ---
        if ($Name) {
            $hit = $false
            foreach ($p in $Name)  { if ($item.Name -like  $p) { $hit = $true; break } }
            if (-not $hit) { return $false }
        }
        if ($IName) {
            $hit = $false
            foreach ($p in $IName) { if ($item.Name -ilike $p) { $hit = $true; break } }
            if (-not $hit) { return $false }
        }
        # Regex tests use pre-compiled patterns with a match timeout (ReDoS
        # defense - see the pre-parse block above).
        if ($compiledRegex)  {
            if (-not (MatchAnyRegex $item.FullName $compiledRegex 'Regex'))   { return $false }
        }
        if ($compiledIRegex) {
            if (-not (MatchAnyRegex $item.FullName $compiledIRegex 'IRegex')) { return $false }
        }

        # --- Negation tests: REJECT if ANY listed pattern matches ---
        if ($NotName)  { foreach ($p in $NotName)  { if ($item.Name -like   $p) { return $false } } }
        if ($NotIName) { foreach ($p in $NotIName) { if ($item.Name -ilike  $p) { return $false } } }
        if ($compiledNotRegex)  {
            if (MatchAnyRegex $item.FullName $compiledNotRegex  'NotRegex')  { return $false }
        }
        if ($compiledNotIRegex) {
            if (MatchAnyRegex $item.FullName $compiledNotIRegex 'NotIRegex') { return $false }
        }

        # Size: only files have a meaningful Length on Windows, so a -Size
        # filter implicitly excludes directories and reparse points.
        # GetSizeBytes returns logical OR allocated bytes per -AllocatedSize.
        if ($parsedSize) {
            if ($item -isnot [System.IO.FileInfo]) { return $false }
            $len = GetSizeBytes $item
            $pass = switch ($parsedSize.Sign) {
                '+'     { $len -gt $parsedSize.Bytes }
                '-'     { $len -lt $parsedSize.Bytes }
                default { $len -eq $parsedSize.Bytes }
            }
            if (-not $pass) { return $false }
        }

        # Time filters
        if ($parsedLastWrite  -and -not (TestTimeSpec $item.LastWriteTime  $parsedLastWrite))  { return $false }
        if ($parsedLastAccess -and -not (TestTimeSpec $item.LastAccessTime $parsedLastAccess)) { return $false }
        if ($parsedCreation   -and -not (TestTimeSpec $item.CreationTime   $parsedCreation))   { return $false }

        # Newer
        if ($newerRef -and $item.LastWriteTime -le $newerRef.LastWriteTime) { return $false }

        # --- Empty filter: 0-byte files OR directories with no entries.
        #     For directories we use EnumerateFileSystemInfos and short-circuit
        #     on the first entry; we never materialise the full child list. ---
        if ($Empty) {
            if ($item -is [System.IO.FileInfo]) {
                if ($item.Length -ne 0) { return $false }
            }
            else {
                # Directory. Empty = enumerator yields zero entries.
                try {
                    $enumerator = [System.IO.DirectoryInfo]::new($item.FullName).EnumerateFileSystemInfos().GetEnumerator()
                    try {
                        if ($enumerator.MoveNext()) { return $false }
                    } finally { $enumerator.Dispose() }
                }
                catch {
                    # Access-denied or other; can't confirm emptiness, so skip.
                    return $false
                }
            }
        }

        # --- ACL-based access checks (Windows-native -perm equivalent).
        #     Placed after the cheap structural filters so an item is rejected
        #     by Type/Name/Size first - we only pay the Get-Acl cost (50-200ms
        #     per item) for survivors. Within an ACL check, the GetCachedAcl
        #     helper ensures the ACL is fetched at most once per item even when
        #     multiple ACL features (-ShowOwner, -SortBy Owner, multiple
        #     -*By filters) are combined.
        #
        #     LITERAL-ACL semantics: matches when the file's DACL grants the
        #     requested right to a listed principal via an Allow ACE. Does
        #     NOT evaluate effective access (no group expansion, no Deny
        #     precedence). See NOTES > PERMISSION-FILTER SEMANTICS. ---
        # Reusable masks (same bit values, different names per type - see
        # TestAclAccess). Each capability filter's mask covers ALL the
        # FileSystemRights bits that semantically grant that capability.
        $FSR = [System.Security.AccessControl.FileSystemRights]

        # READABLE: data-read OR metadata-read.
        #   Files : ReadData | ReadAttributes | ReadExtendedAttributes
        #   Dirs  : ListDirectory | ReadAttributes | ReadExtendedAttributes
        # ReadData and ListDirectory share bit 1, so the mask values are
        # identical between file and dir for the readable case.
        $fileReadableMask = $FSR::ReadData      -bor $FSR::ReadAttributes -bor $FSR::ReadExtendedAttributes
        $dirReadableMask  = $FSR::ListDirectory -bor $FSR::ReadAttributes -bor $FSR::ReadExtendedAttributes

        # WRITABLE: data-write OR metadata-write OR delete (destructive write).
        #   Files : WriteData | WriteAttributes | WriteExtendedAttributes | Delete
        #   Dirs  : CreateFiles | CreateDirectories | DeleteSubdirectoriesAndFiles
        #         | WriteAttributes | WriteExtendedAttributes | Delete
        # The dir mask is broader because a directory has more distinct ways
        # of being "modified" (create children, delete children, etc.).
        $fileWritableMask = $FSR::WriteData -bor $FSR::WriteAttributes -bor `
                            $FSR::WriteExtendedAttributes -bor $FSR::Delete
        $dirWritableMask  = $FSR::CreateFiles -bor $FSR::CreateDirectories -bor `
                            $FSR::DeleteSubdirectoriesAndFiles -bor `
                            $FSR::WriteAttributes -bor $FSR::WriteExtendedAttributes -bor `
                            $FSR::Delete

        if ($ReadableBy) {
            if (-not (TestAclAccess $item $ReadableBy $fileReadableMask $dirReadableMask)) {
                return $false
            }
        }
        if ($WritableBy) {
            if (-not (TestAclAccess $item $WritableBy $fileWritableMask $dirWritableMask)) {
                return $false
            }
        }
        if ($AppendableBy) {
            if (-not (TestAclAccess $item $AppendableBy $FSR::AppendData $FSR::CreateDirectories)) {
                return $false
            }
        }
        if ($ExecutableBy) {
            # Files: must have PATHEXT-style extension AND ExecuteFile granted.
            # Directories: just need Traverse granted (no extension check).
            if ($item -is [System.IO.FileInfo]) {
                if (-not (HasExecutableExtension $item)) { return $false }
            }
            if (-not (TestAclAccess $item $ExecutableBy $FSR::ExecuteFile $FSR::Traverse)) {
                return $false
            }
        }
        # --- Owner-based filtering (GNU find -user analog). Routed through
        #     the per-invocation ACL cache so combining -Owner with any other
        #     ACL feature (-ShowOwner, -SortBy Owner, -*By) pays Get-Acl once.
        if ($Owner -or $NotOwner) {
            $acl = GetCachedAcl $item
            if ($null -eq $acl) {
                # ACL unreadable; can't confirm owner. Treat as no-match for
                # inclusion, but pass for exclusion (we can't claim it MUST be
                # excluded if we don't know).
                if ($Owner) { return $false }
            }
            else {
                $ownerStr = $acl.Owner
                if ($Owner) {
                    $hit = $false
                    foreach ($p in $Owner) {
                        if ($ownerStr -ilike $p) { $hit = $true; break }
                    }
                    if (-not $hit) { return $false }
                }
                if ($NotOwner) {
                    foreach ($p in $NotOwner) {
                        if ($ownerStr -ilike $p) { return $false }
                    }
                }
            }
        }

        # Composite-rights filters require ALL bits of the named composite to
        # be granted - "principal has at least this level of access".
        if ($ModifiableBy) {
            if (-not (TestAclAccess $item $ModifiableBy $FSR::Modify $FSR::Modify -RequireAllBits)) {
                return $false
            }
        }
        if ($FullControlBy) {
            if (-not (TestAclAccess $item $FullControlBy $FSR::FullControl $FSR::FullControl -RequireAllBits)) {
                return $false
            }
        }

        # --- User scriptblock (Where-Object style). Placed last so all cheap
        #     structured tests have had a chance to short-circuit first. ---
        if ($Filter) {
            if (-not ($item | Where-Object $Filter)) { return $false }
        }

        return $true
    }

    # -------------------------------------------------------------------------
    #  Recursive traversal - returns $true when a directory was actually deleted
    #  (to prevent attempting to recurse into it afterwards)
    # -------------------------------------------------------------------------
    function Traverse([string] $dirPath, [int] $depth, [hashtable] $sizeRef) {
        # Byte total for everything under $dirPath is returned via $sizeRef.Value
        # (NOT via 'return') so it doesn't collide with the per-item emissions
        # that flow to the output stream. PowerShell unifies all function output
        # into a single stream, so 'return <value>' would commingle the byte
        # count with the FormatOutput objects we emit for each item.
        $local = [long]0

        try {
            # EnumerateFileSystemInfos returns IEnumerable<FileSystemInfo>
            # (lazy) rather than GetFileSystemInfos's eagerly-materialized
            # array. Directories with hundreds of thousands of entries no
            # longer allocate the whole array upfront, and combined with
            # -First N early-termination we can skip reading most of a
            # huge directory.
            $entries = [System.IO.DirectoryInfo]::new($dirPath).EnumerateFileSystemInfos()
        }
        catch {
            Write-Warning "Cannot access '$dirPath': $($_.Exception.Message)"
            $sizeRef.Value = $local
            return
        }

        foreach ($entry in $entries) {
            # Early-termination check for -First N. Set by Emit() after the
            # Nth item has shipped. Propagates upward through nested Traverse
            # calls via the early return. Flush accumulator first so the
            # caller's running byte total stays consistent.
            if ($emitState.StopWalk) { $sizeRef.Value = $local; return }

            $isDir  = $entry -is [System.IO.DirectoryInfo]
            $isLink = IsReparsePoint $entry

            # Prune excluded directories. Pruned subtrees do NOT contribute
            # to parent's recursive total (matches GNU du --exclude semantics).
            if ($isDir -and $Exclude) {
                $pruned = $false
                foreach ($pat in $Exclude) {
                    if ($entry.Name -ilike $pat) { $pruned = $true; break }
                }
                if ($pruned) { continue }
            }

            # Files contribute to the subtree byte total immediately.
            # GetSizeBytes returns logical OR allocated per -AllocatedSize.
            if (-not $isDir) { $local += GetSizeBytes $entry }

            $deleted = $false
            $deferDir = $DirectoryTotals -and $isDir

            # Depth gates:
            #   emitInRange  - is this depth in the user's display range?
            #   shouldRecurse - traverse children? Without -DirectoryTotals,
            #     MaxDepth caps recursion (for perf). With -DirectoryTotals,
            #     we always recurse so directory totals are accurate even
            #     when emission is capped (matches GNU du -d N semantics).
            $emitInRange   = ($depth -ge $MinDepth) -and ($depth -le $MaxDepth)
            $shouldRecurse = $DirectoryTotals -or ($depth -lt $MaxDepth)

            # PRE-order emission (files always; dirs only when not deferring).
            if (-not $deferDir) {
                if ($emitInRange -and (TestItem $entry)) {
                    TallyItem $entry
                    if ($Delete) {
                        if ($PSCmdlet.ShouldProcess($entry.FullName, 'Delete')) {
                            SafeDelete $entry
                            $deleted = $true
                            if ($PassThru -and -not $SummaryOnly) {
                                # Emit handles count-and-stop AND honours -SortBy
                                # buffering / -Last sliding-window when active.
                                Emit $entry
                            }
                            else {
                                # No emission - count manually for -First N early-term.
                                BumpEmitCount
                            }
                        }
                    }
                    elseif (-not $SummaryOnly) {
                        Emit $entry
                    }
                }
            }

            # Recurse into directories (skip if just deleted, skip non-followed links).
            # Allocate $childRef only when we're actually going to recurse - files
            # (the majority of items) skip this allocation entirely.
            $childBytes = [long]0
            if ($isDir -and -not $deleted -and $shouldRecurse -and (-not $isLink -or $FollowSymlinks)) {
                $childRef = @{ Value = [long]0 }
                Traverse $entry.FullName ($depth + 1) $childRef
                $childBytes = $childRef.Value
                $local += $childBytes
            }

            # POST-order emission for directories when -DirectoryTotals is set.
            if ($deferDir) {
                if ($emitInRange -and (TestItem $entry)) {
                    TallyItem $entry
                    if ($Delete) {
                        if ($PSCmdlet.ShouldProcess($entry.FullName, 'Delete')) {
                            SafeDelete $entry
                            if ($PassThru -and -not $SummaryOnly) {
                                Emit $entry $childBytes
                            }
                            else {
                                BumpEmitCount
                            }
                        }
                    }
                    elseif (-not $SummaryOnly) {
                        Emit $entry $childBytes
                    }
                }
            }
        }

        $sizeRef.Value = $local
    }

    # -------------------------------------------------------------------------
    #  Sort buffering. When -SortBy is set, we cannot stream output as we
    #  traverse - we have to collect everything, sort it, and only then emit.
    #  Without -SortBy, $emitBuffer stays $null and the streaming path is used.
    # -------------------------------------------------------------------------
    # NOTE: must use explicit if/else with separate assignments here, NOT
    #   $emitBuffer = if ($SortBy) { [List[hashtable]]::new() } else { $null }
    # PowerShell's pipeline semantics enumerate the (initially empty) List
    # as it flows through the 'if' expression, so the surrounding assignment
    # ends up capturing $null. Each-branch assignment avoids the pipeline.
    if ($SortBy) {
        $emitBuffer = [System.Collections.Generic.List[hashtable]]::new()
    }
    else {
        $emitBuffer = $null
    }

    # Sliding-window queue for -Last N when there's NO -SortBy. We just keep
    # the most recently emitted N items in a fixed-size queue (O(N) memory
    # regardless of total matches) and flush them at the end.
    if ($Last -gt 0 -and -not $SortBy) {
        $lastQueue = [System.Collections.Generic.Queue[hashtable]]::new()
    }
    else {
        $lastQueue = $null
    }

    # Mutable counters / flags accessed from nested functions. Wrapped in a
    # hashtable so Emit can mutate them (Pwsh assignment in a nested function
    # would otherwise create a new local). Also used to early-terminate the
    # traversal when -First N is satisfied.
    $emitState = @{
        EmittedCount = 0
        StopWalk     = $false
        WarnedBuffer = $false
    }

    # Sort-key extractor: returns the value to sort on for a given column.
    # Sorting always uses the underlying FileSystemInfo properties (not the
    # displayed/formatted ones), so the result is type-correct regardless of
    # -SizeUnit / -LongList / etc.
    function GetSortKey($item, $recursiveBytes, [string] $column) {
        switch ($column) {
            'Name'           { return $item.Name }
            'FullName'       { return $item.FullName }
            'Extension'      { return $item.Extension }
            'Mode'           { return $item.Mode }
            'LastWriteTime'  { return $item.LastWriteTime }
            'CreationTime'   { return $item.CreationTime }
            'LastAccessTime' { return $item.LastAccessTime }
            'Length' {
                # For files: logical or allocated bytes (GetSizeBytes picks
                # per -AllocatedSize). For directories with -DirectoryTotals:
                # the recursive total. Otherwise: 0.
                if ($item -is [System.IO.FileInfo])    { return GetSizeBytes $item }
                elseif ($null -ne $recursiveBytes)     { return [long] $recursiveBytes }
                else                                   { return [long] 0 }
            }
            'Type' {
                # Group directories together, then symlinks, then files.
                if ($item -is [System.IO.DirectoryInfo]) { return 'Directory' }
                elseif (IsReparsePoint $item)            { return 'SymbolicLink' }
                else                                     { return 'File' }
            }
            'Owner' {
                # ACL lookup - slow per item but routed through the per-
                # invocation ACL cache, so combining -SortBy Owner with
                # -ShowOwner or a permission filter pays the cost once.
                $acl = GetCachedAcl $item
                if ($null -ne $acl) { return $acl.Owner } else { return '?' }
            }
        }
    }

    # Either stream-format an item to the pipeline (default) or buffer it for
    # later sorting. Used by every emission site instead of FormatOutput.
    # When buffering for sort, we PRE-COMPUTE the sort key here (rather than
    # inside a Sort-Object Expression scriptblock) because Sort-Object's
    # expression block runs in a separate pipeline scope where nested
    # functions like GetSortKey are not reliably visible.
    # Shared by Emit (streaming output) and the -Delete sites so -First N
    # early-termination works in BOTH "emit and count" and "delete and count"
    # paths. Bumps the per-invocation EmittedCount and sets the StopWalk flag
    # once the cap is reached.
    function BumpEmitCount {
        if ($First -gt 0) {
            $emitState.EmittedCount++
            if ($emitState.EmittedCount -ge $First) {
                $emitState.StopWalk = $true
            }
        }
    }

    function Emit($item, $recursiveBytes = $null) {
        # CASE 1: Buffering for -SortBy. Collect everything (with pre-computed
        # sort key) and flush in sorted order after the main loop. Memory:
        # O(matches). Warn if the buffer grows past MaxBufferItems.
        if ($null -ne $emitBuffer) {
            $entry = @{
                Item           = $item
                RecursiveBytes = $recursiveBytes
            }
            if ($SortBy) {
                $entry.SortKey = GetSortKey $item $recursiveBytes $SortBy
            }
            $emitBuffer.Add($entry)

            if ($MaxBufferItems -gt 0 -and
                -not $emitState.WarnedBuffer -and
                $emitBuffer.Count -ge $MaxBufferItems) {
                # Build the full message string in one piece, THEN apply -f.
                # Concatenating strings with '+' and then '-f' has the wrong
                # precedence ('-f' binds tighter than '+') so the substitution
                # would only apply to the last chunk.
                $warningTemplate = (
                    "Find-Item sort buffer has reached {0:N0} items. " +
                    "Memory usage is proportional to the total result count. " +
                    "For huge trees, consider filtering more aggressively " +
                    "(-Name/-Size/etc), using -First N, or - on PowerShell 7+ - " +
                    "piping streaming output to 'Sort-Object -Top N'. " +
                    "See 'Get-Help Find-Item -Full' for details."
                )
                Write-Warning ($warningTemplate -f $emitBuffer.Count)
                $emitState.WarnedBuffer = $true
            }
            return
        }

        # CASE 2: Sliding-window queue for -Last N (no -SortBy). Memory: O(N).
        if ($null -ne $lastQueue) {
            $lastQueue.Enqueue(@{ Item = $item; RecursiveBytes = $recursiveBytes })
            while ($lastQueue.Count -gt $Last) { $lastQueue.Dequeue() | Out-Null }
            return
        }

        # CASE 3: Streaming output. If -First N is set, count emissions and
        # set the stop flag once we've shipped N - the Traverse loops check
        # the flag and unwind. Memory: O(1).
        FormatOutput $item $recursiveBytes
        BumpEmitCount
    }

    # -------------------------------------------------------------------------
    #  Running totals for -Summary / -SummaryOnly. Hashtable (not PSCustomObject)
    #  because we mutate it from nested functions, which is reliable only with
    #  reference types - PSCustomObject property assignment from inner scopes
    #  is inconsistent across PS versions.
    # -------------------------------------------------------------------------
    $tally = @{
        ItemCount      = 0
        FileCount      = 0
        DirectoryCount = 0
        SymlinkCount   = 0
        TotalBytes     = [long]0
    }

    function TallyItem([System.IO.FileSystemInfo] $item) {
        $tally.ItemCount++
        $isDir  = $item -is [System.IO.DirectoryInfo]
        $isLink = IsReparsePoint $item
        if     ($isLink) { $tally.SymlinkCount++ }
        elseif ($isDir)  { $tally.DirectoryCount++ }
        else {
            $tally.FileCount++
            # GetSizeBytes returns logical OR allocated per -AllocatedSize.
            $tally.TotalBytes += GetSizeBytes $item
        }
    }

    # -------------------------------------------------------------------------
    #  Entry point - one pass per starting path
    # -------------------------------------------------------------------------
    foreach ($startPath in $Path) {
        # Stop walking additional -Path args if -First N was satisfied earlier.
        if ($emitState.StopWalk) { break }

        $resolved = Resolve-Path -LiteralPath $startPath -ErrorAction SilentlyContinue
        if (-not $resolved) {
            Write-Error "Path not found: '$startPath'"
            continue
        }

        $root   = Get-Item -LiteralPath $resolved.Path
        $isDir  = $root -is [System.IO.DirectoryInfo]
        $isLink = IsReparsePoint $root

        $rootDeleted = $false
        $deferRoot = $DirectoryTotals -and $isDir

        # Pre-order: emit the root immediately, then recurse.
        if (-not $deferRoot) {
            if ($MinDepth -eq 0 -and (TestItem $root)) {
                TallyItem $root
                if ($Delete) {
                    if ($PSCmdlet.ShouldProcess($root.FullName, 'Delete')) {
                        SafeDelete $root
                        $rootDeleted = $true
                        if ($PassThru -and -not $SummaryOnly) { Emit $root }
                        else                                  { BumpEmitCount }
                    }
                }
                elseif (-not $SummaryOnly) {
                    Emit $root
                }
            }
        }

        # Recurse if traversable. With -DirectoryTotals we always recurse
        # (even when MaxDepth=0) so the root's reported total is accurate;
        # deeper items are filtered out at the emission step inside Traverse.
        $rootRef = @{ Value = [long]0 }
        if ($isDir -and -not $rootDeleted -and ($DirectoryTotals -or $MaxDepth -gt 0)) {
            if (-not $isLink -or $FollowSymlinks) {
                Traverse $root.FullName 1 $rootRef
            }
        }
        $rootChildBytes = $rootRef.Value

        # Post-order: emit the root AFTER recursing so we have its byte total.
        if ($deferRoot) {
            if ($MinDepth -eq 0 -and (TestItem $root)) {
                TallyItem $root
                if ($Delete) {
                    if ($PSCmdlet.ShouldProcess($root.FullName, 'Delete')) {
                        SafeDelete $root
                        if ($PassThru -and -not $SummaryOnly) { Emit $root $rootChildBytes }
                        else                                  { BumpEmitCount }
                    }
                }
                elseif (-not $SummaryOnly) {
                    Emit $root $rootChildBytes
                }
            }
        }
    }

    # -------------------------------------------------------------------------
    #  If we were buffering (because -SortBy was set), sort the buffer now
    #  and flush it to the pipeline. The sort key comes from the underlying
    #  FileSystemInfo properties (via GetSortKey), so the comparison is
    #  always type-aware - numbers compare numerically, dates chronologically,
    #  strings lexically - regardless of how the value is displayed.
    # -------------------------------------------------------------------------
    if ($null -ne $emitBuffer -and $emitBuffer.Count -gt 0) {
        $descending = $SortOrder -in 'Descending', 'Desc'
        # Sort against the pre-computed SortKey value stored on each entry.
        # (See Emit() for why we pre-compute rather than using a Sort-Object
        # Expression scriptblock here.)
        $sorted = $emitBuffer | Sort-Object -Property { $_.SortKey } -Descending:$descending
        # Apply -First / -Last truncation on the sorted result.
        if     ($First -gt 0) { $sorted = @($sorted | Select-Object -First $First) }
        elseif ($Last  -gt 0) { $sorted = @($sorted | Select-Object -Last  $Last) }
        foreach ($buffered in $sorted) {
            FormatOutput $buffered.Item $buffered.RecursiveBytes
        }
    }

    # Flush the sliding-window queue (-Last N without -SortBy). The queue
    # already holds at most $Last items, in their original traversal order.
    if ($null -ne $lastQueue -and $lastQueue.Count -gt 0) {
        foreach ($queued in $lastQueue) {
            FormatOutput $queued.Item $queued.RecursiveBytes
        }
    }

    # -------------------------------------------------------------------------
    #  Emit the summary record (after all per-item output has flushed). Use
    #  -SizeUnit for the TotalSize string when set explicitly; for the default
    #  Bytes mode, use Auto since a single aggregate number is more readable
    #  with an adaptive unit than as a long raw integer.
    # -------------------------------------------------------------------------
    if ($Summary) {
        $totalSizeUnit = if ($SizeUnit -eq 'Bytes') { 'Auto' } else { $SizeUnit }
        $summaryObj = [pscustomobject][ordered]@{
            ItemCount      = $tally.ItemCount
            FileCount      = $tally.FileCount
            DirectoryCount = $tally.DirectoryCount
            SymlinkCount   = $tally.SymlinkCount
            TotalBytes     = $tally.TotalBytes
            TotalSize      = FormatSize $tally.TotalBytes $totalSizeUnit
        }
        $summaryObj.PSObject.TypeNames.Insert(0, 'FindItem.Summary')
        $summaryObj
    }

    }   # end of `end { }` block (pipeline support — see top of function)
}

# When the script is run directly (not dot-sourced), forward all arguments to Find-Item.
if ($MyInvocation.InvocationName -ne '.') {
    Find-Item @args
}
