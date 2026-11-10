# Security review, 2.4.34

10 November 2026. Starting revision: 8dbf9e4a. I review the requested application
surfaces and land the verified fixes below. This is a source review with selected
runtime checks, not a penetration test or release clearance.

The tracked scope contains 599 source/script paths and 189 other paths under
src, plugins/tor, ci, cmake and workflows. Those are enumeration counts. Pattern
searches cover the broader tree; detailed reads and tests cover the named paths.
I haven't checked every line, every dependency or every native OS interaction.

## Fixed in this iteration

| Finding | Impact and trigger | Change | Evidence |
| --- | --- | --- | --- |
| SEC-001, high | A peer supplying malformed clipboard data can cause an out-of-bounds read. Format IDs were converted to an enum before range checking. | I validate counts, headers, lengths and trailing bytes before altering the clipboard, retain wire IDs as unsigned and close adapters on exceptions. | The old implementation produces an ASan heap-buffer-overflow with 32 supplied bytes and 4096 announced bytes. Six regressions cover all truncation points, large fields, high-bit/unknown formats, binary/duplicate formats and failed adapter writes. |
| SEC-002, high when DEBUG2 is selected | X11 selection replies dump every requestor-window property, including clipboard text, into diagnostics. Passwords and unrelated window contents can be retained. | I remove the property enumeration and payload dump. The actual selection notification remains. | Source removal and Linux compilation. A real X11 DEBUG2 selection session still needs desktop validation. Previously captured logs aren't erased by this fix. |
| SEC-003, conditional trust bypass | The engine reads its pin file through an unchecked generic file reader, even though GUI approval storage has stricter checks. Unsafe legacy/custom storage can therefore be accepted by the engine. | I add bounded checked loading, clear prior in-memory pins before a read and refuse connection on validation failure. POSIX uses checked ancestors and a retained file handle; Windows reuses its private-file reader. | Six POSIX cases cover valid/CRLF entries, malformed/oversized storage, missing files, writable files, links, unsafe parents, FIFOs and invalid paths. Native Windows loading remains unverified. |
| SEC-004, medium | Diagnostics disclose full command arguments, profile/configuration locations and dragged-file names/targets. | I remove the identified raw startup, trust-store and drag/drop values; fixed labels and counts remain. | Source review and Linux/Qt compilation. macOS/Windows changes are diagnostic-only but still need native validation. Other diagnostic metadata hasn't received an exhaustive privacy audit. |

The clipboard finding establishes a memory-safety defect. It doesn't establish
a working code-execution exploit. Its high-bit ID case is checked without relying
on a compiler's enum representation. Unknown future formats remain compatible,
and repeated known formats retain the last value. Trailing garbage now fails.

Malformed clipboard input leaves the old contents and ownership timestamp alone.
A local adapter failure is closed safely, but native clipboard replacement isn't
made transactionally atomic by this change. Total clipboard accumulation is a
separate open issue below.

The checked trust reader accepts only correctly sized SHA-256/SHA-1 records;
TLS peer approval still requires SHA-256. Empty/missing storage grants nothing.
An unsafe or malformed file throws, clears in-memory authority and refuses the
connection. The stored approvals aren't rewritten or repaired. Windows ancestor
handling, macOS extended ACLs and same-user mutation after checking remain open.

## Remaining work, in order

| Area | Current observation | Next check or repair |
| --- | --- | --- |
| Clipboard/file assembly, BX-006 | Clipboard receive caches and expected-size state are static, and data chunks append without a total-transfer cap. File assembly also retains shared progress state. | Move assembly into each peer/session; bind IDs/sequences, reject missing/repeated starts, bound accumulated bytes and clear state on loss of connection. Test interleaving and reconnects. |
| Packet queues, BX-006 | PacketStreamFilter has a 4 MiB packet limit, but readMore can accumulate many valid packets. A rejected size doesn't establish a terminal parser state. | Bound total queued bytes and work per event; discard safely and stop parsing after a protocol error. Test the actual underlying stream and event transitions. |
| File-drop metadata/destinations, BX-011 | Drag metadata parsing trusts delimiters/counts; failed numeric parsing can return an uninitialised size. DropHelper uses a path-based truncating write without a link/overwrite policy. Drag/drop is disabled by default. | Keep that default. Add strict metadata parsing and destination authorisation, checked handle-relative creation, link/overwrite refusal and failure preservation before wider use. |
| Bitmap/native adapters, BX-010 | Windows DIB conversion reads header fields and dimensions from OS-provided memory without a full checked layout. Native converter behaviour isn't covered here. | Check header sizes, offsets, signed dimensions and multiplication before GDI/OS decoding. I want external Windows/macOS review and native malformed-image cases. |
| Local commands, BX-003 | Existing Windows pipe identity/administrator policy and queued authorisation remain in place; no arbitrary action runner is added. | Recheck installed-service UAC, actual console switching, target executable selection and logout/reconnect with another account. Hosted helper checks aren't the whole desktop path. |
| Diagnostics | Identified payload/name/argument sites are removed. The file logger still uses ordinary append semantics; other metadata remains. | Private log-file creation, link handling and redacted exports need a separate cross-platform change. Review retained support logs for sensitive content. |
| Dependencies/provenance, BX-024 | New OpenSSL notices name a fix version which isn't yet available at the checked release endpoints. Runtime inventory and clean-machine packaging remain incomplete. | Obtain verified corrected inputs, review changes/licences, then build and verify the actual loaded libraries and provider/configuration paths. |
| Tor, BX-032 | Local bridge/protocol/TLS tests exist. Tor itself isn't installed here. | Test a real authorised onion session and a client without its key, then latency, sleep, dropped circuits and held-key recovery. Validate native platforms and ACLs. |

## Dependency disposition

I check the official [OpenSSL vulnerability list](https://www.openssl-library.org/news/vulnerabilities/)
and [downloads page](https://www.openssl-library.org/source/). Today's notices
name 3.5.10 fixes for CVE-2026-88823, CVE-2026-107496, CVE-2026-88822,
CVE-2026-95691 and CVE-2026-95692. I find no application calls to CMS_encrypt,
AES-GCM-SIV or OpenSSL QUIC in the inspected source; ordinary TLS is selected.
That is an applicability observation, not proof about every transitive consumer.

The official downloads page still lists 3.5.9. The 3.5.10 tag/release endpoints
and official checksum endpoint return 404 at this checkpoint. I retain the
verified pin rather than invent an archive/hash. The corrected dependency remains
an open task; no 3.5.10 build or distribution is claimed. The legacy Windows
installer remains refused. Current source selections and licence limitations
are in docs/dependencies.md.

Qt, platform libraries, libcurl, DNS-SD, filesystem and test dependencies retain
their existing selections. No external source or install script is imported or
executed for these fixes. A complete transitive advisory review, SBOM, native
runtime hashes and distribution notices remain outstanding. No hardcoded
production credential was identified in the scanned matches; that isn't a
whole-history secret audit.

## Evidence and limits

The targeted ASan/UBSan run passes 46 clipboard/fingerprint/storage cases with
leak detection disabled. This isn't new leak- or thread-sanitiser evidence.
Normal full-build results and platform limitations are recorded in docs/build.md.
I preserve the test branch and leave master unchanged.

Exhaustive serialisation, network, input-routing and native adapter reviews remain
unfinished. The concrete fixes above stand on their source paths and named
tests. Overall security and release readiness remain open.
