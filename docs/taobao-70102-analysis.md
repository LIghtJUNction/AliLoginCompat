# Taobao 70102: verified wrapper flow

Scope: the saved Android SG 6.8.260901 library with SHA-256
`0bfbfff2bd2a9abdf82e34706276c8ad3d4e7e78a1dee276fa3984fab448f126`.
This describes the local factor wrapper, not the server's risk policy or a fix.

## Address convention

Historical Ghidra exports use an image bias of `0x100000`. Subtract that bias to
obtain an ELF virtual offset for this analysis project. The first ELF LOAD starts
at zero. Runtime addresses are the load bias plus the ELF virtual offset.

| Role | Ghidra address | ELF virtual offset |
| --- | --- | --- |
| Java command bridge | `0x15a2fc` | `0x05a2fc` |
| Native router | `0x156f70` | `0x056f70` |
| 70102 JNI argument wrapper | `0x1d002c` | `0x0d002c` |
| Unified factor wrapper | `0x1d3410` | `0x0d3410` |
| Identified fallback | `0x210158` | `0x110158` |
| Form URL encoder | `0x247abc` | `0x147abc` |
| Append observation point | `0x24dc40` | `0x14dc40` |

Existing native profiles already contain ELF offsets. Do not subtract the bias
again. Decoded VM image offsets are a separate address space.

## Recovered decisions

Six obscured branches were checked by executing original ARM64 instructions with
eight varied register/stack states each. Four depend on local literals; two
assume the relative relocation table retains its APK initial values. Later
runtime changes to that table have not been excluded. Temporary Ghidra branch
conversions were restored, and the project was processed read-only.

The recovered wrapper behaves as follows:

1. A missing appkey pointer, zero length, or empty first character sets
   `error_out=2401` and returns failure.
2. The `gste` configuration is queried when its cache marker is unset. A query
   error substitutes zero. A value of one adds `0x8` to the argument flags and
   continues into the same internal `(7,1,2,selector=0)` dispatch.
3. If that dispatch returns one, validate its required output objects. MiniWUA
   must have a nonnull buffer and positive length; the UMT, Sgext and Sign output
   objects must also exist. Missing required output sets `error_out=2499` and
   returns failure.
4. If the dispatch does not return one, call the identified fallback. A successful
   fallback goes through the same required-output checks; failure returns without
   a factor map. Missing output after a successful primary dispatch does not
   enter this fallback.
5. Argument flag `0x2` applies form URL encoding to output strings before copying
   them. Flag `0x1` gates the optional `x-us` output. The `pip` configuration gates
   optional `x-pipu1`; full `wua` and `x-gst` are copied when their output buffers
   are available.

These flags belong to the outer argument structure at offset `0xd4`. They are
**not** the decoded MiniWUA candidate 18-byte environment state. Do not label
them Root/VPN bits.

The original encoder matched `java.net.URLEncoder` on five synthetic inputs,
including every nonzero byte, with byte-preserving Latin-1 reference conversion.
Only buffer services and `strlen` were mocked. This identifies form encoding,
not fingerprint encryption.

## What the captured requests establish

The identified fallback builds fixed nine-byte prefixes before appending variable
data: `acYBCM001` for Sign, `agYBCM001` for Sgext, and `amYBCM001` for MiniWUA.
Its buffer methods append to the existing buffer and preserve those prefixes.
None of the 24 HTTP requests associated with the previous command sample had
these prefixes; all three compared fields were present in every request.
Under this library implementation, those requests did not come from this
particular fallback. Other unobserved runtime paths are not excluded.

Both successful recommendation and rejected cart requests can pass this local
wrapper and share the same candidate MiniWUA state. Local generation success
does not establish that the environment passed server checks. The server's
specific rejection condition remains unknown.

All four selected calls had `useWua=false`. This wrapper still requires MiniWUA;
its required-output check is not conditional on that boolean. An optional full
`wua` output is a separate slot.

The next discriminating observation is the actual registered target for
`(7,1,2,selector=0)`, or the VM callback used when that lookup fails. A static
absence from the recovered registration list is insufficient to choose between
those paths. This analysis has not identified the environment-state writer or
provided a verified cart fix.

## Read-only device routing snapshot (2026-11-14)

Two matching snapshots from the live Taobao process, with the mapped library's
full SHA-256 checked against the saved APK library, establish the following
routing state. This is a routing-table observation, not an execution trace of a
new cart request.

| Route | Snapshot result |
| --- | --- |
| `(7,1,2,selector=1)` | Registered native target `0x0d002c`, the expected outer wrapper |
| `(7,1,2,selector=0)` | No registered native entry |
| `(2,6,1,selector=0)` | No registered native entry |
| Missing-entry callback | Executable target `0x1b4dc0` |

All offsets in this section are ELF offsets. Given this table state, the
router's missing-entry branch selects that callback for the internal factor
route. This does not exclude later table updates.

The callback's first 16 live bytes match the original library. Its stub branches
to `0x1b0dc0`, which resolves a two-pointer trampoline table entry at displacement
`0x3fd0`. The live entry points to `0x1b0db0`; that stub enters `0x1b0c50`, whose
argument-marshalling call is at `0x1b05c4`. The associated closure entry is
`0x160300`.

The saved closure context has execution-kind one at offset `0x1c`. In the
recovered `0x160300` implementation, that value selects the function pointer at
`owner + 0x58`, passing the closure's code pointer and marshalled arguments.
The initial read did not capture the owner function pointer or bytecode-to-module
match. Its next read was interrupted by loss of the ADB connection. The subsequent
sample below closes that routing-location gap; neither sample establishes a
successful cart result.

The router's missing-entry callback is distinct from the identified factor
fallback at `0x110158`. Selecting a VM-backed route is not evidence of failed
security-factor generation or abnormal device status.

## Matched VM callback module and entry

A subsequent Taobao launch produced two matching complete routing snapshots.
The live owner method is ELF `0x15b9b4`, agreeing with the saved object's execution
method. Its internal execution mode is two. Following its entry handle identifies:

| Item | Verified value |
| --- | --- |
| Saved module ID | `204f22e1f34732a873d0c9e5d8210920` |
| Exported entry ID | `79adfb7d4443086631b29818efab6120` |
| Entry-record index in saved metadata | 15 |
| Offset in original module code area | `0x827c` |
| Offset in decoded module image | `0x8744` |

The 64 bytes read from the live entry match that image location exactly and occur
only once in the saved image. Its export metadata independently agrees with both
offsets. These are VM module offsets, not ARM64 offsets in `libsgmainso`.

The executable method subtracts the module code base from the entry handle.
The interpreter distinguishes raw words and expanded records using module byte
`+0x1b`. Under its established seed precondition `W25=43`, original ARM64 execution
on eight synthetic cases verified both address calculations:

- Raw words: `module.code_base + entry_offset`.
- Expanded records: `module.record_base + ((entry_offset - 4) / 4) * 16`.

The sampled module has expanded records enabled. A bounded 512-byte read of the
corresponding runtime records was saved privately. This does not establish all
instruction boundaries or opcode meanings: records can include immediate data.
A candidate RELA-table recovery using 25 previously saved opcode observations
found no common anchor, so it supplies no opcode-semantic proof.

This identifies the **shared router callback**, not the final MiniWUA-producing
function. The callback receives the route tuple and still must dispatch it within
the VM. Its branch for `(7,1,2,selector=0)`, subsequent state writers, and the
server's rejection rule remain unresolved. No risk fields were rewritten and no
new successful business request is claimed.

The subsequent [shared VM router prefix analysis](taobao-vm-router-analysis.md)
recovers two call-structure comparisons, route arithmetic, and the first native
import reached. The final security-factor target remains unresolved.
