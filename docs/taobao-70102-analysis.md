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
