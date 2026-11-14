# Taobao VM registry lookup: recovered failure branches

Scope: SG 6.8.260901 and the shared callback documented in the
[VM router prefix](taobao-vm-router-analysis.md). This describes local lookup
behavior, not device-risk acceptance or a server rejection rule.

## Method and limits

The entire captured original module code area (67,572 bytes) matches the decoded
APK module exactly, beyond the earlier 64-byte entry match. Expanded VM records
and the actual runtime opcode table were executed offline using original ARM64
handlers. The route arguments, container metadata and caller frame are synthetic.

An opt-in model returns zero for single-threaded `pthread_rwlock_rdlock` and
`pthread_rwlock_unlock` imports (83 and 84). Import 83's live target was previously
matched to the device libc symbol; import 84's name is established by the APK
metadata. No risk function, account operation or server response is modeled as
successful. These models do not prove the actual phone lock state.

The failing lookup cases write their output error before the harness stops at an
uninitialized synthetic caller continuation (`0x10`). This is a partial-run
observation, not proof of normal function completion.

## Lookup keys and structures

After computing K, tested nonnegative routes descend through keys consistent
with:

```text
first_key = K / 10,000
second_key = (K / 100) % 100
third_key = K % 100
```

| Route | Observed keys in successful synthetic prefix matches |
| --- | --- |
| `(7,1,2,0)` | `6607`, `1`, `2` |
| `(2,6,1,0)` | `6602`, `6`, `1` |
| `(7,3,8,0)` | `6607`, `3`, `8` |

Container reads establish a pointer array at container `+0` and a 32-bit count at
`+8`. Entries are pointers to records with a 32-bit key at `+0`, selector
qualification at `+4`, and another pointer at `+8`. The observed comparisons
include selector qualification; these fields must not be labeled risk flags.
No particular C++ standard-container type has been established.

Matching three levels reaches the selected record's `+8` pointer. The synthetic
sentinel then encounters a read at selected-object `+8`; that object remains
unclassified. It has not been identified as the final factor-producing function.

## Specific missing-entry errors

| Synthetic condition | Error written for `(7,1,2,0)` |
| --- | --- |
| Empty first container or no matching first record | `701029904` |
| Matching first record, empty second container | `701029905` |
| Matching first and second records, empty third container | `701029906` |

The first missing-entry case for `(2,6,1,0)` writes `206019904`. These observations
agree with `command_number * 10,000 + {9904,9905,9906}` in those cases. They are
local lookup errors, not the server's HTTP 419 response or a Root/VPN verdict.

Negative and positive fixtures distinguish mismatched keys from matching prefix
records. An earlier predecessor-node hypothesis failed and was discarded; direct
record-key reads support the pointer-array model above. A provisional field name
`kind` was also rejected: its observed comparison is selector qualification.

## Live registration capture

A subsequent read-only capture from Taobao PID 7112 validated this lookup on the
phone. The SDK fingerprint and complete raw module code matched the saved
profile, and two full routing snapshots agreed. Both registry reads found:

| Level | Key | Container entries | Matching records |
| --- | --- | --- | --- |
| First | 6607 | 6 | 1 |
| Second | 1 | 2 | 1 |
| Third | 2 | 23 | 1 |

The selected object contains a list with **one descriptor**. Descriptor fields
`+0x20` and `+0x28` both point to byte-string objects containing this 32-byte ID:

```text
0bdc18ee4cf95fc88b11fd0fe155f65e
```

Static export metadata uniquely matches that ID within the Taobao images:

| Field | Value |
| --- | --- |
| Module | `59818921a60ea372693874c6dada31e9` |
| Export record | 2 |
| VM code offset | `0x122c0` (74,432) |
| Decoded image offset | 75,524 |

This connects the live **registration** to an APK entry. It does not show that a
particular failed business request invoked the entry, nor identify its risk
result or the server rule. The same ID exists in Idlefish at a different offset;
the Taobao offset must not be reused there.

The descriptor's `+0x28` object was initially explored as another pointer list.
Live bytes reject that interpretation: `+0` points to character data and `+8` is
the string's **byte length**, 32, not a count of 32 callbacks. The descriptor's
`+0x50` field was nonzero, but its pointed-to object's layout remains unresolved.
An attempted owner/module interpretation encountered a zero pointer and stopped;
it is not recorded as a successful module resolution.

ADB disconnected during subsequent reads. No phone reboot, login, app-data clear,
security-result rewrite or on-device native function call was performed. An
isolated offline run of entry `0x122c0` with a synthetic zero argument structure
stopped after seven records on a missing input object; this is not a successful
handler execution.

In this captured state the three registry levels are present, so the synthetic
missing-entry errors above cannot be cited as the phone's failure cause. The
handler's actual arguments, execution on a failing request, environment-field
writers and server rejection condition remain unresolved. No Taobao fix is
claimed.

## Registered handler: isolated prefix

A later offline prefix run supplies a synthetic input block whose first pointer
references another zeroed synthetic object. It does not substitute a security
function result. Original handlers establish these limited observations:

- A zero initial R8 branches at VM `0x122cc` to `0x12b04`, which executes a return
  opcode. The synthetic caller continuation is absent; normal completion is not
  established.
- The two-level synthetic input reaches local helper `0xa730` and, after 29 VM
  instructions, call site `0xa780`. Execution stops before native resolver
  `0x161474` for import 2.
- Import metadata identifies that unresolved import by ID
  `b4413bf45b4651909a72331b0a32bdc5`, uniquely matching declared provider module
  `977966b0ece28f4eee6216434b6175ea`, export 187, VM offset `0x24274`.

The provider has not been executed in this test. The cross-module argument ABI,
real request inputs, resulting security fields and server decision remain
unverified. A nearby `us_sdt` string held in a register is not sufficient to name
a risk field or identify an upload operation.
