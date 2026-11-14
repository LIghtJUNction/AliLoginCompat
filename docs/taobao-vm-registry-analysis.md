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

## Remaining observation

The actual phone's container entries and selected object have not been captured.
A bounded read-only walker was prepared for the known `(7,1,2,0)` profile: verify
the entire live module code against the APK image, bound counts and mapped reads,
then repeat the three-level lookup without calling or changing the target.
It is not yet validated against live registry contents.

No finding here establishes missing registration on the phone, identifies the
environment-state writer, fixes Taobao, or describes Idlefish's distinct SDK.
