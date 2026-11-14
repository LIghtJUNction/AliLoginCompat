# Taobao shared VM router: recovered prefix

Scope: Android SG 6.8.260901 with SHA-256
`0bfbfff2bd2a9abdf82e34706276c8ad3d4e7e78a1dee276fa3984fab448f126`.
This extends the [70102 wrapper analysis](taobao-70102-analysis.md). It identifies
routing behavior, not a server risk rule or an accepted device environment.

## Actual opcode dispatch table

The native executor at ELF `0x170d1c` loads a 16-bit opcode from the runtime
record and selects a handler from its fifth input argument. The caller at
`0x18f6cc` supplies the runtime pointer stored at ELF global `0x305d10`.
A subsequent read-only device capture saved that table's bounded candidate span,
the module's raw code, and its expanded records. Adjacent table slots are not
independently proven valid opcodes.

For the callback's first record, opcode 588 maps to ELF `0x186768`. Original
instructions save VM registers and adjust the VM stack using the record's
immediate. This is a prologue operation, not evidence of a risk test.

## Recovered comparisons and arithmetic

The matched shared callback is in module
`204f22e1f34732a873d0c9e5d8210920`, at code offset `0x827c`.
Original ARM64 execution on captured records and a synthetic frame established:

| Module code offset | Comparison | Taken path for the synthetic `(7,1,2,0)` call |
| --- | --- | --- |
| `0x829c` | First 32-bit field of callback argument structure equals zero | Equal; advance two runtime records |
| `0x82bc` | Selector equals two | Not equal; branch forward 129 runtime records |

The native router constructs that first field as zero. These are call-structure
comparisons; they have not been identified as Root/VPN/environment tests. Paths
for other structure headers and selector two have not yet been recovered.

The selected path computes:

```text
K = 66,000,000 + major * 10,000 + middle * 100 + minor
```

| Synthetic route | Observed K |
| --- | --- |
| `(7,1,2,0)` | 66,070,102 |
| `(7,1,2,1)` | 66,070,102 |
| `(2,6,1,0)` | 66,020,601 |
| `(1,1,1,0)` | 66,010,101 |

These cases verify the arithmetic in the observed prefix. They do not establish
K's complete downstream use, validity ranges for arbitrary inputs, or any
association with a server error code. K is passed into a local helper at module
code offset `0x5058`.

## First import reached

The prefix reaches opcode 17 with binding index 83. In the saved module's import
metadata that index names `pthread_rwlock_rdlock`. The live binding has kind one.
Its native target matches the same symbol's exact ELF offset `0x9c874` in the
device libc, with libc SHA-256
`35a725eb85f090f6a1d330ca4075d239afb215800205bfb3fca5e24258c480b0`.
This locates a synchronization operation, not a device-risk verdict.

The native binding resolver at ELF `0x161474` was exported under its original
entry-state precondition (word at ELF `0x2d1a88` equals 77). Its type-one branch
calls the native bridge; other binding kinds have distinct VM resolution paths.
The temporary analysis substitution was restored and the project processed
read-only. This conditional export is not evidence that a new phone request
executed every branch.

## Limits and next unresolved step

The offline runner executes original native instructions, with synthetic route
arguments and VM bookkeeping state. It stops before the unmodeled binding
resolver; no native import, security result, account operation, or network
request is mocked into success. The captured module data and private traces
remain local.

The next unresolved step is the lookup after the read-lock call, then the
function that actually produces the security factors. This analysis has not
identified which device signal causes rejection, nor fixed search, cart or
product details. Idlefish's separate SDK has not been validated by this prefix.

The subsequent [VM registry lookup analysis](taobao-vm-registry-analysis.md)
recovers the three key comparisons and missing-entry errors using explicitly
synthetic containers and synchronization models. Actual registry values remain
unread.
