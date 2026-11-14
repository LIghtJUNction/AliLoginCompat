# Original VM record conversion, verified offline

The saved SG 6.8.260901 converter at **ELF `0x175d70`** can expand format
`0x10003` images without running their business or risk handlers. The public
[conversion tool](../scripts/expand-vm-records.py) executes the original ARM64
instructions in Unicorn; it does not substitute an inferred opcode decoder.

## Byte-for-byte check and context dependencies

Using the saved shared-router image and its original addresses produced exactly
the phone's **270,272** expanded bytes, with zero differences:

```text
b4de5af6de7907293ee26f2a1b46f5bcf51d25193e7d094d9cdd85531c8ef4bf
```

That run executed 668,839 native instructions and returned zero. A completely
zeroed module context needed only these fields:

| Context offset | Value supplied/read |
| --- | --- |
| `+0x8` | Destination record buffer |
| `+0x194` | Loader code-word count |
| `+0x1a0` | Original code base |

The only observed context write is the compiled marker at `+0x18`. It is not a
MiniWUA environment-state bit. Native calls and unmapped accesses stop the tool;
no Android services, device properties, account state or network are simulated.

The loader's count is `(declared_code_bytes >> 2) + 1`, as recovered from its
context construction. Omitting the extra word produces an output shorter by
16 bytes. That initial image-mode attempt was corrected before the public tool
was validated against the complete phone sample. Input bounds include the extra
word and final output size is `declared_code_bytes * 4`.

A Ghidra decompilation attempt timed out. It is not used as evidence that the
converter was understood; the claims above rely on original-instruction execution,
context-access observations and the exact output comparison.

## Validated conversion scope

The tool completed conversion of all **14** saved Taobao `0x10003` images, producing
5,393,200 bytes of records in total. Every run returned zero and observed the same
three context reads and one marker write. This includes:

| Module ID | Expanded bytes |
| --- | --- |
| `204f22e1f34732a873d0c9e5d8210920` | 270,272 |
| `3c0dd530424f13ecb4a21a96f59485fe` | 1,325,552 |
| `977966b0ece28f4eee6216434b6175ea` | 774,864 |
| `7492aeb5fd9d5e39018708643e780dfb` | 812,384 |
| `475f97a366e099f307fcca1d7776e7aa` | 66,192 |

Only the shared-router output was directly compared with captured phone records.
Conversion of other images does not establish their executed paths or security
results. The remaining Taobao `0x10005` image is rejected, as are unrecognized
library fingerprints. Idlefish's different SDK is not covered by this profile.

## Usage

Requires Python 3 and Unicorn 2.x; local validation used Unicorn 2.1.4. Provide
your own original library and already decoded VM image. SDK binaries, expanded
records, credentials and captured device material are not distributed here.

```sh
python3 scripts/expand-vm-records.py \
  --library /private/libsgmainso-6.8.260901.so \
  --image /private/module.decoded.bin \
  --output /private/records.bin
```

The tool writes a private binary only after a successful conversion. An adjacent
JSON receipt records the run; a failure receipt may exist without a binary. Existing paths
require `--force`. `--reference` additionally requires exact agreement before
writing a binary. For a comparison with captured relocated records, supply the
original image and record-buffer addresses with `--image-base` and
`--records-base`. A mismatch or incomplete run exits nonzero.

## What remains unresolved

Record conversion is not a complete disassembler: instructions can span multiple
records and use inline data. Fixed-slot string references are candidates until
their boundaries and paths are checked. In the risk-related module, the converted
code has an address-operation candidate for `adb_enabled` at module code offset
`0x16950`, and one for `llc_miniwua_risk_update` at `0x9928`. These are VM offsets,
not native ELF offsets, and do not establish any environment-state bit meaning.

This tooling removes one dependency on live instruction-record capture. Actual
registry contents, execution state, risk-field writers and the server's rejection
condition still require further evidence. No Taobao fix is claimed.
