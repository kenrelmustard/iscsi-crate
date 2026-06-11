# Scryer Prolog model of the iSCSI protocol

This directory contains a small **executable model** of the parts of iSCSI
(RFC 3720) whose behaviour is *logical* rather than wire-format. The model is
the source of truth for a generated test corpus that is replayed against the
real Rust implementation by `tests/model_corpus_tests.rs`.

The point: write the protocol rules **once, declaratively**, let Prolog
enumerate cases exhaustively, and use the result as an independent oracle for
the implementation. When the model and the code disagree, a test fails — which
is exactly the signal you want.

## Files

| File | Purpose |
|------|---------|
| `iscsi_protocol.pl` | The model: login state machine, key negotiation, sequence-number window, CHAP ordering. |
| `Makefile` | `make corpus` regenerates the corpus; `make check` verifies the committed corpus is up to date. |
| `../tests/corpus/iscsi_model_corpus.txt` | Generated corpus (committed, so `cargo test` needs no Prolog). |
| `../tests/model_corpus_tests.rs` | Rust test that replays the corpus against the implementation. |

## What is modelled

1. **Login state machine** (`next_state/4`) — RFC 3720 §5.3. A single
   `process_login` step from `Free` as a function of CSG / NSG / Transit,
   cross-checked against `AnySession::process_login`. All 32 `(CSG,NSG,Transit)`
   combinations are enumerated, including the illegal CSG values that must land
   in `Failed` — this directly guards the auth-bypass surface.
2. **Key negotiation result-functions** (`neg_rule/3`, `neg_result/4`) —
   RFC 3720 §5.2/§12. Minimum/Maximum for numerics, AND/OR for booleans,
   digests forced to `None`, checked against `SessionData::apply_initiator_param`.
3. **Command-sequence-number window** (`sn_in_window/3`) — RFC 3720 §3.2.2.1.
   32-bit serial-number arithmetic including wrap-around, checked against
   `SessionData::validate_cmd_sn`.
4. **CHAP message ordering** (`chap_case/4`) — RFC 3720 §11. The legal ordering
   of `AuthMethod`/`CHAP_A`/`CHAP_I`/`CHAP_C`/`CHAP_N`/`CHAP_R` and the coarse
   outcome of the first initiator message set, checked against the security
   negotiation path.

## What is **not** modelled

- PDU byte encoding / BHS layout, digests, padding (`src/pdu.rs`) — serialization.
- SCSI block commands and the storage backend.
- Concurrency / async socket behaviour.

These are I/O and serialization concerns already covered by the crate's own
Rust tests; Prolog adds little there.

## Workflow

```bash
# One-time: install the interpreter
cargo install scryer-prolog

# Regenerate the corpus after changing the model
make -C model corpus

# CI / pre-commit: fail if the committed corpus drifted from the model
make -C model check

# Run the conformance tests (no Prolog needed; reads the committed corpus)
cargo test --test model_corpus_tests
```

## How to extend

To add coverage, add cases/rules to `iscsi_protocol.pl`, run `make -C model
corpus`, and (if a new record `KIND` was introduced) add a matching arm in
`tests/model_corpus_tests.rs`. The corpus format is one record per line:

```
SEQWINDOW exp=<u32> max=<u32> sn=<u32> expect=<accept|reject>
NEGOTIATE key=<Key> init=<value> expect=<value>
STATE     csg=<0-3> nsg=<0-3> transit=<0|1> expect=<StateName>
CHAP      case=<name> params=<K:V,...|-> expect_state=<State> expect_key=<k=v|key|none>
```

## Is this worth it?

For this crate, the model earns its keep on the **login state machine and
negotiation rules** — exhaustive `(CSG,NSG,Transit)` enumeration and the
min/max/AND/OR matrix are tedious and error-prone to maintain by hand, and the
illegal-transition cases are security-relevant. The sequence-number and CHAP
layers are a smaller win but cheap to include. It is deliberately *not* a full
formal model (no TLA+-style temporal properties, no multi-step session traces
yet) — it is a lightweight, regenerable oracle that lives next to the code.
