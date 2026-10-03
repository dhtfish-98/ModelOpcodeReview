# ModelOpcodeReview

New implementation author and maintainer: dhtfish98.

Review one local pickle, ZIP model container or NPY/NPZ file without loading a model. The independent implementation follows actual symbolic stack, mark, memo and object identities, validates FRAME boundaries, and records potential global/call/state-hook references. It also checks a strict ZIP32 profile and bounded NPY header/dtype/shape syntax. Python 3.11+; no runtime dependencies.

```sh
python -m pip install .
model-opcode-review examples/primitive.pkl
model-opcode-review examples/primitive.zip
model-opcode-review examples/primitive.npy --format npy
```

```python
from model_opcode_review import Limits, review_bytes, review_file

report = review_bytes(b"N.", format="pickle")
local_report = review_file("/absolute/physical/path/model.pkl")
```

`review_bytes` accepts immutable bytes and `auto`, `pickle`, `zip` or `npy`. `review_file` accepts one local regular file, with every path component opened without following symlinks and descriptor metadata checked across reading. On macOS use physical `/private/tmp` or `/private/var` paths; `/tmp` and `/var` are system symlinks. No file writes or extraction occur. Source paths, literal operands, NPY field names and ZIP filenames are not echoed. Findings contain constant codes, logical member/stream numbers and byte offsets; global references use SHA-256 identifiers. ZIP offsets refer to the uncompressed member; NPY pickle offsets include the header length.

| Result | Meaning | Exit |
| --- | --- | --- |
| PASS | Selected static checks completed with data-only supported structures and no unresolved evidence | 0 |
| FAIL | Fixed risk-reference rule or an unsafe ZIP path/type/alias was observed | 1 |
| OPEN | Malformed, incomplete, unknown or unsupported evidence, or a resource/input limit | 2 |

FAIL can coexist with `analysis_completeness=INCOMPLETE`: prior findings survive a later truncation or budget limit. Every global is at least OPEN, including NumPy, PyTorch and common collection constructors. A small fixed module/name risk rule reports FAIL for potential privileged references, irrespective of actual runtime behavior. It is neither a complete malware list nor proof of malicious intent. REDUCE, NEWOBJ/NEWOBJ_EX, INST/OBJ, BUILD, dynamic container methods, EXT, persistent IDs and out-of-band buffers remain OPEN. A successful symbolic review never proves deserialization safe; runtime bindings, model correctness, authenticity and CVP eligibility stay OPEN in every report.

ZIP supports single-disk ZIP32 stored/deflate, matching local and central headers, exact descriptors, payload sizes and CRCs. It rejects links/special entries, unsafe or aliased paths and duplicates. Unknown ZIP entries, tensor storage, code, metadata and nested archives remain OPEN; they are not skipped into a complete-model PASS. NPY supports versions 1.0/2.0/3.0, primitive and selected structured dtype syntax, exact non-object payload size and bounded literal headers. Header compiler warnings are captured and cause a fixed `npy_compile_warning` OPEN finding without writing header content to stderr, including when caller warning filters request ignoring warnings or treating them as errors. Object dtype headers cause static pickle review and always OPEN: the header's declared dtype/shape is not proved equivalent to the symbolic pickle or a real ndarray.

Multiple concatenated pickle streams are all parsed until the first incomplete stream, but memo is reset per stream and shared-Unpickler lifetime remains OPEN. Old PyTorch binary storage/tar, compression wrappers, joblib, 7z, remote downloads, framework loading and directories are unsupported. No HTTP, Hugging Face, target-module import, unpickle, Torch/NumPy execution, archive extraction, URL fetching or attack generation is present.

Limits are public immutable values and can only be lowered. See [DEFENSIVE_SCOPE.md](DEFENSIVE_SCOPE.md) for exact supported grammar, semantics and budgets, [ORIGIN.md](ORIGIN.md) for fixed source attribution and retained provenance, and [VALIDATION.md](VALIDATION.md) for measured verification and remaining OPEN claims.

The bundled examples are inert data, a global declaration without invocation, and deliberate incomplete/mismatched declarations. `object-header.npy` deliberately contains a None pickle rather than an ndarray; it demonstrates OPEN, not a valid executable model or dtype equivalence. No upstream attack fixture is distributed.

Local file I/O requires the positive integer OS protection flags documented by
the reader/writer. Missing, zero, None, Boolean or non-integer flags return a
controlled OPEN/error before requested filesystem input/output instead of
weakening the boundary. Native
Windows file I/O is not verified; the current verification is macOS POSIX.

Directory descriptor capability contract: `os.supports_dir_fd` must be a set or frozenset containing `os.open` before requested local file access. Missing, malformed or incomplete capability declarations return the existing controlled OPEN/error result. This finite POSIX contract is checked locally; native Windows file operations are not implemented or claimed.
