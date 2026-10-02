"""Static symbolic pickle machine. Values are identities, never target objects."""

import pickletools
from dataclasses import dataclass, field
from hashlib import sha256
from io import BytesIO

from .contracts import Incomplete

# A deliberately small independent risk rule. Every other global is OPEN, including
# popular model constructors. This is not an allowlist or a full malware detector.
RISK_MODULES = frozenset(
    {
        "os",
        "posix",
        "nt",
        "subprocess",
        "socket",
        "ctypes",
        "pickle",
        "_pickle",
        "runpy",
        "urllib",
        "requests",
    }
)
RISK_BUILTINS = frozenset({"eval", "exec", "compile", "open", "__import__", "getattr"})
MARK = object()


@dataclass
class Value:
    identity: int
    kind: str
    text: str | None = None
    global_hash: str | None = None
    edges: list = field(default_factory=list)


class Machine:
    def __init__(self, evidence, member, base, stream):
        self.e = evidence
        self.loc = {"member": member, "stream": stream}
        self.base = base
        self.stack = []
        self.memo = {}
        self.marks = []
        self.protocol = None
        self.frame_end = None
        self.offset = base

    def emit(self, code, status="OPEN", **extra):
        self.e.emit(code, status, **self.loc, offset=self.offset, **extra)

    def new(self, kind, text=None, edges=()):
        self.e.charge("nodes")
        value = Value(self.e.counts["nodes"], kind, text)
        self.add(value, edges)
        return value

    def add(self, value, edges):
        self.e.charge("references", len(edges))
        value.edges.extend(edges)

    def push(self, value):
        if len(self.stack) >= self.e.limits.stack:
            raise Incomplete("budget_stack")
        self.stack.append(value)

    def pop(self):
        if not self.stack or self.stack[-1] is MARK:
            raise Incomplete("stack_underflow_or_mark")
        return self.stack.pop()

    def top(self):
        if not self.stack or self.stack[-1] is MARK:
            raise Incomplete("stack_underflow_or_mark")
        return self.stack[-1]

    def marked(self):
        if not self.marks:
            raise Incomplete("missing_mark")
        index = self.marks.pop()
        values = self.stack[index + 1 :]
        del self.stack[index:]
        return values

    def global_value(self, module, name):
        # Hash framing is unambiguous, including adversarial embedded NULs.
        raw = module.encode("utf-8", "surrogatepass")
        ref = sha256(
            len(raw).to_bytes(8, "big") + raw + name.encode("utf-8", "surrogatepass")
        ).hexdigest()
        risk = module.split(".", 1)[0] in RISK_MODULES or (
            module in {"builtins", "__builtin__"} and name in RISK_BUILTINS
        )
        malformed = (
            not module or not name or any(ord(c) < 32 or ord(c) == 127 for c in module + name)
        )
        self.emit(
            "invalid_global_name"
            if malformed
            else "risk_global_reference"
            if risk
            else "unresolved_global_reference",
            "OPEN" if malformed or not risk else "FAIL",
            reference_sha256=ref,
        )
        result = self.new("global")
        result.global_hash = ref
        return result

    def invoke(self, code, target, args):
        extra = {"target_identity": target.identity}
        if target.global_hash:
            extra["reference_sha256"] = target.global_hash
        self.emit(code, **extra)
        return self.new("constructed", edges=[target, *args])

    def mutation(self, kind, values):
        target = self.top()
        if target.kind != kind:
            self.emit("dynamic_container_method", target_identity=target.identity)
        if kind in {"dict", "set"}:
            self.hash_keys(values[::2] if kind == "dict" else values)
        self.add(target, values)

    def hash_keys(self, values):
        for value in values:
            pending, seen = [value], set()
            while pending:
                self.e.charge("work")
                current = pending.pop()
                if current.identity in seen:
                    continue
                seen.add(current.identity)
                if current.kind in {"list", "dict", "set", "bytearray"}:
                    self.emit("unhashable_container_key", target_identity=current.identity)
                    break
                if current.kind in {"tuple", "frozenset"}:
                    pending.extend(current.edges)
                elif current.kind not in {"str", "bytes", "scalar"}:
                    self.emit("dynamic_key_hash", target_identity=current.identity)
                    break

    def step(self, opcode, arg, start, end):
        self.offset = self.base + start
        name = opcode.name
        self.e.charge("opcodes")
        if end - start > self.e.limits.operand_bytes + 9:
            raise Incomplete("budget_operand_bytes")
        if self.frame_end is not None:
            if start == self.frame_end:
                self.frame_end = None
            elif start > self.frame_end or end > self.frame_end or name == "FRAME":
                raise Incomplete("frame_boundary")
        if self.protocol is not None and opcode.proto > self.protocol:
            raise Incomplete("opcode_above_declared_protocol")
        if self.protocol is None and opcode.proto >= 2 and name != "PROTO":
            self.emit("missing_protocol_header")
        if isinstance(arg, (bytes, bytearray, str)):
            length = (
                len(arg) if not isinstance(arg, str) else len(arg.encode("utf-8", "surrogatepass"))
            )
            if length > self.e.limits.operand_bytes:
                raise Incomplete("budget_operand_bytes")
        if name == "PROTO":
            if start != 0 or self.protocol is not None or not 2 <= arg <= 5:
                raise Incomplete("protocol_header")
            self.protocol = arg
        elif name == "FRAME":
            if self.protocol is None or self.protocol < 4 or arg < 1:
                raise Incomplete("frame_header")
            self.frame_end = end + arg
        elif name == "MARK":
            self.marks.append(len(self.stack))
            self.push(MARK)
        elif name == "POP":
            if not self.stack:
                raise Incomplete("stack_underflow")
            if self.stack[-1] is MARK:
                self.marks.pop()
            self.stack.pop()
        elif name == "POP_MARK":
            self.marked()
        elif name == "DUP":
            self.push(self.top())
        elif name in {"PUT", "BINPUT", "LONG_BINPUT", "MEMOIZE"}:
            index = len(self.memo) if name == "MEMOIZE" else arg
            if type(index) is not int or not 0 <= index < self.e.limits.memo:
                raise Incomplete("budget_memo_index")
            if index not in self.memo and len(self.memo) >= self.e.limits.memo:
                raise Incomplete("budget_memo")
            self.memo[index] = self.top()
        elif name in {"GET", "BINGET", "LONG_BINGET"}:
            if type(arg) is not int or not 0 <= arg < self.e.limits.memo:
                raise Incomplete("budget_memo_index")
            if arg not in self.memo:
                self.emit("undefined_memo_reference")
                self.push(self.new("unknown"))
            else:
                self.push(self.memo[arg])
        elif name in {"UNICODE", "BINUNICODE", "SHORT_BINUNICODE", "BINUNICODE8"}:
            self.push(self.new("str", arg))
        elif name in {"STRING", "BINSTRING", "SHORT_BINSTRING"}:
            # Python-2 string decoding depends on the caller's encoding setting.
            if not isinstance(arg, str) or not arg.isascii():
                self.emit("legacy_string_encoding")
                self.push(self.new("unknown"))
            else:
                self.push(self.new("str", arg))
        elif name in {"BINBYTES", "SHORT_BINBYTES", "BINBYTES8", "BYTEARRAY8"}:
            self.push(self.new("bytes" if name != "BYTEARRAY8" else "bytearray"))
        elif name in {
            "NONE",
            "NEWTRUE",
            "NEWFALSE",
            "INT",
            "BININT",
            "BININT1",
            "BININT2",
            "LONG",
            "LONG1",
            "LONG4",
            "FLOAT",
            "BINFLOAT",
        }:
            self.push(self.new("scalar"))
        elif name in {"EMPTY_LIST", "EMPTY_TUPLE", "EMPTY_DICT", "EMPTY_SET"}:
            self.push(self.new(name[6:].lower()))
        elif name in {"LIST", "TUPLE", "DICT", "FROZENSET"}:
            values = self.marked()
            if name == "DICT" and len(values) % 2:
                raise Incomplete("dict_odd_items")
            if name in {"DICT", "FROZENSET"}:
                self.hash_keys(values[::2] if name == "DICT" else values)
            self.push(self.new(name.lower(), edges=values))
        elif name in {"TUPLE1", "TUPLE2", "TUPLE3"}:
            values = [self.pop() for _ in range(int(name[-1]))][::-1]
            self.push(self.new("tuple", edges=values))
        elif name == "APPEND":
            value = self.pop()
            self.mutation("list", [value])
        elif name in {"APPENDS", "ADDITEMS", "SETITEMS"}:
            values = self.marked()
            if name == "SETITEMS" and len(values) % 2:
                raise Incomplete("dict_odd_items")
            self.mutation({"APPENDS": "list", "ADDITEMS": "set", "SETITEMS": "dict"}[name], values)
        elif name == "SETITEM":
            value, key = self.pop(), self.pop()
            self.mutation("dict", [key, value])
        elif name in {"GLOBAL", "INST"}:
            if name == "GLOBAL" and self.protocol is not None and self.protocol >= 4:
                self.emit("legacy_global_in_protocol4_or5")
            if not isinstance(arg, str) or " " not in arg:
                raise Incomplete("global_operand")
            module, target = arg.split(" ", 1)
            value = self.global_value(module, target)
            if name == "INST":
                value = self.invoke("instance_construction", value, self.marked())
            self.push(value)
        elif name == "STACK_GLOBAL":
            target, module = self.pop(), self.pop()
            if target.kind != "str" or module.kind != "str":
                self.emit(
                    "unknown_stack_global",
                    module_identity=module.identity,
                    name_identity=target.identity,
                )
                value = self.new("unknown", edges=[module, target])
            else:
                value = self.global_value(module.text, target.text)
            self.push(value)
        elif name == "REDUCE":
            args, target = self.pop(), self.pop()
            if args.kind != "tuple":
                self.emit("reduce_args_not_tuple")
            self.push(self.invoke("reduce_potential_call", target, [args]))
        elif name in {"NEWOBJ", "NEWOBJ_EX"}:
            kwargs = self.pop() if name == "NEWOBJ_EX" else None
            args, target = self.pop(), self.pop()
            if args.kind != "tuple" or (kwargs is not None and kwargs.kind != "dict"):
                self.emit("newobj_argument_types")
            self.push(
                self.invoke("object_construction", target, [args] + ([kwargs] if kwargs else []))
            )
        elif name == "OBJ":
            values = self.marked()
            if not values:
                raise Incomplete("obj_missing_class")
            self.push(self.invoke("object_construction", values[0], values[1:]))
        elif name == "BUILD":
            state = self.pop()
            target = self.top()
            self.emit("build_potential_state_hook", target_identity=target.identity)
            self.add(target, [state])
        elif name in {"EXT1", "EXT2", "EXT4", "PERSID", "BINPERSID", "NEXT_BUFFER"}:
            args = [self.pop()] if name == "BINPERSID" else []
            self.emit("external_reference_" + name.lower())
            self.push(self.new("unknown", edges=args))
        elif name == "READONLY_BUFFER":
            target = self.top()
            self.emit("external_buffer_readonly", target_identity=target.identity)
        elif name == "STOP":
            if self.marks or len(self.stack) != 1 or self.stack[0] is MARK:
                raise Incomplete("stop_stack_contract")
            if self.frame_end is not None and self.frame_end != end:
                raise Incomplete("stop_before_frame_end")
            return True
        else:
            raise Incomplete("unsupported_opcode")
        return False


def analyze_pickle(data, evidence, member=0, base=0):
    if not data:
        evidence.emit("empty_pickle", member=member, offset=base)
        return
    source = BytesIO(data)
    stream_count = 0
    while source.tell() < len(data):
        evidence.charge("streams")
        stream_count += 1
        start = source.tell()
        machine = Machine(evidence, member, base + start, stream_count)
        current = source
        stopped = False
        try:
            for opcode, arg, position in pickletools.genops(current):
                stopped = machine.step(opcode, arg, position - start, current.tell() - start)
                if machine.frame_end is not None and machine.frame_end > len(data) - start:
                    raise Incomplete("truncated_frame")
            if not stopped:
                raise Incomplete("missing_stop")
        except Incomplete as exc:
            evidence.emit(str(exc), member=member, stream=stream_count, offset=machine.offset)
            break
        except (ValueError, UnicodeError, OverflowError, EOFError):
            evidence.emit(
                "invalid_or_truncated_opcode",
                member=member,
                stream=stream_count,
                offset=base + current.tell(),
            )
            break
        if source.tell() <= start:
            raise Incomplete("pickle_no_progress")
    if stream_count > 1:
        evidence.emit("multiple_stream_memo_lifetime_unproved", member=member, offset=base)
