# SPDX-License-Identifier: LicenseRef-Proprietary
# Copyright (c) 2026 Sovereignty Foundation
"""The module's surface against its type stub, pulse_wire.pyi: every public
name, member kind, signature and default the module has, the stub declares,
and nothing more."""

import ast
import inspect
import pathlib
import types

import pulse_wire as pw


# ─── the type stub ────────────────────────────────────────────────────────

STUB = pathlib.Path(__file__).resolve().parents[1] / "pulse_wire.pyi"

# Dunder methods a type checker needs to see, so the stub declares each the
# module defines: a context manager's, a container's, equality and hashing.
DECLARED_DUNDERS = (
    "__enter__",
    "__exit__",
    "__len__",
    "__iter__",
    "__getitem__",
    "__contains__",
    "__eq__",
    "__hash__",
)

REQUIRED = "required"


def _stub_names(text):
    """The top-level names of the stub `text`, each with its node."""
    names = {}
    for node in ast.parse(text).body:
        if isinstance(node, (ast.ClassDef, ast.FunctionDef)):
            names[node.name] = node
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names[node.target.id] = node
        elif isinstance(node, ast.Assign):
            names.update((t.id, node) for t in node.targets if isinstance(t, ast.Name))
    return names


def _stub_members(cls_node):
    """A stub class's members: name -> (kind, node)."""
    members = {}
    for node in cls_node.body:
        if isinstance(node, ast.FunctionDef):
            decorators = {d.id for d in node.decorator_list if isinstance(d, ast.Name)}
            if "property" in decorators:
                kind = "property"
            elif "staticmethod" in decorators:
                kind = "static method"
            else:
                kind = "method"
            members[node.name] = (kind, node)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            classvar = ast.unparse(node.annotation).startswith("ClassVar")
            members[node.target.id] = ("class constant" if classvar else "property", node)
    return members


def _runtime_kind(cls, name):
    raw = vars(cls)[name]
    if isinstance(raw, staticmethod):
        return "static method"
    if isinstance(raw, (types.GetSetDescriptorType, types.MemberDescriptorType)):
        return "property"
    if isinstance(raw, (types.MethodDescriptorType, types.WrapperDescriptorType)):
        return "method"
    return "class constant"


def _stub_params(fn, drop_first):
    """(name, kind, default) for each parameter of a stub function."""
    a = fn.args
    positional = a.posonlyargs + a.args
    defaults = [None] * (len(positional) - len(a.defaults)) + list(a.defaults)
    params = []
    for i, (arg, default) in enumerate(zip(positional, defaults)):
        kind = "POSITIONAL_ONLY" if i < len(a.posonlyargs) else "POSITIONAL_OR_KEYWORD"
        params.append((arg.arg, kind, REQUIRED if default is None else ast.literal_eval(default)))
    if a.vararg:
        params.append((a.vararg.arg, "VAR_POSITIONAL", REQUIRED))
    for arg, default in zip(a.kwonlyargs, a.kw_defaults):
        value = REQUIRED if default is None else ast.literal_eval(default)
        params.append((arg.arg, "KEYWORD_ONLY", value))
    if a.kwarg:
        params.append((a.kwarg.arg, "VAR_KEYWORD", REQUIRED))
    return params[1:] if drop_first else params


def _runtime_params(obj, drop_first):
    params = [
        (p.name, p.kind.name, REQUIRED if p.default is inspect.Parameter.empty else p.default)
        for p in inspect.signature(obj).parameters.values()
    ]
    return params[1:] if drop_first else params


def _stub_mismatches(text):
    """What differs between the stub `text` and the built module."""
    stub = _stub_names(text)
    problems = []
    runtime = {n for n in dir(pw) if not n.startswith("_")}
    declared = {n for n in stub if not n.startswith("_")}
    problems += [f"pulse_wire.{n} is not in the stub" for n in sorted(runtime - declared)]
    problems += [f"the stub declares {n}, which pulse_wire lacks" for n in sorted(declared - runtime)]
    if "__version__" not in stub:
        problems.append("the stub does not declare __version__")

    for name in sorted(runtime & declared):
        obj, node = getattr(pw, name), stub[name]
        if isinstance(obj, type):
            if not isinstance(node, ast.ClassDef):
                problems.append(f"{name} is a class; the stub does not declare it as one")
                continue
            bases = [b.__name__ for b in obj.__bases__ if b is not object]
            stub_bases = [ast.unparse(b) for b in node.bases]
            if bases != stub_bases:
                problems.append(f"{name}'s bases are {bases}; the stub's are {stub_bases}")
            problems += _class_mismatches(name, obj, node)
        elif callable(obj):
            if not isinstance(node, ast.FunctionDef):
                problems.append(f"{name} is a function; the stub does not declare it as one")
            elif _runtime_params(obj, False) != _stub_params(node, False):
                problems.append(
                    f"{name}{inspect.signature(obj)} differs from the stub's "
                    f"{_stub_params(node, False)}"
                )
        elif isinstance(node, (ast.ClassDef, ast.FunctionDef)):
            problems.append(f"{name} is a constant; the stub declares a {type(node).__name__}")
    return problems


def _class_mismatches(name, cls, node):
    problems = []
    members = _stub_members(node)
    if issubclass(cls, BaseException):
        if members:
            problems.append(f"the stub gives exception {name} members {sorted(members)}")
        return problems
    runtime = {n for n in vars(cls) if not n.startswith("_")}
    runtime |= {n for n in DECLARED_DUNDERS if vars(cls).get(n) is not None}
    declared = {n for n in members if not n.startswith("_") or n in DECLARED_DUNDERS}
    problems += [f"{name}.{n} is not in the stub" for n in sorted(runtime - declared)]
    problems += [f"the stub declares {name}.{n}, which {name} lacks" for n in sorted(declared - runtime)]
    for member in sorted(runtime & declared):
        kind, fn = members[member]
        actual = _runtime_kind(cls, member)
        if kind != actual:
            problems.append(f"{name}.{member} is a {actual}; the stub declares a {kind}")
            continue
        raw = vars(cls)[member]
        if kind in ("method", "static method") and not isinstance(raw, types.WrapperDescriptorType):
            obj = getattr(cls, member)
            drop = kind == "method"
            if _runtime_params(obj, drop) != _stub_params(fn, drop):
                problems.append(
                    f"{name}.{member}{inspect.signature(obj)} differs from the stub's "
                    f"{_stub_params(fn, drop)}"
                )
    # A class Python can construct has a text signature; its __init__ in the
    # stub must take the same parameters, and one it cannot has no __init__.
    init = members.get("__init__")
    if cls.__text_signature__ is None:
        if init is not None:
            problems.append(f"{name} cannot be constructed; the stub gives it __init__")
    elif init is None:
        problems.append(f"{name}{cls.__text_signature__} is constructible; the stub has no __init__")
    elif _runtime_params(cls, False) != _stub_params(init[1], True):
        problems.append(
            f"{name}{inspect.signature(cls)} differs from the stub's __init__ "
            f"{_stub_params(init[1], True)}"
        )
    return problems


def test_stub_matches_module():
    """pulse_wire.pyi declares exactly what the module exports: every public
    name, each class's members of the kind they are, every signature with the
    runtime's parameters and defaults, every exception with its base."""
    problems = _stub_mismatches(STUB.read_text(encoding="utf-8"))
    assert not problems, "pulse_wire.pyi is out of date:\n  " + "\n  ".join(problems)


def test_stub_check_sees_a_difference():
    """The check above is not vacuous: a stub missing a name, with a wrong
    default, a wrong base or a member of the wrong kind is reported."""
    text = STUB.read_text(encoding="utf-8")
    for old, new, expected in [
        ("def bind_pair(", "def bind_pair_renamed(", "pulse_wire.bind_pair"),
        ("timeout_s: float = 10.0", "timeout_s: float = 9.0", "Channel.open"),
        ("class ChannelClosed(EOFError)", "class ChannelClosed(ValueError)", "ChannelClosed"),
        ("    @property\n    def pending", "    def pending", "Channel.pending"),
        ("    def to_bytes(self) -> bytes: ...\n", "", "PulseEnvelope.to_bytes"),
    ]:
        broken = text.replace(old, new)
        assert broken != text, old
        problems = _stub_mismatches(broken)
        assert any(expected in p for p in problems), (expected, problems)


if __name__ == "__main__":
    tests = [
        test_module_constants,
        test_pulse_zero_init,
        test_pulse_field_round_trip,
        test_pulse_bytes_round_trip,
        test_pulse_origin_id_wrong_length_rejected,
        test_pulse_from_bytes_wrong_length_rejected,
        test_pulse_envelope_id_round_trip,
        test_loopback_round_trip,
        test_recv_timeout_raises,
        test_threaded_sender_receiver,
        test_stub_matches_module,
        test_stub_check_sees_a_difference,
    ]
    failed = 0
    for fn in tests:
        try:
            fn()
            print(f"PASS  {fn.__name__}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"FAIL  {fn.__name__}: {type(e).__name__}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    if failed:
        raise SystemExit(1)
