# Python bindings

<p class="pm-kind"><b>Reference</b> · the Python binding: what it wraps, how to build it and where to read its API</p>

The Python binding lives at `bindings/python/` — a PyO3/maturin module named `pulse_wire`, wrapping `Pulse`, `Sender`, and `Receiver` over the reference UDP transport (see [Language bindings](bindings.md) for what it does and how it differs from the pure-Python thin client).

Build and inspect it locally:

```
cd bindings/python
maturin develop
python -c "import pulse_wire; help(pulse_wire)"
```

The module's own docstrings are the source of truth for its Python-facing API. Its test suite (`test_loopback.py`, `test_send_buffer.py`, `test_recv_into.py`, `test_canonical_codec_cross_language.py`) is also a good place to see real call patterns.
