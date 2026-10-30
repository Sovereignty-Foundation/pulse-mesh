# Write a language binding

<p class="pm-kind"><b>How-to guide</b> · for anyone implementing the codec or a client in another language and wanting it to conform</p>

A binding conforms when it reproduces the vectors byte for byte. There are two kinds of binding in this tree and a third kind outside it, and the guide covers all three.

## Know which kind you are writing

- **A codec binding** wraps `pulse-canon` for another runtime. The Python, Node and C bindings under `peripheral/bindings/` do this with native extensions, and the WebAssembly binding does it for the browser. They inherit conformance from the codec; their tests prove the wrapper adds nothing.
- **A thin client** speaks the port protocol to a running daemon over a WebSocket, without the codec. The Python and Node thin clients in the daemon repository (`clients/`) are the pattern: attach, send, on, tap, run, detach, in about two hundred lines.
- **An independent implementation** of the codec in another language is a satellite repository: it proves conformance against the vectors on its own and registers in the profiles repository's `modules.toml`, which lists none today.

## 1. Start from the vectors

The three files under `pulse/pulse-spec/test-vectors/` are the contract: `pulse-layout-known-good`, `envelope-raw-known-good` and `envelope-nested-3-level`, each as a JSON description of the fields and as the exact hex bytes. Your first test loads a vector, builds the value from the JSON fields, encodes it, and compares the bytes; your second decodes the hex and compares the fields; your third recomputes the identifier and compares it with the one in the vector.

## 2. Implement chapter 3 exactly

The specification's [PulseEnvelope chapter](../reference/spec/03-envelope.md) is the whole codec: the 44-byte header, the type-name section with its tag and length, the payload section with its variant tag, and the identifier preimage with the domain tag and the length prefixes. Two things catch most implementations: the type-name length is a byte length of UTF-8, not a character count; and the identifier's preimage begins with the domain tag `pulse-envelope-id/v2` and includes the payload's byte length before its bytes. If the raw vector's identifier matches, the nested one usually does; if it does not, the nested payload's count prefix is the place to look.

## 3. Prove it the way the tree does

In the browser, the WebAssembly binding's `check_fixture` runs every vector through the compiled codec. For a native binding, mirror `bindings/wasm/tests/smoke.mjs`: round-trip each vector, then build a typed envelope, tamper with one payload byte and confirm `verify` fails. A thin client has nothing to prove against the vectors; its test is a session against an embedded daemon, which `mesh-hub`'s `embed` module provides in a few lines.

## 4. Register a satellite

An implementation outside this repository adds an entry to `modules.toml`, in the profiles repository, naming its repository, its tier, its conformance surface and its registry status; the file defines those fields and holds no entry yet. The entry is how the registry finds it; the vectors are how it is judged.
