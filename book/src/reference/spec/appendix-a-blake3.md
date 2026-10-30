# Appendix A. BLAKE3

<p class="pm-kind"><b>Reference · informative</b> · the hash the content identifier is built on</p>

The content identifier of chapter 3 is the first 16 bytes of a BLAKE3 hash over the preimage of section 3.2. BLAKE3 is specified by its authors in the BLAKE3 paper and reference implementation, published at github.com/BLAKE3-team. The standard uses the plain hash mode with the preimage's own domain tag as its first bytes; it does not use BLAKE3's keyed or key-derivation modes.

The reference implementation hashes with the Rust `blake3` crate. The WebAssembly binding compiles the same crate. The Python and Node bindings and the satellite implementations use independent BLAKE3 implementations, and the vectors of chapter 8 are what show that all of them produce the same 16 bytes for the same preimage; that equality is the cross-language byte-equality contract of section 3.6.

Truncating a 32-byte BLAKE3 output to 16 bytes keeps the identifier the size of a node id and a Pulse's `envelope_ref`; the 128-bit identifier is a content address, not a signature, and the standard makes no claim about it beyond collision resistance at that width for the purpose of addressing.
