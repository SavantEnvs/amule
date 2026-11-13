# CTag copy constructor aborts on a BOOL or BOOLARRAY tag

`input.bin` (harness format: byte 0 = mode, rest = tag stream) is the 3-byte tag `85 41 01`: type
`TAGTYPE_BOOL`, name `0x41`, value `1`. `input-boolarray.bin` is the same with a `TAGTYPE_BOOLARRAY`.

- Where: `CTag::CTag(const CFileDataIO&)` (`src/Tag.cpp:142-155`) accepts BOOL and BOOLARRAY tags: it skips
  their data and keeps the type. `CTag::CTag(const CTag&)` (`src/Tag.cpp:79`) handles neither and reaches
  `wxFAIL`, which aborts when `wx_exit_on_assert` is set (as in the Mayhemfile).
- Reachable: the harness calls `CloneTag()` on every tag it reads; the application does the same in
  `src/kademlia/kademlia/Entry.cpp:76` and `src/Server.cpp:66`, so a peer that sends such a tag in a
  stream those code paths read can hit it.
- Fix: make the copy constructor accept the types the reader accepts, or have the reader reject (or
  discard) tags it cannot represent.

Reproduce: `wx_exit_on_assert=1 ./fuzz_tag_stream-standalone mayhem/tag_stream/known-findings/bool-tag-clone-assert/input.bin`
