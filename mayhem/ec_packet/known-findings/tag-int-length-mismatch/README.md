# GetInt() over-reads a received integer tag whose data is shorter than its declared type

`input.bin` (harness format: byte 0 = mode, rest = EC stream) is an EC packet containing a tag whose
type byte says `EC_TAGTYPE_UINT32` but whose data length is 2.

- Where: `CECTag::ReadFromSocket` (`src/libs/ec/cpp/ECTag.cpp:451`) stores the wire type and wire length
  without checking that an integer type has the matching length; `CECTag::GetInt()` (`ECTag.cpp:649`)
  then does `RawPeekUInt32(m_tagData)`, a 4-byte read from a 2-byte heap buffer.
- Impact: heap-buffer-overflow read in whatever code calls `GetInt()` on a tag received from a remote
  EC client/server (amuled, amulecmd, amulegui, amuleweb).
- Fix: in `ReadFromSocket`, reject integer tags whose `m_dataLen` != 1/2/4/8 for their type.

Reproduce: `./fuzz_ec_packet-standalone mayhem/ec_packet/known-findings/tag-int-length-mismatch/input.bin`
