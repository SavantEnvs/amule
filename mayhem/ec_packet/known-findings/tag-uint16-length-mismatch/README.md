# GetInt() over-reads a received UINT16 tag whose data is shorter than 2 bytes

`input.bin` (harness format: byte 0 = mode, rest = EC stream) is an EC packet containing a tag whose
type byte says `EC_TAGTYPE_UINT16` but whose data length is 1.

- Where: `CECTag::ReadFromSocket` (`src/libs/ec/cpp/ECTag.cpp`) stores the wire type and wire length
  without checking that an integer type has the matching length; `CECTag::GetInt()` (`ECTag.cpp:647`)
  then does `RawPeekUInt16(m_tagData)`, a 2-byte read from a 1-byte heap buffer.
- Impact: heap-buffer-overflow read in whatever code calls `GetInt()` on a tag received from a remote
  EC client/server (amuled, amulecmd, amulegui, amuleweb). Same root cause as
  `tag-int-length-mismatch` and `tag-uint64-length-mismatch`, on the UINT16 branch.
- Fix: in `ReadFromSocket`, reject integer tags whose `m_dataLen` does not match their type (1/2/4/8).

Reproduce: `./fuzz_ec_packet-standalone mayhem/ec_packet/known-findings/tag-uint16-length-mismatch/input.bin`
