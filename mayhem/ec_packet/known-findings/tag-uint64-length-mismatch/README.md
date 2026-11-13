# GetInt() over-reads a received UINT64 tag whose data is shorter than 8 bytes

`input.bin` (harness format: byte 0 = mode, rest = EC stream) is an EC packet with a tag whose type byte
says `EC_TAGTYPE_UINT64` but whose data length is 2.

- Where: `CECTag::ReadFromSocket` (`src/libs/ec/cpp/ECTag.cpp`) stores the wire type and length without
  checking that an integer type has the matching length; `CECTag::GetInt()` (`ECTag.cpp:651`) then does
  `RawPeekUInt64(m_tagData)`, an 8-byte read from a 2-byte heap buffer. Same root cause as
  `tag-int-length-mismatch`, in the 64-bit arm of the switch.
- Impact: heap-buffer-overflow read in any caller of `GetInt()` on a received tag.
- Fix: in `ReadFromSocket`, reject integer tags whose `m_dataLen` does not match their type.

Reproduce: `./fuzz_ec_packet-standalone mayhem/ec_packet/known-findings/tag-uint64-length-mismatch/input.bin`
