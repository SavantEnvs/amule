# GetStringDataSTL() asserts on a received string tag with zero-length data

`input.bin` (harness format: byte 0 = mode, rest = EC stream) is an EC packet with an
`EC_TAGTYPE_STRING` tag whose data length is 0.

- Where: `CECTag::ReadFromSocket` leaves `m_tagData == NULL` for a zero data length but keeps the wire
  type; `CECTag::GetStringDataSTL()` (`src/libs/ec/cpp/ECTag.cpp:668`) then hits `EC_ASSERT(false)`.
- Impact: a remote peer aborts the process (assertions enabled) by sending an empty string tag.
- Fix: same as `tag-int-null-data-assert`, in `ReadFromSocket`.

Reproduce: `./fuzz_ec_packet-standalone mayhem/ec_packet/known-findings/tag-string-null-data-assert/input.bin`
