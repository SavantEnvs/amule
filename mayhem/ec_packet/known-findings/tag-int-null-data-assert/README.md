# GetInt() asserts on a received integer tag with zero-length data

`input.bin` (harness format: byte 0 = mode, rest = EC stream) is an EC packet with a tag that has an
integer type byte but a data length of 0.

- Where: `CECTag::ReadFromSocket` leaves `m_tagData == NULL` when the data length is 0 but keeps the wire
  type; `CECTag::GetInt()` (`src/libs/ec/cpp/ECTag.cpp:639`) then fails
  `EC_ASSERT(m_dataType == EC_TAGTYPE_UNKNOWN)`, which is a plain `assert()` in this build.
- Impact: a remote peer aborts the process (assertions enabled) by sending an empty typed tag.
- Fix: in `ReadFromSocket`, reject (or retype as `EC_TAGTYPE_UNKNOWN`) a tag with a non-unknown type and
  no data.

Reproduce: `./fuzz_ec_packet-standalone mayhem/ec_packet/known-findings/tag-int-null-data-assert/input.bin`
