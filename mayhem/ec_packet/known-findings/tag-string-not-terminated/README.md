# GetStringDataSTL() reads past a received string tag that has no terminating NUL

`input.bin` (harness format: byte 0 = mode, rest = EC stream) is an EC packet with an `EC_TAGTYPE_STRING`
tag whose data does not end in a NUL byte.

- Where: `CECTag::GetStringDataSTL()` (`src/libs/ec/cpp/ECTag.cpp:672`) builds `std::string(m_tagData)`,
  which runs `strlen` on a buffer that `CECTag::ReadFromSocket` filled with exactly `m_dataLen` wire bytes
  and never terminated.
- Impact: heap-buffer-overflow read (ASan, `strlen`) in any caller of `GetStringDataSTL()` /
  `GetStringData()` on a received tag.
- Fix: in `ReadFromSocket`, require a string tag to end in NUL (or build the string from `m_dataLen`).

Reproduce: `./fuzz_ec_packet-standalone mayhem/ec_packet/known-findings/tag-string-not-terminated/input.bin`
