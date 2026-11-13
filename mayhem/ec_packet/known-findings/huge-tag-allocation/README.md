# EC tag with an attacker-chosen length is allocated before it is read

`input.bin` (harness format: byte 0 = mode, rest = EC stream) is a 10-byte EC packet whose first
tag claims a data length of `0xff0100ff` (~4 GB) in a body that is only a few bytes long.

- Where: `CECTag::ReadFromSocket` (`src/libs/ec/cpp/ECTag.cpp:451`) calls `NewData()` /
  `new char[m_dataLen]` with the length read from the wire, before checking that the bytes exist.
  `CECSocket::ReadPacket` has already bounded the *packet* length (16 MB), but not the tag length
  inside it.
- Impact: a peer that can open the EC port (before authentication) makes amuled/amulegui allocate up
  to 4 GB per tag; libFuzzer reports `out-of-memory` (malloc limit), ASan reports
  `allocation-size-too-big` with `max_allocation_size_mb` set low.
- Fix: reject a tag whose `m_dataLen` exceeds the remaining packet bytes before allocating.

Reproduce: `./fuzz_ec_packet-standalone mayhem/ec_packet/known-findings/huge-tag-allocation/input.bin`
(with `ASAN_OPTIONS=max_allocation_size_mb=500` for the standalone binary).
