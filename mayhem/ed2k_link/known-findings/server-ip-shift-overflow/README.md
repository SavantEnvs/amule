# StringIPtoUint32() shifts by 32 or more bits on a server link with more than four dotted fields

`input.bin` is the raw link `ed2k://|server|1.1.1.1.1.1|4661|/` (the `ed2k_link` harness takes the link text
as is, no mode byte).

- Where: `StringIPtoUint32` (`src/NetworkFunctions.cpp:55`), reached from `CED2KServerLink::CED2KServerLink`
  (`src/ED2KLink.cpp:129`) via `CED2KLink::CreateLinkFromUrl`. It does `tmp_ip | value << (field * 8)`,
  and `field` is incremented on every `.` with no upper bound. The fifth `.` shifts a 32-bit `unsigned`
  by 32, which is undefined behaviour (UBSan `shift-exponent`; the function would only reject the
  address afterwards, at the final `field == 3` check).
- Impact: undefined behaviour on attacker-controlled text: any `ed2k://|server|...|/` link pasted into
  the GUI, given on the command line, or received through the EC "add link" request.
- Fix: return false as soon as `field` would exceed 3 (e.g. `if (field > 3) return false;` before the shift).

Reproduce: `./fuzz_ed2k_link-standalone mayhem/ed2k_link/known-findings/server-ip-shift-overflow/input.bin`
