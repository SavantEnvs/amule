// Shared one-time init for the aMule harnesses: bring up wxBase without an app object.
#ifndef MAYHEM_HARNESS_COMMON_H
#define MAYHEM_HARNESS_COMMON_H

#include <wx/init.h>
#include <wx/log.h>

#include <cstdio>

static inline void MayhemInitWx()
{
	wxInitialize();
	wxLog::EnableLogging(false);
	// A few library paths printf() progress notes to stdout; keep them out of the fuzzer's output.
	(void)freopen("/dev/null", "w", stdout);
}

#endif
