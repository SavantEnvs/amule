// magnet: URI parser and its magnet -> ed2k:// converter.
#include <MagnetURI.h>

#include <cstddef>
#include <cstdint>

#include "../harness_common.h"

extern "C" int LLVMFuzzerInitialize(int *, char ***)
{
	MayhemInitWx();
	return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	wxString uri = wxString::FromUTF8(reinterpret_cast<const char *>(data), size);
	// The parsers take a wxString, which every real caller builds from text; FromUTF8 yields an empty string for bytes that aren't UTF-8, so those never reach the parser.
	if (uri.IsEmpty() && size) {
		return -1;
	}
	CMagnetURI magnet(uri);
	(void)magnet.GetLink();
	(void)magnet.GetField("xt");
	(void)magnet.GetField("dn");
	CMagnetED2KConverter conv(uri);
	if (conv.CanConvertToED2K()) {
		(void)conv.GetED2KLink();
	}
	return 0;
}
