// eD2k/Kad tag stream reader: the TLV list found in server replies, search results, .met files and
// client hello packets. CTag(CFileDataIO&) is run over an in-memory file until it runs dry.
#include <Tag.h>
#include <MemFile.h>
#include <SafeFile.h>
#include <common/MuleDebug.h>

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
	if (size < 1) {
		return -1;
	}
	// First byte: bit0 = strings are UTF-8 (the "unicode" peer capability), as in the library API.
	const bool utf8 = data[0] & 1;
	CMemFile file(const_cast<uint8_t *>(data) + 1, size - 1);
	try {
		while (file.GetPosition() < file.GetLength()) {
			CTag tag(file, utf8);
			(void)tag.GetFullInfo();
			if (tag.IsInt()) {
				(void)tag.GetInt();
			} else if (tag.IsStr()) {
				(void)tag.GetStr();
			} else if (tag.IsHash()) {
				(void)tag.GetHash();
			} else if (tag.IsBlob()) {
				(void)tag.GetBlobSize();
			}
			delete tag.CloneTag();
		}
	} catch (const CMuleException &) {
		// Malformed/truncated tag stream: the reader reports it by exception.
		return -1;
	}
	return 0;
}
