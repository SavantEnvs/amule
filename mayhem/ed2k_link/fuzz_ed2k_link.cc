// ed2k:// link parser (file, server and server-list links), as used when a link is pasted into the
// GUI, passed on the command line or received through the EC "add link" request.
#include <ED2KLink.h>
#include <MemFile.h>
#include <SafeFile.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

#include "../harness_common.h"

extern "C" int LLVMFuzzerInitialize(int *, char ***)
{
	MayhemInitWx();
	return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	wxString link = wxString::FromUTF8(reinterpret_cast<const char *>(data), size);
	// The parsers take a wxString, which every real caller builds from text; FromUTF8 yields an empty string for bytes that aren't UTF-8, so those never reach the parser.
	if (link.IsEmpty() && size) {
		return -1;
	}
	try {
		std::unique_ptr<CED2KLink> parsed(CED2KLink::CreateLinkFromUrl(link));
		if (!parsed) {
			return -1;
		}
		(void)parsed->GetLink();
		switch (parsed->GetKind()) {
		case CED2KLink::kFile: {
			CED2KFileLink *f = static_cast<CED2KFileLink *>(parsed.get());
			(void)f->GetName();
			(void)f->GetSize();
			(void)f->HasValidAICHHash();
			(void)f->GetHashKey().Encode();
			if (f->m_hashset) {
				f->m_hashset->Seek(0, wxFromStart);
			}
			break;
		}
		case CED2KLink::kServer: {
			CED2KServerLink *s = static_cast<CED2KServerLink *>(parsed.get());
			(void)s->GetIP();
			(void)s->GetPort();
			break;
		}
		case CED2KLink::kServerList: {
			CED2KServerListLink *l = static_cast<CED2KServerListLink *>(parsed.get());
			(void)l->GetAddress();
			break;
		}
		default:
			break;
		}
	} catch (const wxString &) {
		// The parser reports malformed links by throwing a wxString message.
		return -1;
	}
	return 0;
}
