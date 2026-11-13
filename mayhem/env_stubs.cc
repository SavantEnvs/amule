// Same stub upstream's NetworkFunctionsTest uses so LibSocket.cpp (home of amuleIPV4Address, which
// NetworkFunctions.cpp needs) links without the daemon's GUI-notification machinery.
#include <GuiEvents.h>

namespace MuleNotify {
	void HandleNotificationAlways(const CMuleNotiferBase &) {}
}

// CAICHHash::GetString() verbatim from SHAHashSet.cpp: ED2KLink.cpp needs it, but the rest of that
// file drags in the download queue, part files and the application object.
#include <SHAHashSet.h>
#include <OtherFunctions.h>

wxString CAICHHash::GetString() const
{
	return EncodeBase32(m_abyBuffer, HASHSIZE);
}
