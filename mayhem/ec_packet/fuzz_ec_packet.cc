// Feeds a byte stream to the External Connections (EC) protocol receiver, the code amuled runs on
// every byte arriving on its remote-control TCP port: CECSocket::OnInput -> ReadHeader -> ReadPacket
// (zlib inflate, UTF-8 number decoding, nested tag parsing) -> OnPacketReceived.
#include <ECSocket.h>
#include <ECPacket.h>
#include <ECMemSocket.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

#include "../harness_common.h"

namespace {

class CFuzzECSocket : public CECSocket {
public:
	CFuzzECSocket(const uint8_t *data, size_t size, bool authorized)
		: CECSocket(false), m_data(data), m_size(size), m_pos(0), m_authorized(authorized)
	{
		// Offer every optional wire capability so ZLIB / UTF-8 numbers / large tag counts are reachable.
		m_my_flags |= EC_FLAG_ZLIB | EC_FLAG_UTF8_NUMBERS | EC_FLAG_LARGE_TAG_COUNT;
	}

	size_t Packets() const { return m_packets; }

	const CECPacket *OnPacketReceived(const CECPacket *packet, uint32 trueSize) override
	{
		(void)trueSize;
		m_packets++;
		Walk(*packet, 0);
		return nullptr;
	}

private:
	static void Walk(const CECTag &tag, int depth)
	{
		(void)tag.GetTagLen(true);
		(void)tag.GetTagName();
		if (tag.IsInt()) {
			(void)tag.GetInt();
		} else if (tag.IsString()) {
			(void)tag.GetStringDataSTL();
		}
		if (depth < 64) {
			for (CECTag::const_iterator it = tag.begin(); it != tag.end(); ++it) {
				Walk(*it, depth + 1);
			}
		}
	}

	void WriteDoneAndQueueEmpty() override {}
	bool InternalConnect(uint32_t, uint16_t, bool) override { return true; }
	bool InternalWaitOnConnect(long, long) override { return true; }
	bool InternalWaitForWrite(long, long) override { return true; }
	bool InternalWaitForRead(long, long) override { return true; }
	int  InternalGetLastError() override { return 0; }
	void InternalClose() override { m_closed = true; }
	bool InternalError() override { return false; }
	uint32 InternalRead(void *ptr, uint32 len) override
	{
		size_t n = m_size - m_pos;
		if (n > len) {
			n = len;
		}
		if (n) {
			memcpy(ptr, m_data + m_pos, n);
			m_pos += n;
		}
		return (uint32)n;
	}
	uint32 InternalWrite(const void *, uint32 len) override { return len; }
	bool InternalIsConnected() override { return !m_closed; }
	void InternalDestroy() override {}
	bool IsAuthorized() override { return m_authorized; }

	const uint8_t *m_data;
	size_t m_size;
	size_t m_pos;
	bool m_authorized;
	bool m_closed = false;
	size_t m_packets = 0;
};

} // namespace

extern "C" int LLVMFuzzerInitialize(int *, char ***)
{
	MayhemInitWx();
	return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	// First byte selects the socket state: bit0 = logged in (large packets, buffer growth allowed) vs.
	// the pre-login state a freshly accepted connection is in.
	if (size < 1) {
		return -1;
	}
	CFuzzECSocket sock(data + 1, size - 1, data[0] & 1);
	sock.OnInput();
	return 0;
}
