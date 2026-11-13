// Known-answer probe for aMule's wire/link parsers. Linked dynamically against the unsanitized
// libraries; mayhem/test.sh compares every printed line against a pinned expected value.
#include <ED2KLink.h>
#include <MagnetURI.h>
#include <MemFile.h>
#include <RLE.h>
#include <Tag.h>
#include <ECSocket.h>
#include <ECPacket.h>
#include <common/MuleDebug.h>

#include <wx/init.h>
#include <wx/log.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <vector>

static void Say(const char *key, const wxString &val)
{
	printf("%s=%s\n", key, (const char *)val.utf8_str());
}

namespace {

class CLoopSocket : public CECSocket {
public:
	CLoopSocket() : CECSocket(false) {}
	std::vector<unsigned char> wire;
	size_t rd = 0;
	uint32 opcode = 0xffff;
	wxString text;
	uint64_t number = 0;
	int packets = 0;

	const CECPacket *OnPacketReceived(const CECPacket *p, uint32) override
	{
		packets++;
		opcode = p->GetOpCode();
		const CECTag *s = p->GetTagByName(EC_TAG_STRING);
		if (s) {
			text = s->GetStringData();
		}
		const CECTag *n = p->GetTagByName(EC_TAG_CLIENT_ID);
		if (n) {
			number = n->GetInt();
		}
		return nullptr;
	}

private:
	void WriteDoneAndQueueEmpty() override {}
	bool InternalConnect(uint32_t, uint16_t, bool) override { return true; }
	bool InternalWaitOnConnect(long, long) override { return true; }
	bool InternalWaitForWrite(long, long) override { return true; }
	bool InternalWaitForRead(long, long) override { return true; }
	int  InternalGetLastError() override { return 0; }
	void InternalClose() override {}
	bool InternalError() override { return false; }
	uint32 InternalRead(void *ptr, uint32 len) override
	{
		size_t n = wire.size() - rd;
		if (n > len) {
			n = len;
		}
		memcpy(ptr, wire.data() + rd, n);
		rd += n;
		return (uint32)n;
	}
	uint32 InternalWrite(const void *ptr, uint32 len) override
	{
		const unsigned char *p = static_cast<const unsigned char *>(ptr);
		wire.insert(wire.end(), p, p + len);
		return len;
	}
	bool InternalIsConnected() override { return true; }
	void InternalDestroy() override {}
};

} // namespace

int main()
{
	wxInitialize();
	wxLog::EnableLogging(false);

	// ed2k:// links
	{
		std::unique_ptr<CED2KLink> l(CED2KLink::CreateLinkFromUrl(
			"ed2k://|file|Some%20File.bin|123456789|0123456789ABCDEF0123456789ABCDEF|/"));
		CED2KFileLink *f = static_cast<CED2KFileLink *>(l.get());
		printf("file.kind=%d\n", (int)l->GetKind());
		Say("file.name", f->GetName());
		printf("file.size=%llu\n", (unsigned long long)f->GetSize());
		Say("file.hash", f->GetHashKey().Encode());
		Say("file.link", l->GetLink());
	}
	{
		std::unique_ptr<CED2KLink> l(CED2KLink::CreateLinkFromUrl("ed2k://|server|1.2.3.4|4661|/"));
		CED2KServerLink *s = static_cast<CED2KServerLink *>(l.get());
		printf("server.kind=%d\n", (int)l->GetKind());
		printf("server.port=%u\n", (unsigned)s->GetPort());
		Say("server.link", l->GetLink());
	}
	{
		bool threw = false;
		try {
			std::unique_ptr<CED2KLink> l(CED2KLink::CreateLinkFromUrl("ed2k://|file|broken|"));
		} catch (const wxString &) {
			threw = true;
		}
		printf("bad.rejected=%d\n", threw ? 1 : 0);
	}

	// magnet: URIs
	{
		CMagnetED2KConverter c("magnet:?xt=urn:ed2k:0123456789ABCDEF0123456789ABCDEF&xl=1234&dn=Test.bin");
		printf("magnet.convertible=%d\n", c.CanConvertToED2K() ? 1 : 0);
		Say("magnet.ed2k", c.GetED2KLink());
		CMagnetURI m("magnet:?a=1&b=2&a=3");
		printf("magnet.a=%zu\n", m.GetField("a").size());
		Say("magnet.link", m.GetLink());
	}

	// RLE decode: "AAA" run, "B", then a 2-byte run of "C"
	{
		const uint8_t enc[] = {'A', 'A', 3, 'B', 'C', 'C', 2};
		RLE_Data d(0, false);
		const uint8 *out = d.Decode(enc, sizeof enc);
		printf("rle.size=%d\n", d.Size());
		printf("rle.data=%.*s\n", d.Size(), (const char *)out);
		// differential mode: second frame is XORed onto the first
		RLE_Data x(0, true);
		const uint8_t f1[] = {1, 2, 3, 4};
		x.Decode(f1, sizeof f1);
		const uint8_t f2[] = {1, 1, 4};   // run of four 0x01 bytes, XORed onto 1,2,3,4
		x.Decode(f2, sizeof f2);
		printf("rle.diff=%d,%d,%d,%d\n", x.Buffer()[0], x.Buffer()[1], x.Buffer()[2], x.Buffer()[3]);
	}

	// eD2k tag stream: short-form uint32 tag (name 1) and string tag (name 2)
	{
		const uint8_t raw[] = {0x83, 0x01, 0xEF, 0xBE, 0xAD, 0xDE,
		                       0x82, 0x02, 0x05, 0x00, 'h', 'e', 'l', 'l', 'o'};
		CMemFile mf(const_cast<uint8_t *>(raw), sizeof raw);
		CTag t1(mf, false);
		printf("tag1.name=%u int=0x%llx\n", (unsigned)t1.GetNameID(), (unsigned long long)t1.GetInt());
		CTag t2(mf, false);
		printf("tag2.name=%u\n", (unsigned)t2.GetNameID());
		Say("tag2.str", t2.GetStr());
		bool threw = false;
		try {
			const uint8_t bad[] = {0x83, 0x01, 0xEF};
			CMemFile bf(const_cast<uint8_t *>(bad), sizeof bad);
			CTag t3(bf, false);
		} catch (const CMuleException &) {
			threw = true;
		}
		printf("tag.truncated_rejected=%d\n", threw ? 1 : 0);
	}

	// EC packet: serialise, then parse back through the receive state machine
	{
		CLoopSocket tx;
		CECPacket req(EC_OP_STAT_REQ);
		req.AddTag(CECTag(EC_TAG_STRING, wxString("amule-kat")));
		req.AddTag(CECTag(EC_TAG_CLIENT_ID, (uint32_t)0x01020304));
		tx.SendPacket(&req);
		printf("ec.wire_bytes=%zu\n", tx.wire.size());
		CLoopSocket rx;
		rx.wire = tx.wire;
		rx.OnInput();
		printf("ec.packets=%d\n", rx.packets);
		printf("ec.opcode=0x%02x\n", (unsigned)rx.opcode);
		Say("ec.string", rx.text);
		printf("ec.number=0x%llx\n", (unsigned long long)rx.number);
		// a header announcing 16MB+1 must be refused rather than read
		CLoopSocket bad;
		const unsigned char hdr[8] = {0, 0, 0, 0x20, 0x01, 0x00, 0x00, 0x01};
		bad.wire.assign(hdr, hdr + 8);
		bad.OnInput();
		printf("ec.oversize_packets=%d\n", bad.packets);
	}
	return 0;
}
