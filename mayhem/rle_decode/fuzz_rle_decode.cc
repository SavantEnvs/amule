// Run-length + XOR-difference decoder used for the part/gap/request status bit maps that amuled sends
// to remote GUIs in EC packets (RLE_Data::Decode, both the byte and the 64-bit-array flavours).
#include <RLE.h>

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
	if (size < 3) {
		return -1;
	}
	// byte 0: bit0 = differential mode; byte 1: where to split the stream into two consecutive frames.
	const bool use_diff = data[0] & 1;
	const uint8_t *body = data + 2;
	const size_t blen = size - 2;
	const size_t split = data[1] % (blen + 1);

	RLE_Data dec(0, use_diff);
	(void)dec.Decode(body, (int)split);
	(void)dec.Decode(body + split, (int)(blen - split));

	// The 64-bit-array flavour requires (wxASSERTs) a decoded size that is a multiple of 8 -- the
	// sender always produces whole uint64 elements -- so only call it for such streams.
	RLE_Data probe(0, false);
	(void)probe.Decode(body, (int)blen);
	if (probe.Size() % 8 == 0) {
		RLE_Data dec64(0, use_diff);
		ArrayOfUInts64 out;
		dec64.Decode(body, (int)blen, out);
	}
	return 0;
}
