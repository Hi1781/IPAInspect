#include "zinflate.h"
#include <zlib.h>
#include <string.h>

int zraw_inflate(const unsigned char* in, unsigned long inLen,
                 unsigned char* out, unsigned long outCap,
                 unsigned long* outLen) {
    z_stream s;
    memset(&s, 0, sizeof(s));
    /* -15 => raw deflate，无 zlib 头（ZIP 存储方式） */
    if (inflateInit2(&s, -15) != Z_OK) return -1;
    s.next_in  = (Bytef*)in;
    s.avail_in = (uInt)inLen;
    s.next_out = (Bytef*)out;
    s.avail_out = (uInt)outCap;
    int r = inflate(&s, Z_FINISH);
    *outLen = (unsigned long)s.total_out;
    inflateEnd(&s);
    return (r == Z_STREAM_END) ? 0 : 1;
}
