#ifndef ZINFLATE_H
#define ZINFLATE_H

#include <stddef.h>

/* 将 raw DEFLATE（ZIP 使用的、无 zlib 头的 deflate 流）解压到 out 缓冲区。
 * 返回 0 表示成功；outLen 回写实际输出字节数。 */
int zraw_inflate(const unsigned char* in, unsigned long inLen,
                 unsigned char* out, unsigned long outCap,
                 unsigned long* outLen);

#endif
