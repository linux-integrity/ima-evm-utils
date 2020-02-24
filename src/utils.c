#include <stdint.h>

#include "utils.h"

int hex_to_bin(char ch)
{
	if ((ch >= '0') && (ch <= '9'))
		return ch - '0';
	ch = tolower(ch);
	if ((ch >= 'a') && (ch <= 'f'))
		return ch - 'a' + 10;
	return -1;
}

int hex2bin(void *dst, const char *src, size_t count)
{
	int hi, lo;

	while (count--) {
		if (*src == ' ')
			src++;

		hi = hex_to_bin(*src++);
		lo = hex_to_bin(*src++);

		if ((hi < 0) || (lo < 0))
			return -1;

		*(uint8_t *)dst++ = (hi << 4) | lo;
	}
	return 0;
}
