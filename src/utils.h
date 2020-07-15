#include <ctype.h>
#include <sys/types.h>

int get_cmd_path(const char *prog_name, char *buf, size_t buf_len);
int hex_to_bin(char ch);
int hex2bin(void *dst, const char *src, size_t count);
