#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// grsec

void * __attribute__((size_overflow(1))) coolmalloc(size_t size)
{
	return malloc(size);
}

void report_size_overflow(const char *file, unsigned int line, const char *func, const char *ssa_name)
{
	printf("SIZE_OVERFLOW: size overflow detected in function %s %s:%u %s", func, file, line, ssa_name);
	fflush(stdout);
	_exit(1);
}

int main(int argc, char *argv[])
{
	unsigned long a;
	unsigned long b;

	a = strtoul(argv[1], NULL, 0);
	b = strtoul(argv[2], NULL, 0);
	return printf("%p\n", coolmalloc(a * b));
}
