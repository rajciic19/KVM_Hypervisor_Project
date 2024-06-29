#include <stdint.h>

#define SERIAL_PORT 0xE9

static void outb(uint16_t port, uint8_t value) {
	asm("outb %0,%1" : /* empty */ : "a" (value), "Nd" (port) : "memory");
}

void
__attribute__((noreturn))
__attribute__((section(".start")))_start(void) {

	/*
		INSERT CODE BELOW THIS LINE
	*/

	const char *p;
	uint16_t port = 0xE9;
	uint8_t value = 'E';

	asm("outb %0,%1" : /* empty */ : "a" (value), "Nd" (port) : "memory");
	/*for (p = "Hello, world from guest!\n"; *p; ++p)
		outb(0xE9, *p);*/

	/*
		INSERT CODE ABOVE THIS LINE
	*/

	for (;;)
		asm("hlt");
}