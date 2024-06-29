#include <stdint.h>
#include <stddef.h>  // Include this header for size_t
#include <string.h>

#define SERIAL_PORT 0xE9
#define COMMAND_PORT 0x0278

#define OPEN 0x11
#define CLOSE 0x12
#define WRITE 0x13
#define READ 0x14

static void outb(uint16_t port, uint8_t value) {
    asm volatile ("outb %0, %1" : : "a"(value), "Nd"(port));
}

static uint8_t inb(uint16_t port) {
    uint8_t ret;
    asm volatile ("inb %1, %0" : "=a"(ret) : "Nd"(port));
    return ret;
}

static uint32_t open_file(const char *filename) {
    outb(COMMAND_PORT, OPEN);
    while (*filename) {
        outb(COMMAND_PORT, *filename++);
    }
    outb(COMMAND_PORT, '\0');

    char privilege[2]={'a','\0'};
    outb(COMMAND_PORT, privilege[0]);
    outb(COMMAND_PORT, privilege[1]);

    return inb(COMMAND_PORT);
}

static void write_file(uint32_t file_id, const char *content) {
    outb(COMMAND_PORT, WRITE);
    outb(SERIAL_PORT, file_id+'0');
    outb(COMMAND_PORT, file_id);
    outb(COMMAND_PORT,'\0');
    while (*content) {
        outb(COMMAND_PORT, *content++);
    }
    outb(COMMAND_PORT, '\0');
}

static void read_file(uint32_t file_id, char *buffer, size_t size) {
    outb(COMMAND_PORT, READ);
    outb(COMMAND_PORT, file_id + '0');
    for (size_t i = 0; i < size - 1; i++) {
        buffer[i] = inb(COMMAND_PORT);
        if (buffer[i] == '\0') break;
    }
    buffer[size - 1] = '\0';
}

static void close_file(uint32_t file_id) {
    outb(COMMAND_PORT, CLOSE);
    outb(COMMAND_PORT, file_id + '0');
}

static void print_to_serial(const char *str) {
    while (*str) {
        outb(SERIAL_PORT, *str++);
    }
}

void __attribute__((noreturn)) __attribute__((section(".start"))) _start(void) {
    const char *filename = "test123.txt";
    const char *content = "Hello from guest3!\n";
    char buffer[32];

    uint32_t file_id = open_file(filename);

    write_file(file_id, content);

    read_file(file_id, buffer, sizeof(buffer));

    print_to_serial(buffer);

    close_file(file_id);

    for (;;) {
        asm volatile ("hlt");
    }
}