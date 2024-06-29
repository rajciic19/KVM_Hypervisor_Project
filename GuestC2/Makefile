guest.img: guest.o
	ld -T guest.ld guest.o -o guest.img

guest1.img: guest1.o
	ld -T guest1.ld guest1.o -o guest1.img

guest2.img: guest2.o
	ld -T guest2.ld guest2.o -o guest2.img

guest.o: guest.c
	$(CC) -m64 -ffreestanding -fno-pic -c -o $@ $^

guest1.o: guest.c
	$(CC) -m64 -ffreestanding -fno-pic -c -o $@ $^

guest2.o: guest.c
	$(CC) -m64 -ffreestanding -fno-pic -c -o $@ $^
clean:
	rm -f guest.o guest.img guest1.img guest1.o guest2.img guest2.o
