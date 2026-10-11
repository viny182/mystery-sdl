CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra -Wno-unused-parameter
mystery: mystery_sdl.c
	$(CC) $(CFLAGS) $$(pkg-config --cflags sdl2) -o $@ $< $$(pkg-config --libs sdl2)
clean:
	rm -f mystery
