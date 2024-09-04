SRCS     := $(wildcard *.asm)
EFI_APPS := $(SRCS:.asm=.efi)

.PHONY: all clean

all: $(EFI_APPS)

%.efi: %.asm
	nasm -fbin -o $@ $^

clean:
	rm -f $(EFI_APPS)
