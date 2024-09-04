SRCS = $(wildcard **/*.asm)
BINS = $(SRCS:.asm=)

.PHONY: all clean test

all: $(BINS)
	@for f in $(BINS); do \
		echo "$$f: $$(stat -c %s $$f) bytes - $$(file $$f | cut -d' ' -f2-)"; \
	done

%: %.asm
	nasm -fbin -o $@ $^
	chmod +x $@

test: all
	@for f in $(BINS); do \
		pad="$$(printf '%*s' $$((52 - $${#f})) '' | tr ' ' -)"; \
		echo "---[$$f]$$pad"; \
		"$$f" || true; \
	done

clean:
	rm -f $(BINS)
