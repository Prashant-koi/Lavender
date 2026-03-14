CLANG ?= clang
ARCH ?= x86

BPF_SRC := execve.bpf.c
BPF_OBJ := execve.bpf.o
VMLINUX := vmlinux.h

BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) -I.

.PHONY: help vmlinux build clean disasm

help:
	@echo "Targets:"
	@echo "  make vmlinux  - Generate vmlinux.h from kernel BTF"
	@echo "  make build    - Build $(BPF_OBJ)"
	@echo "  make disasm   - Show BPF disassembly (requires llvm-objdump)"
	@echo "  make clean    - Remove generated build artifacts"

$(VMLINUX):
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX)

vmlinux: $(VMLINUX)

$(BPF_OBJ): $(BPF_SRC) $(VMLINUX)
	$(CLANG) $(BPF_CFLAGS) -c $(BPF_SRC) -o $(BPF_OBJ)

build: $(BPF_OBJ)

# Useful for quick inspection of generated BPF bytecode.
disasm: $(BPF_OBJ)
	llvm-objdump -S $(BPF_OBJ)

clean:
	rm -f $(BPF_OBJ)
