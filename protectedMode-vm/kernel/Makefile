# gcc -nostdinc -c kernel.S -o kernel.o
# ld -Ttext=0x00 -nostdlib -static kernel.o -o kernel.elf
# objcopy -O binary kernel.elf kernel.bin

NAME	:= kernel

BIN	:= $(NAME).bin
ELF	:= $(NAME).elf
OBJ	:= $(NAME).o

all: $(BIN)

$(BIN): $(ELF)
	objcopy -O binary $< $@

$(ELF): $(OBJ)
	ld -Ttext=0x00 -nostdlib -static $< -o $@

%.o: %.S
	gcc -nostdinc -c $< -o $@

clean:
	rm -f $(BIN) $(ELF) $(OBJ)
.PHONY: clean
