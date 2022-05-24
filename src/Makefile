BUILD_DIR?=../build/

include $(BUILD_DIR)/software/include/generated/variables.mak
include $(SOC_DIRECTORY)/software/common.mak


OBJDIR = ./obj
EXT_LIBDIR = ../ext_lib
OBJECTS = $(OBJDIR)/isr.o $(OBJDIR)/main.o $(OBJDIR)/crt0.o $(OBJDIR)/test_aes.o

INCLUDES += -I$(EXT_LIBDIR)/tinycrypt \
			-I$(EXT_LIBDIR)/tinycrypt/tests \
			-I$(EXT_LIBDIR)/tinycrypt/tests/include \
			-I$(EXT_LIBDIR)/tinycrypt/lib/include \

all: demo.bin

# pull in dependency info for *existing* .o files
-include $(OBJECTS:.o=.d)

%.bin: %.elf
	$(OBJCOPY) -O binary $< $@
	chmod -x $@

demo.elf: $(OBJECTS)
	$(CC) $(LDFLAGS) \
		-T linker.ld \
		-N -o $@ \
		$(OBJECTS) \
		$(PACKAGES:%=-L$(BUILD_DIR)/software/%) \
		-L$(EXT_LIBDIR)/tinycrypt/lib \
		$(LIBS:lib%=-l%) \
		-ltinycrypt \
		-lgcc 
	chmod -x $@

$(OBJDIR)/main.o: main.c
	$(compile)

$(OBJDIR)/crt0.o: $(CPU_DIRECTORY)/crt0.S
	$(assemble)

$(OBJDIR)/%.o: %.cpp
	$(compilexx)

$(OBJDIR)/%.o: %.c
	$(compile)

$(OBJDIR)/test_aes.o: $(EXT_LIBDIR)/tinycrypt/tests/test_aes.c
	$(compile)

$(OBJDIR)/%.o: %.S
	$(assemble)

clean:
	$(RM) $(OBJECTS) $(OBJECTS:.o=.d) demo.elf demo.bin .*~ *~

.PHONY: all main.o clean load
