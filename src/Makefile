BUILD_DIR?=../build/

include $(BUILD_DIR)/software/include/generated/variables.mak
include $(SOC_DIRECTORY)/software/common.mak

OBJDIR = ./obj
EXT_LIBDIR = ../ext_lib
MBED_LIB = $(EXT_LIBDIR)/mbedtls/library

TINY_CRYPT_OBJ := $(OBJDIR)/aes_decrypt.o \
				$(OBJDIR)/aes_encrypt.o \
				$(OBJDIR)/ctr_mode.o \
				$(OBJDIR)/ctr_prng.o \
				$(OBJDIR)/ccm_mode.o \
				$(OBJDIR)/cmac_mode.o \
				$(OBJDIR)/utils.o 

OBJECTS := $(TINY_CRYPT_OBJ) \
		  $(OBJDIR)/isr.o \
		  $(OBJDIR)/main.o \
		  $(OBJDIR)/crt0.o

INCLUDES += -I$(EXT_LIBDIR)/tinycrypt \
			-I$(EXT_LIBDIR)/tinycrypt/tests \
			-I$(EXT_LIBDIR)/tinycrypt/tests/include \
			-I$(EXT_LIBDIR)/tinycrypt/lib/include \
			-I$(EXT_LIBDIR)/mbedtls \
			-I$(EXT_LIBDIR)/mbedtls/include \

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
		-L$(MBED_LIB) \
		$(LIBS:lib%=-l%) \
		-ltinycrypt \
		-lmbedcrypto \
		-lgcc 
	chmod -x $@

$(OBJDIR)/main.o: main.c $(MBED_LIB)/libmbedcrypto.a $(EXT_LIBDIR)/tinycrypt/lib/libtinycrypt.a
	$(compile)

	

$(OBJDIR)/crt0.o: $(CPU_DIRECTORY)/crt0.S
	$(assemble)

$(OBJDIR)/%.o: %.cpp
	$(compilexx)

$(OBJDIR)/%.o: %.c
	$(compile)

$(OBJDIR)/%.o: $(EXT_LIBDIR)/tinycrypt/lib/source/%.c
	$(compile)

$(EXT_LIBDIR)/tinycrypt/lib/libtinycrypt.a: $(TINY_CRYPT_OBJ)
	$(AR) $(ARFLAGS) $@ $^

$(OBJDIR)/%.o: %.S
	$(assemble)

clean:
	$(RM) $(OBJECTS) $(OBJECTS:.o=.d) $(EXT_LIBDIR)/tinycrypt/lib/libtinycrypt.a demo.elf demo.bin .*~ *~

.PHONY: all main.o clean load
