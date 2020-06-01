######## Variables ########

AUTO_GEN_FILES := l1_asm.h l2_asm.h

LIB         := libcachesc.a
LIBSRCS     := cache.c util.c victim.c addr_translation.c
LIBHEADERS  := cachesc.h io.h asm.h cache_types.h device_conf.h \
			   $(AUTO_GEN_FILES)
LIBOBJS     := $(LIBSRCS:.c=.o)

CC          := gcc
CFLAGS      := -std=gnu99 -O1 -Winline
CURR_PATH	:= $(realpath $(dir $(realpath $(firstword $(MAKEFILE_LIST)))))

ifeq ($(INST_PATH),)
    INST_PATH = $(realpath $(dir $(CURR_PATH)))
endif

LIB_DIR		:= $(INST_PATH)/lib
INCL_DIR	:= $(INST_PATH)/include
HEADERS 	:= $(LIBHEADERS) $(LIBSRCS:.c=.h)

# Uncomment to suppress asserts
# CFLAGS += DNDEBUG

######## Targets ########

all: gen $(LIB) build-lib install

gen:
	./gen_cache_asm_files.py

build-lib:
	ar rcs $(LIB) $(LIBHEADERS) $(LIBOBJS)
	ranlib $(LIB)

install:
	cp $(CURR_PATH)/$(LIB) $(LIB_DIR)/
	cp $(CURR_PATH)/$(HEADERS) $(INCL_DIR)/

clean:
	rm -f $(LIB) $(LIBOBJS) $(AUTO_GEN_FILES) $(LIB_DIR)/$(LIB)

rebuild: clean all

$(LIB): $(LIBOBJS)
