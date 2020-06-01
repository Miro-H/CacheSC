######## Variables ########

CURR_PATH := $(realpath $(dir $(realpath $(firstword $(MAKEFILE_LIST)))))

ifeq ($(INST_PATH),)
    INST_PATH = $(realpath $(dir $(CURR_PATH)))
endif

ifeq ($(OPENSSL_INCL),)
    OPENSSL_INCL = /usr/local/include
endif

ifeq ($(OPENSSL_LIB),)
    OPENSSL_LIB = /usr/local/lib
endif

ifeq ($(ARGON_INCL),)
    ARGON_INCL = /usr/include
endif

ifeq ($(ARGON_LIB),)
    ARGON_LIB = /usr/lib/x86_64-linux-gnu
endif

CFLAGS  += -std=gnu99 -D_ISOC11_SOURCE=1 -O1 -Winline

## CacheSC
CFLAGS  += -I$(INST_PATH)/include
LDFLAGS += -L$(INST_PATH)/lib
LDLIBS  += -lcachesc

## OpenSSL
CFLAGS  += -I$(OPENSSL_INCL)
LDFLAGS += -L$(OPENSSL_LIB)
LDLIBS  += -lcrypto

## Argon2
CFLAGS  += -I$(ARGON_INCL)
LDFLAGS += -L$(ARGON_LIB) -static
LDLIBS  += -largon2 -pthread

CC	:= gcc
OUT := single-eviction openssl-aes-cbc argon2d-attacker argon2d-victim

ifneq ($(NORMALIZE),)
    CFLAGS += -DNORMALIZE=$(NORMALIZE)
endif

######## Targets ########

all: $(OUT)

rebuild: clean all

clean:
	rm -rf *.o $(OUT)

$(OUT):
	$(CC) $(CFLAGS) -o $@ $(@:=.c) $(LDFLAGS) $(LDLIBS)
