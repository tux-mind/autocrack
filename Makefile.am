bin_PROGRAMS = autocrack
autocrack_SOURCES = autocrack.c common/common* parser/* engine/engine*
autocrack_LDFLAGS= -lcrypto -lm -lmagic -lcurl -lpthread
autocrack_CFLAGS = -Wall -DCONFDIR="\"$(MY_CONFDIR)\"" -Iinclude
