bin_PROGRAMS = autocrack
autocrack_SOURCES = autocrack.c common/common* parser/* engine/engine*
autocrack_LDFLAGS= -lm
autocrack_CFLAGS = -Wall -Iinclude

check-local:
	test/test.sh
