CC := gcc
CFLAGS := -Wall -Wextra -pthread
LDFLAGS := -lmta_rand -lmta_crypt -lcrypto

all: encrypt.out

encrypt.out: C_code.c
	$(CC) $(CFLAGS) C_code.c -o $@ $(LDFLAGS)

clean:
	rm -rf encrypt.out
