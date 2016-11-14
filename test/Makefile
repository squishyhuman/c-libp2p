CC = gcc
CFLAGS = -O0 -I../include -I.

ifdef DEBUG
CFLAGS += -g3
endif

LFLAGS = -L../
DEPS = crypto/test_base58.h crypto/test_rsa.h test_mbedtls.h
OBJS = testit.o 

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

testit_libp2p: $(OBJS) $(DEPS)
	$(CC) -o $@ $(OBJS) $(LFLAGS) -lp2p -lm
	
all: testit_libp2p

clean:
	rm -f *.o
	rm -f testit_libp2p
