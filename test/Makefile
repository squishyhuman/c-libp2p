CC = gcc
CFLAGS = -O0 -I../include -I. -I../../c-multihash/include -I../../c-multiaddr/include -std=c99

ifdef DEBUG
CFLAGS += -g3
endif

LFLAGS = -L../ -L../../c-multihash -L../../c-multiaddr
DEPS = crypto/test_base58.h crypto/test_rsa.h test_mbedtls.h
OBJS = testit.o ../../c-protobuf/protobuf.o ../../c-protobuf/varint.o ../libp2p.a

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

testit_libp2p: $(OBJS) $(DEPS)
	$(CC) -o $@ $(OBJS) $(LFLAGS) -lp2p -lm -lmultihash -lmultiaddr -lpthread
	
all_others:
	cd ../crypto; make all;
	cd ../thirdparty; make all;

all: all_others testit_libp2p

clean:
	rm -f *.o
	rm -f testit_libp2p

test: clean testit_libp2p
