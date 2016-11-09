CC = gcc
CFLAGS = -O0 -I../include -I. -g3
LFLAGS = -L../
DEPS = crypto/test_base58.h crypto/test_mbedtls.h crypto/test_rsa.h
OBJS = testit.o 

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

testit_libp2p: $(OBJS)
	$(CC) -o $@ $(OBJS) $(LFLAGS) -lp2p -lm
	
all: testit_libp2p

clean:
	rm -f *.o
	rm testit_libp2p
