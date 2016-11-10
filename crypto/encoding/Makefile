CC = gcc
CFLAGS = -O0 -I../../include -g3
LFLAGS =
DEPS = ../../include/libp2p/crypto/encoding/base58.h ../../include/libp2p/crypto/encoding/base64.h \
	../../include/libp2p/crypto/encoding/x509.h
OBJS = base58.o base64.o x509.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

	
all: $(OBJS)

clean:
	rm -f *.o
