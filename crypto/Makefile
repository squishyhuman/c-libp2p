CC = gcc
CFLAGS = -O0 -I../include -I../../c-protobuf -I../../c-multihash/include -g3
LFLAGS =
DEPS = 
OBJS = rsa.o sha256.o sha512.o sha1.o key.o peerutils.o ephemeral.o aes.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

	
all: $(OBJS)
	cd encoding; make all;

clean:
	rm -f *.o
	cd encoding; make clean;
