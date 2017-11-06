CC = gcc
CFLAGS = -O0 -I../include -I../../c-protobuf -I../../c-multihash/include -I../../c-multiaddr/include -g3 -std=c11
LFLAGS =
DEPS = 
OBJS = peer.o peerstore.o providerstore.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

	
all: $(OBJS)

clean:
	rm -f $(OBJS)
