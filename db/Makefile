CC = gcc
CFLAGS = -O0 -I../include -I../../c-protobuf -I../../c-multihash/include -I../../c-multiaddr/include -g3 -std=c99
LFLAGS =
DEPS = 
OBJS = datastore.o filestore.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

	
all: $(OBJS)

clean:
	rm -f $(OBJS)
