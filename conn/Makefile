CC = gcc
CFLAGS = -O0 -I../include -I../../c-protobuf -I../../c-multihash/include -I../../c-multiaddr/include -g3
LFLAGS =
DEPS = 
OBJS = dialer.o transport_dialer.o connection.o tcp_transport_dialer.o session.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

	
all: $(OBJS)

clean:
	rm -f *.o
