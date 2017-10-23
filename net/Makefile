CC = gcc
CFLAGS = -O0 -Wall -I../include -I../../c-protobuf -I../../c-multiaddr/include 

ifdef DEBUG
CFLAGS += -g3
endif

LFLAGS = 
DEPS = 
OBJS = sctp.o socket.o tcp.o udp.o multistream.o protocol.o connectionstream.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

all: $(OBJS)

clean:
	rm -f *.o
