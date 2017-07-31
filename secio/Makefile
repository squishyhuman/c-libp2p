CC = gcc
CFLAGS = -O0 -Wall -I../include -I../../c-protobuf -I../../c-multiaddr/include -std=c99

ifdef DEBUG
CFLAGS += -g3
endif

LFLAGS = 
DEPS = 
OBJS = exchange.o propose.o secio.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

all: $(OBJS)

clean:
	rm -f *.o
