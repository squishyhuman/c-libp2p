DHT_DIR = dht
CC = gcc
CFLAGS = -O0 -I../include -I../../c-multiaddr/include -I$(DHT_DIR) -g3
LFLAGS =
DEPS = $(DHT_DIR)/dht.h
OBJS = kademlia.o dht.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

all: $(OBJS)

$(DHT_DIR)/dht.h:
	git clone https://github.com/jech/dht.git $(DHT_DIR)

dht.c: $(DEPS)
	ln -s $(DHT_DIR)/dht.c .

clean:
	rm -f $(OBJS) dht.c
	rm -rf $(DHT_DIR)
