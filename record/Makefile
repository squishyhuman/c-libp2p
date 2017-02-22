CC = gcc
CFLAGS = -O0 -I../include -I../../c-protobuf -I../../c-multihash/include -I../../c-multiaddr/include -g3
LFLAGS =
DEPS = 
OBJS = record.o message.o message_handler.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

	
all: $(OBJS)

clean:
	rm -f $(OBJS)
