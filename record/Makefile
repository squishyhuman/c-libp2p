CC = gcc
CFLAGS = -O0 -I../include -I../../c-protobuf -I../../c-multihash/include -g3
LFLAGS =
DEPS = 
OBJS = record.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

	
all: $(OBJS)

clean:
	rm -f $(OBJS)
