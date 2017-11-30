CC = gcc
CFLAGS = -O0 -Wall -I../include -I../../c-multiaddr/include -std=c99

ifdef DEBUG
CFLAGS += -g3
endif

LFLAGS = 
DEPS = 
OBJS = string_list.o vector.o linked_list.o logger.o urlencode.o thread_pool.o threadsafe_buffer.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

all: $(OBJS)

clean:
	rm -f *.o
