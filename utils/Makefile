CC = gcc
CFLAGS = -O0 -Wall -I../include -I../../c-multiaddr/include

ifdef DEBUG
CFLAGS += -g3
endif

LFLAGS = 
DEPS = 
OBJS = string_list.o vector.o linked_list.o multiaddress.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

all: $(OBJS)

clean:
	rm -f *.o
