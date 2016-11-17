CC = gcc
CFLAGS = -O0 -I../include -g3
LFLAGS =
DEPS = 
OBJS = hashmap.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

	
all: $(OBJS)

clean:
	rm -f *.o
