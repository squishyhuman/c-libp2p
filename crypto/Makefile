CC = gcc
CFLAGS = -O0 -I../include
LFLAGS =
DEPS = 
OBJS = rsa.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

	
all: $(OBJS)
	cd encoding; make all;

clean:
	rm -f *.o
	cd encoding; make clean;
