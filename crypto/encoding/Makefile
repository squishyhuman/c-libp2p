CC = gcc
CFLAGS = -O0 -I../../include -g3
LFLAGS =
DEPS = 
OBJS = asn1.o base58.o base64.o x509.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

	
all: $(OBJS)

clean:
	rm -f *.o
