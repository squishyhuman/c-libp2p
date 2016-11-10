
DEBUG = true
export DEBUG

OBJS = crypto/rsa.o crypto/encoding/base58.o crypto/encoding/base64.o \
	crypto/encoding/x509.o thirdparty/mbedtls/*.o


compile: 
	cd crypto; make all;
	cd thirdparty; make all;
	ar rcs libp2p.a $(OBJS)
	
test: compile
	cd test; make all;
	
all: test
	
clean:
	cd crypto; make clean;
	cd thirdparty; make clean
	cd test; make clean;
	rm -rf libp2p.a

