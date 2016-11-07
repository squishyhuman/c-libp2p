OBJS = crypto/rsa.o crypto/encoding/asn1.o crypto/encoding/base58.o crypto/encoding/base64.o \
	crypto/encoding/x509.o thirdparty/mbedtls/*.o


all: 
	cd crypto; make all;
	cd thirdparty; make all;
	ar rcs libp2p.a $(OBJS)
	
clean:
	cd crypto; make clean;
	cd thirdparty; make clean
	rm -rf libp2p.a
	