
DEBUG = true
export DEBUG

OBJS = crypto/*.o crypto/encoding/*.o thirdparty/mbedtls/*.o hashmap/hashmap.o record/*.o routing/*.o


compile: 
	cd crypto; make all;
	cd thirdparty; make all;
	cd hashmap; make all;
	cd record; make all;
	cd routing; make all;
	cd secio; make all;
	ar rcs libp2p.a $(OBJS)
	
test: compile
	cd test; make all;
	
rebuild: clean all
	
all: test
	
clean:
	cd crypto; make clean;
	cd hashmap; make clean;
	cd thirdparty; make clean
	cd test; make clean;
	cd record; make clean;
	cd routing; make clean;
	cd secio; make all;
	rm -rf libp2p.a

