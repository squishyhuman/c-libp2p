
DEBUG = true
export DEBUG

OBJS = \
	conn/*.o \
	crypto/*.o \
	crypto/encoding/*.o \
	db/*.o \
	thirdparty/mbedtls/*.o \
	hashmap/hashmap.o \
	net/*.o \
	nodeio/*.o \
	os/*.o \
	peer/*.o \
	record/*.o \
	routing/*.o \
	secio/*.o \
	utils/*.o

link: 
	ar rcs libp2p.a $(OBJS)

compile:
	cd conn; make all;
	cd crypto; make all;
	cd db; make all;
	cd thirdparty; make all;
	cd hashmap; make all;
	cd net; make all;
	cd nodeio; make all;
	cd os; make all;
	cd peer; make all;
	cd record; make all;
	cd routing; make all;
	cd secio; make all;
	cd utils; make all;
	
test: compile link
	cd test; make all;
	
rebuild: clean all
	
all: test
	
clean:
	cd conn; make clean;
	cd crypto; make clean;
	cd db; make clean;
	cd hashmap; make clean;
	cd net; make clean;
	cd nodeio; make clean;
	cd os; make clean;
	cd peer; make clean;
	cd thirdparty; make clean
	cd record; make clean;
	cd routing; make clean;
	cd secio; make clean;
	cd utils; make clean;
	cd test; make clean;
	rm -rf libp2p.a

