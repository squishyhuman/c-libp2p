/**
 * A playground for testing mbedtls functions
 */

#include "mbedtls/bignum.h"

int convertToString(unsigned char* string, int len) {
	// load up the mpi
	mbedtls_mpi mpi;
	mbedtls_mpi_init(&mpi);
	int retVal = mbedtls_mpi_read_binary(&mpi, string, len);
	if (retVal < 0) {
		mbedtls_mpi_free(&mpi);
		return 0;
	}

	// put it in string form so we can see it
	size_t buffer_len = 50;
	size_t output_len = 0;
	char buffer[buffer_len];
	retVal = mbedtls_mpi_write_string(&mpi, 10, buffer, buffer_len, &output_len);
	if (retVal < 0) {
		mbedtls_mpi_free(&mpi);
		return 0;
	}
	for(int i = 0; i < output_len; i++) {
		printf("%02x", buffer[i]);
	}
	printf("\n");
	mbedtls_mpi_free(&mpi);
	return 1;
}

int test_mbedtls_varint_128_binary() {
	// the values I'm working with 0x08, 0x00, 0x18, 0xa7, 0x09
	unsigned char starting_val[5] = { 0x08, 0x00, 0x18, 0x87, 0x09 };
	size_t starting_len = 5;

	for(int i = 0; i < 5; i++) {
		if (convertToString(&starting_val[i], 5 - i) != 1)
			return 0;
	}

	printf(" 3 and 4\n");
	if (convertToString(&starting_val[2], 2) != 1) {
		return 0;
	}

	printf("And now the other way...\n");

	for(int i = 1; i <= 5; i--) {
		if (convertToString(starting_val, i) != 1)
			return 0;
	}


	return 1;
}

int test_mbedtls_varint_128_string() {
	// go from string to uint_128 and back again
	char* bigint_string = "47942806932686753431";

	mbedtls_mpi mpi;

	mbedtls_mpi_init(&mpi);

	int retVal = mbedtls_mpi_read_string( &mpi, 10, bigint_string );
	if (retVal < 0) {
		mbedtls_mpi_free(&mpi);
		return 0;
	}

	// now go back again
	size_t buffer_len = 50;
	size_t output_len = 0;
	char buffer[buffer_len];
	retVal = mbedtls_mpi_write_string(&mpi, 10, buffer, buffer_len, &output_len);
	if (retVal < 0) {
		mbedtls_mpi_free(&mpi);
		return 0;
	}
	if (strcmp(buffer, bigint_string) != 0) {
		mbedtls_mpi_free(&mpi);
		return 0;
	}
	mbedtls_mpi_free(&mpi);
	return 1;
}
