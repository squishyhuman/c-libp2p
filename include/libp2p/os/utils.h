/**
 * OS specific stuff. This is going to get ugly, but at least its in one place
 */
#ifndef __OS_UTILS_H__
#define __OS_UTILS_H__

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/**
 * a linked list to store filenames
 */
struct FileList {
	char* file_name;
	struct FileList* next;
};

/**
 * Builds a list of files within a directory
 * @param path the path to examine
 * @returns a FileList struct of the first file
 */
struct FileList* os_utils_list_directory(const char* path);

/**
 * Cleans up memory used by a FileList struct
 * @param first the struct to free
 * @returns true(1)
 */
int os_utils_free_file_list(struct FileList* first);

/**
 * Split the filename from the path
 * @param in the full path and filename
 * @param path only the path part
 * @param filename only the file name
 * @returns true(1)
 */
int os_utils_split_filename(const char* in, char** path, char** filename);


/**
 * get an environment varible from the os
 * @param variable the variable to look for
 * @returns the results
 */
char* os_utils_getenv(const char* variable);
int os_utils_setenv(const char* variable, const char* value, int overwrite);
/**
 * get the user's home directory
 * @returns the user's home directory
 */
char* os_utils_get_homedir();

/**
 * join 2 pieces of a filepath, being careful about the slashes
 * @param root the root part
 * @param extension what should be concatenated
 * @param results where to put the results
 * @param max_len throw an error if the total is longer than max_len
 */
int os_utils_filepath_join(const char* root, const char* extension, char* results, unsigned long max_len);

int os_utils_file_exists(const char* file_name);

int os_utils_file_size(const char* file_name);

int os_utils_directory_writeable(const char* path);

int os_utils_directory_exists(const char* path);

/**
 * Determine if the path presented is actually a directory
 * @param file_name the path to examine
 * @returns true(1) if file_name is actually a directory
 */
int os_utils_is_directory(const char* file_name);

#endif /* utils_h */
