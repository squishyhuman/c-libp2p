#include "libp2p/os/utils.h"

#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifndef __MINGW32__
	#include <pwd.h>
#endif
#include <unistd.h>
#include <stdio.h>
#include <dirent.h>

/**
 * get an environment varible from the os
 * @param variable the variable to look for
 * @returns the results
 */
char* os_utils_getenv(const char* variable) {
	return getenv(variable);
}

/**
 * set an environment variable in the os
 * @param variable the variable to set
 * @param value the value to assign to the variable
 * @param overwrite passing a non-zero will allow an existing value to be overwritten
 * @returns true(1) on success
 */
int os_utils_setenv(const char* variable, const char* value, int overwrite) {
#ifdef __MINGW32__
	return 0;
#else
	setenv(variable, value, overwrite);
	return 1;
#endif
}

/**
 * returns the user's home directory
 * @returns the home directory
 */
char* os_utils_get_homedir() {
#ifndef __MINGW32__
	struct passwd *pw = getpwuid(getuid());
	return pw->pw_dir;
#endif
	return ".";
}

/**
 * join 2 pieces of a filepath, being careful about the slashes
 * @param root the root part
 * @param extension what should be concatenated
 * @param results where to put the results
 * @param max_len throw an error if the total is longer than max_len
 */
int os_utils_filepath_join(const char* root, const char* extension, char* results, unsigned long max_len) {
	if (strlen(root) + strlen(extension) + 1 > max_len)
		return 0;
	strncpy(results, root, strlen(root) + 1);
	// one of these should have a slash. If not, add one
	if (root[strlen(root)-1] != '/' && extension[0] != '/') {
		results[strlen(root)] = '/';
		results[strlen(root)+1] = 0;
	}
	strncat(results, extension, strlen(extension)+1);
	return 1;
}

int os_utils_file_exists(const char* file_name) {
	if (access(file_name, F_OK) != -1)
		return 1;
	return 0;
}

/***
 * See if the passed in directory exists, and is a directory
 * @param directory_name the name to examine
 * @returns true(1) if it exists, false(0) if not
 */
int os_utils_directory_exists(const char* directory_name) {
	if (access(directory_name, F_OK) != -1 && os_utils_is_directory(directory_name))
		return 1;
	return 0;
}

/**
 * Determine if the passed in file name is a directory
 * @param file_name the file name
 * @returns true(1) if file_name is a directory
 */
int os_utils_is_directory(const char* file_name) {
	struct stat path_stat;
	stat(file_name, &path_stat);
	return S_ISDIR(path_stat.st_mode) != 0;
}

int os_utils_split_filename(const char* in, char** path, char** filename) {
	int len = strlen(in);
	char* pos = strrchr(in, '/');
	if (pos != NULL) {
		pos++;
		*path = (char*)malloc((pos - in) + 1);
		strncpy(*path, in, pos-in-1);
		(*path)[pos-in-1] = 0;
		*filename = (char*)malloc(len - (pos-in) + 1);
		strcpy(*filename, pos);
		(*filename)[len - (pos-in)] = 0;
	} else {
		*filename = (char*)malloc(len+1);
		strcpy(*filename, in);
	}
	return 1;
}

struct FileList* os_utils_list_directory(const char* path) {
	DIR* dp;
	struct dirent *ep;
	struct FileList* first = NULL;
	struct FileList* last = NULL;
	struct FileList* next = NULL;

	dp = opendir(path);
	if (dp != NULL) {
		while ( (ep = readdir(dp)) ) {
			if (strcmp(ep->d_name, ".") != 0 && strcmp(ep->d_name, "..") != 0) {
				// grab the data
				next = (struct FileList*)malloc(sizeof(struct FileList));
				next->file_name = malloc(strlen(ep->d_name) + 1);
				strcpy(next->file_name, ep->d_name);
				next->next = NULL;
				// put it in the appropriate spot
				if (first == NULL) {
					first = next;
					last = next;
				} else {
					last->next = next;
					last = next;
				}
			} // not dealing with . or ..
		} // while
		closedir(dp);
	}
	return first;
}

int os_utils_free_file_list(struct FileList* first) {
	if (first != NULL) {
		struct FileList* next = first;
		struct FileList* last = NULL;
		while (next != NULL) {
			last = next->next;
			if (next->file_name != NULL) {
				free(next->file_name);
			}
			free(next);
			next = last;
		}
	}
	return 1;
}



int os_utils_directory_writeable(const char* path) {
	int result = access(path, W_OK);
	return result == 0;
}

int os_utils_file_size(const char* path) {
	size_t file_size = 0;
	// open file
	FILE* in_file = fopen(path, "r");
	if (in_file == NULL)
		return 0;
	// determine size
	fseek(in_file, 0L, SEEK_END);
	file_size = ftell(in_file);
	fclose(in_file);
	return file_size;
}
