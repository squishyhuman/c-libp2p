#include <stdlib.h>

#include "libp2p/utils/string_list.h"

struct StringList* libp2p_utils_string_list_new() {
	struct StringList* list = (struct StringList*)malloc(sizeof(struct StringList));
	if (list != NULL)
	{
		list->next = NULL;
		list->string = NULL;
	}
	return list;
}

void libp2p_utils_string_list_free(struct StringList* list) {
	struct StringList* current = list;
	struct StringList* temp = NULL;

	while(current != NULL) {
		if (current->string != NULL)
			free(current->string);
		temp = current->next;
		free(current);
		current = temp;
	}
}
