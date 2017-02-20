#include <stdlib.h>

#include "libp2p/utils/linked_list.h"

struct Libp2pLinkedList* libp2p_utils_linked_list_new() {
	struct Libp2pLinkedList* out = (struct Libp2pLinkedList*)malloc(sizeof(struct Libp2pLinkedList));
	if (out != NULL) {
		out->item = NULL;
		out->next = NULL;
	}
	return out;
}

void libp2p_utils_linked_list_free(struct Libp2pLinkedList* head) {
	struct Libp2pLinkedList* current = head;
	while (current != NULL) {
		free(current->item);
		current = current->next;
	}
}
