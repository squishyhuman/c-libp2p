#pragma once

struct Libp2pLinkedList {
	void* item;
	void* next;
};

/***
 * Create a new linked list struct
 * @returns a new linked list struct
 */
struct Libp2pLinkedList* libp2p_utils_linked_list_new();

/**
 * Free resources from a linked list
 * @param head the top of the linked list
 */
void libp2p_utils_linked_list_free(struct Libp2pLinkedList* head);
