#pragma once

struct Libp2pLinkedList {
	void* item;
	struct Libp2pLinkedList* next;
};

/***
 * Create a new linked list struct
 * @returns a new linked list struct
 */
struct Libp2pLinkedList* libp2p_utils_linked_list_new();

/**
 * Free resources from a linked list
 * NOTE: if the item is a complex object, free the item before
 * you call this method, and set item to NULL. Otherwise, this
 * method will call a simple free()
 * @param head the top of the linked list
 */
void libp2p_utils_linked_list_free(struct Libp2pLinkedList* head);
