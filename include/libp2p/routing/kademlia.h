#pragma once

int start_kademlia(int sock, int family, char* peer_id, int timeout);
void stop_kademlia (void);

void *kademlia_thread (void *ptr);
void *announce_thread (void *ptr);

int announce_once_kademlia(unsigned char* id, uint16_t port, int timeout);

int announce_kademlia (char* peer_id, uint16_t port);
int search_kademlia(char* peer_id, int timeout);

int ping_kademlia (char *ip, uint16_t port);
