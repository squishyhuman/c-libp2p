struct StringList {
	char* string;
	struct StringList* next;
};

struct StringList* libp2p_utils_string_list_new();

void libp2p_utils_string_list_free(struct StringList* in);
