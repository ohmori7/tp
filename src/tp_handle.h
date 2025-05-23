struct tp_handle;

struct tp_handle *tp_handle_register(const char *, int (*)(struct tp_option *, int, char * const []),
    int (*)(struct tp_option *, int, char * const []));
struct tp_handle *tp_handle_lookup_by_name(const char *);
int tp_handle_client(struct tp_handle *, struct tp_option *, int, char * const []);
int tp_handle_server(struct tp_handle *, struct tp_option *, int, char * const []);
