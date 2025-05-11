struct tp_option {
	const char *to_protoname;
	const char *to_addrname;
	const char *to_servicename;
	const char *to_filename;
	const char *to_ccname;
};

void tp_option_init(struct tp_option *);
