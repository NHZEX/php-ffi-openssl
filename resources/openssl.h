void OPENSSL_config(const char *config_name);
void OPENSSL_no_config(void);

void CRYPTO_cleanup_all_ex_data(void);
void OPENSSL_add_all_algorithms_conf(void);
void OPENSSL_add_all_algorithms_noconf(void);

void ERR_load_crypto_strings(void);
void ERR_free_strings(void);

unsigned long ERR_get_error(void);
char *ERR_error_string(unsigned long e, char *buf);