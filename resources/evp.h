void EVP_cleanup(void);

typedef struct evp_pkey_asn1_method_st EVP_PKEY_ASN1_METHOD;

typedef struct evp_pkey_st EVP_PKEY;
typedef struct evp_cipher_st EVP_CIPHER;
typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;

struct evp_pkey_st {
  int type;
  int save_type;
  int references;
  const EVP_PKEY_ASN1_METHOD *ameth;
  ENGINE *engine;
  union {
    char *ptr;
    struct rsa_st *rsa;
    struct dsa_st *dsa;
    struct dh_st *dh;
    struct ec_key_st *ec;
    struct gost_key_st *gost;
  } pkey;
  int save_parameters;
  struct stack_st_X509_ATTRIBUTE *attributes;
};

struct evp_cipher_st {
  int nid;
  int block_size;
  int key_len;
  int iv_len;
  unsigned long flags;
  int (*init)(EVP_CIPHER_CTX *ctx, const unsigned char *key,
              const unsigned char *iv, int enc);
  int (*do_cipher)(EVP_CIPHER_CTX *ctx, unsigned char *out,
                   const unsigned char *in, size_t inl);
  int (*cleanup)(EVP_CIPHER_CTX *);
  int ctx_size;
  int (*set_asn1_parameters)(EVP_CIPHER_CTX *, ASN1_TYPE *);
  int (*get_asn1_parameters)(EVP_CIPHER_CTX *, ASN1_TYPE *);
  int (*ctrl)(EVP_CIPHER_CTX *, int type, int arg, void *ptr);
  void *app_data;
};

struct evp_cipher_ctx_st {
  const EVP_CIPHER *cipher;
  ENGINE *engine;
  int encrypt;
  int buf_len;

  unsigned char oiv[16];
  unsigned char iv[16];
  unsigned char buf[32];
  int num;

  void *app_data;
  int key_len;
  unsigned long flags;
  void *cipher_data;
  int final_used;
  int block_mask;
  unsigned char final[32];
};