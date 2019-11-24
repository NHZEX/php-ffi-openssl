typedef struct x509_st X509;
typedef struct X509_algor_st X509_ALGOR;
typedef struct X509_crl_st X509_CRL;
typedef struct x509_crl_method_st X509_CRL_METHOD;
typedef struct x509_revoked_st X509_REVOKED;
typedef struct X509_name_st X509_NAME;
typedef struct X509_pubkey_st X509_PUBKEY;
typedef struct x509_store_st X509_STORE;
typedef struct x509_store_ctx_st X509_STORE_CTX;

typedef struct stack_st_X509_ALGOR X509_ALGORS;

struct stack_st_X509_ALGOR {
  _STACK stack;
};

struct X509_algor_st {
  ASN1_OBJECT *algorithm;
  ASN1_TYPE *parameter;
};

struct stack_st_X509_NAME_ENTRY {
  _STACK stack;
};

struct X509_name_st {
  struct stack_st_X509_NAME_ENTRY *entries;
  int modified;
  BUF_MEM *bytes;
  unsigned char *canon_enc;
  int canon_enclen;
};

typedef struct X509_VERIFY_PARAM_ID_st X509_VERIFY_PARAM_ID;

typedef struct X509_VERIFY_PARAM_st {
  char *name;
  time_t check_time;
  unsigned long inh_flags;
  unsigned long flags;
  int purpose;
  int trust;
  int depth;
  struct stack_st_ASN1_OBJECT *policies;
  X509_VERIFY_PARAM_ID *id;
} X509_VERIFY_PARAM;

struct stack_st_X509_VERIFY_PARAM {
  _STACK stack;
};

struct x509_store_st {

  int cache;
  struct stack_st_X509_OBJECT *objs;

  struct stack_st_X509_LOOKUP *get_cert_methods;

  X509_VERIFY_PARAM *param;

  int (*verify)(X509_STORE_CTX *ctx);
  int (*verify_cb)(int ok, X509_STORE_CTX *ctx);
  int (*get_issuer)(X509 **issuer, X509_STORE_CTX *ctx, X509 *x);
  int (*check_issued)(X509_STORE_CTX *ctx, X509 *x, X509 *issuer);
  int (*check_revocation)(X509_STORE_CTX *ctx);
  int (*get_crl)(X509_STORE_CTX *ctx, X509_CRL **crl, X509 *x);
  int (*check_crl)(X509_STORE_CTX *ctx, X509_CRL *crl);
  int (*cert_crl)(X509_STORE_CTX *ctx, X509_CRL *crl, X509 *x);
  struct stack_st_X509 *(*lookup_certs)(X509_STORE_CTX *ctx, X509_NAME *nm);
  struct stack_st_X509_CRL *(*lookup_crls)(X509_STORE_CTX *ctx, X509_NAME *nm);
  int (*cleanup)(X509_STORE_CTX *ctx);

  CRYPTO_EX_DATA ex_data;
  int references;
};

typedef struct X509_extension_st {
  ASN1_OBJECT *object;
  ASN1_BOOLEAN critical;
  ASN1_OCTET_STRING *value;
} X509_EXTENSION;

typedef struct stack_st_X509_EXTENSION X509_EXTENSIONS;

struct stack_st_X509_EXTENSION {
  _STACK stack;
};

struct X509_pubkey_st {
  X509_ALGOR *algor;
  ASN1_BIT_STRING *public_key;
  EVP_PKEY *pkey;
};

typedef struct X509_pubkey_st X509_PUBKEY;

typedef struct X509_val_st {
  ASN1_TIME *notBefore;
  ASN1_TIME *notAfter;
} X509_VAL;

typedef struct x509_cinf_st {
  ASN1_INTEGER *version;
  ASN1_INTEGER *serialNumber;
  X509_ALGOR *signature;
  X509_NAME *issuer;
  X509_VAL *validity;
  X509_NAME *subject;
  X509_PUBKEY *key;
  ASN1_BIT_STRING *issuerUID;
  ASN1_BIT_STRING *subjectUID;

  struct stack_st_X509_EXTENSION *extensions;
  ASN1_ENCODING enc;
} X509_CINF;

typedef struct X509_POLICY_NODE_st X509_POLICY_NODE;
typedef struct X509_POLICY_LEVEL_st X509_POLICY_LEVEL;
typedef struct X509_POLICY_TREE_st X509_POLICY_TREE;
typedef struct X509_POLICY_CACHE_st X509_POLICY_CACHE;

typedef struct AUTHORITY_KEYID_st AUTHORITY_KEYID;
typedef struct DIST_POINT_st DIST_POINT;
typedef struct ISSUING_DIST_POINT_st ISSUING_DIST_POINT;
typedef struct NAME_CONSTRAINTS_st NAME_CONSTRAINTS;

typedef struct x509_cert_aux_st {
  struct stack_st_ASN1_OBJECT *trust;
  struct stack_st_ASN1_OBJECT *reject;
  ASN1_UTF8STRING *alias;
  ASN1_OCTET_STRING *keyid;
  struct stack_st_X509_ALGOR *other;
} X509_CERT_AUX;

struct x509_st {
  X509_CINF *cert_info;
  X509_ALGOR *sig_alg;
  ASN1_BIT_STRING *signature;
  int valid;
  int references;
  char *name;
  CRYPTO_EX_DATA ex_data;

  long ex_pathlen;
  long ex_pcpathlen;
  unsigned long ex_flags;
  unsigned long ex_kusage;
  unsigned long ex_xkusage;
  unsigned long ex_nscert;
  ASN1_OCTET_STRING *skid;
  AUTHORITY_KEYID *akid;
  X509_POLICY_CACHE *policy_cache;
  struct stack_st_DIST_POINT

      *crldp;

  struct stack_st_GENERAL_NAME

      *altname;
  NAME_CONSTRAINTS *nc;

  unsigned char sha1_hash[20];
  X509_CERT_AUX *aux;
};

typedef struct x509_trust_st {
  int trust;
  int flags;
  int (*check_trust)(struct x509_trust_st *, X509 *, int);
  char *name;
  int arg1;
  void *arg2;
} X509_TRUST;

struct stack_st_X509_TRUST {
  _STACK stack;
};

typedef struct x509_cert_pair_st {
  X509 *forward;
  X509 *reverse;
} X509_CERT_PAIR;
struct x509_revoked_st {
  ASN1_INTEGER *serialNumber;
  ASN1_TIME *revocationDate;
  struct stack_st_X509_EXTENSION *extensions;

  struct stack_st_GENERAL_NAME *issuer;

  int reason;
  int sequence;
};

struct stack_st_X509_REVOKED {
  _STACK stack;
};

typedef struct X509_crl_info_st {
  ASN1_INTEGER *version;
  X509_ALGOR *sig_alg;
  X509_NAME *issuer;
  ASN1_TIME *lastUpdate;
  ASN1_TIME *nextUpdate;
  struct stack_st_X509_REVOKED *revoked;
  struct stack_st_X509_EXTENSION *extensions;
  ASN1_ENCODING enc;
} X509_CRL_INFO;

struct X509_crl_st {

  X509_CRL_INFO *crl;
  X509_ALGOR *sig_alg;
  ASN1_BIT_STRING *signature;
  int references;
  int flags;

  AUTHORITY_KEYID *akid;
  ISSUING_DIST_POINT *idp;

  int idp_flags;
  int idp_reasons;

  ASN1_INTEGER *crl_number;
  ASN1_INTEGER *base_crl_number;

  unsigned char sha1_hash[20];

  struct stack_st_GENERAL_NAMES *issuers;
  const X509_CRL_METHOD *meth;
  void *meth_data;
};

struct stack_st_X509_CRL {
  _STACK stack;
};

X509 *X509_new(void);
void X509_free(X509 *a);

X509_STORE *X509_STORE_new(void);
void X509_STORE_free(X509_STORE *v);