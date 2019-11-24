typedef struct pkcs7_issuer_and_serial_st {
  X509_NAME *issuer;
  ASN1_INTEGER *serial;
} PKCS7_ISSUER_AND_SERIAL;

typedef struct pkcs7_signer_info_st {
  ASN1_INTEGER *version;
  PKCS7_ISSUER_AND_SERIAL *issuer_and_serial;
  X509_ALGOR *digest_alg;
  struct stack_st_X509_ATTRIBUTE *auth_attr;
  X509_ALGOR *digest_enc_alg;
  ASN1_OCTET_STRING *enc_digest;
  struct stack_st_X509_ATTRIBUTE *unauth_attr;

  EVP_PKEY *pkey;
} PKCS7_SIGNER_INFO;

struct stack_st_PKCS7_SIGNER_INFO {
  _STACK stack;
};

typedef struct pkcs7_recip_info_st {
  ASN1_INTEGER *version;
  PKCS7_ISSUER_AND_SERIAL *issuer_and_serial;
  X509_ALGOR *key_enc_algor;
  ASN1_OCTET_STRING *enc_key;
  X509 *cert;
} PKCS7_RECIP_INFO;

struct stack_st_PKCS7_RECIP_INFO {
  _STACK stack;
};

typedef struct pkcs7_signed_st {
  ASN1_INTEGER *version;
  struct stack_st_X509_ALGOR *md_algs;
  struct stack_st_X509 *cert;
  struct stack_st_X509_CRL *crl;
  struct stack_st_PKCS7_SIGNER_INFO *signer_info;
  struct pkcs7_st *contents;
} PKCS7_SIGNED;

typedef struct pkcs7_enc_content_st {
  ASN1_OBJECT *content_type;
  X509_ALGOR *algorithm;
  ASN1_OCTET_STRING *enc_data;
  const EVP_CIPHER *cipher;
} PKCS7_ENC_CONTENT;

typedef struct pkcs7_enveloped_st {
  ASN1_INTEGER *version;

  struct stack_st_PKCS7_RECIP_INFO *recipientinfo;
  PKCS7_ENC_CONTENT *enc_data;
} PKCS7_ENVELOPE;

typedef struct pkcs7_signedandenveloped_st {
  ASN1_INTEGER *version;

  struct stack_st_X509_ALGOR *md_algs;

  struct stack_st_X509 *cert;

  struct stack_st_X509_CRL *crl;

  struct stack_st_PKCS7_SIGNER_INFO *signer_info;

  PKCS7_ENC_CONTENT *enc_data;

  struct stack_st_PKCS7_RECIP_INFO *recipientinfo;
} PKCS7_SIGN_ENVELOPE;

typedef struct pkcs7_digest_st {
  ASN1_INTEGER *version;
  X509_ALGOR *md;
  struct pkcs7_st *contents;
  ASN1_OCTET_STRING *digest;
} PKCS7_DIGEST;

typedef struct pkcs7_encrypted_st {
  ASN1_INTEGER *version;
  PKCS7_ENC_CONTENT *enc_data;
} PKCS7_ENCRYPT;

typedef struct pkcs7_st {
  unsigned char *asn1;
  long length;
  int state;
  int detached;
  ASN1_OBJECT *type;

  union {
    char *ptr;
    ASN1_OCTET_STRING *data;
    PKCS7_SIGNED *sign;
    PKCS7_ENVELOPE *enveloped;
    PKCS7_SIGN_ENVELOPE *signed_and_enveloped;
    PKCS7_DIGEST *digest;
    PKCS7_ENCRYPT *encrypted;
    ASN1_TYPE *other;
  } d;
} PKCS7;

struct stack_st_PKCS7 {
  _STACK stack;
};

PKCS7 *PKCS7_new(void);
void PKCS7_free(PKCS7 *a);
PKCS7 *d2i_PKCS7(PKCS7 **a, const unsigned char **in, long len);
int i2d_PKCS7(PKCS7 *a, unsigned char **out);
int PKCS7_verify(PKCS7 *p7, struct stack_st_X509 *certs, X509_STORE *store,
                 BIO *indata, BIO *out, int flags);