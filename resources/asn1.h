struct asn1_string_st {
  int length;
  int type;
  unsigned char *data;
  long flags;
};

typedef struct asn1_string_st ASN1_INTEGER;
typedef struct asn1_string_st ASN1_ENUMERATED;
typedef struct asn1_string_st ASN1_BIT_STRING;
typedef struct asn1_string_st ASN1_OCTET_STRING;
typedef struct asn1_string_st ASN1_PRINTABLESTRING;
typedef struct asn1_string_st ASN1_T61STRING;
typedef struct asn1_string_st ASN1_IA5STRING;
typedef struct asn1_string_st ASN1_GENERALSTRING;
typedef struct asn1_string_st ASN1_UNIVERSALSTRING;
typedef struct asn1_string_st ASN1_BMPSTRING;
typedef struct asn1_string_st ASN1_UTCTIME;
typedef struct asn1_string_st ASN1_TIME;
typedef struct asn1_string_st ASN1_GENERALIZEDTIME;
typedef struct asn1_string_st ASN1_VISIBLESTRING;
typedef struct asn1_string_st ASN1_UTF8STRING;
typedef struct asn1_string_st ASN1_STRING;
typedef int ASN1_BOOLEAN;
typedef int ASN1_NULL;

typedef struct ASN1_VALUE_st ASN1_VALUE;

typedef struct asn1_object_st {
  const char *sn, *ln;
  int nid;
  int length;
  const unsigned char *data;
  int flags;
} ASN1_OBJECT;

typedef struct asn1_type_st {
  int type;
  union {
    char *ptr;
    ASN1_BOOLEAN boolean;
    ASN1_STRING *asn1_string;
    ASN1_OBJECT *object;
    ASN1_INTEGER *integer;
    ASN1_ENUMERATED *enumerated;
    ASN1_BIT_STRING *bit_string;
    ASN1_OCTET_STRING *octet_string;
    ASN1_PRINTABLESTRING *printablestring;
    ASN1_T61STRING *t61string;
    ASN1_IA5STRING *ia5string;
    ASN1_GENERALSTRING *generalstring;
    ASN1_BMPSTRING *bmpstring;
    ASN1_UNIVERSALSTRING *universalstring;
    ASN1_UTCTIME *utctime;
    ASN1_GENERALIZEDTIME *generalizedtime;
    ASN1_VISIBLESTRING *visiblestring;
    ASN1_UTF8STRING *utf8string;

    ASN1_STRING *set;
    ASN1_STRING *sequence;
    ASN1_VALUE *asn1_value;
  } value;
} ASN1_TYPE;

typedef struct ASN1_ENCODING_st {
  unsigned char *enc;
  long len;
  int modified;
} ASN1_ENCODING;

struct stack_st_ASN1_OBJECT {
  _STACK stack;
};

ASN1_OBJECT *OBJ_nid2obj(int n);
int OBJ_obj2nid(const ASN1_OBJECT *o);