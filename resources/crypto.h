typedef struct crypto_ex_data_st CRYPTO_EX_DATA;
struct crypto_ex_data_st {
  struct stack_st_void *sk;
};
struct stack_st_void {
  _STACK stack;
};

typedef struct bio_st BIO;

typedef void bio_info_cb(struct bio_st *, int, const char *, int, long, long);
typedef int BIO_info_cb(BIO *, int, int);

typedef struct bio_method_st {
  int type;
  const char *name;
  int (*bwrite)(BIO *, const char *, int);
  int (*bread)(BIO *, char *, int);
  int (*bputs)(BIO *, const char *);
  int (*bgets)(BIO *, char *, int);
  long (*ctrl)(BIO *, int, long, void *);
  int (*create)(BIO *);
  int (*destroy)(BIO *);
  long (*callback_ctrl)(BIO *, int, bio_info_cb *);
} BIO_METHOD;

struct bio_st {
  const BIO_METHOD *method;

  long (*callback)(struct bio_st *, int, const char *, int, long, long);
  char *cb_arg;

  int init;
  int shutdown;
  int flags;
  int retry_reason;
  int num;
  void *ptr;
  struct bio_st *next_bio;
  struct bio_st *prev_bio;
  int references;
  unsigned long num_read;
  unsigned long num_write;

  CRYPTO_EX_DATA ex_data;
};

BIO *BIO_new_file(const char *filename, const char *mode);
BIO *BIO_new(const BIO_METHOD *type);

int BIO_set(BIO *a, const BIO_METHOD *type);
int BIO_free(BIO *a);

int BIO_read(BIO *b, void *buf, int len);
int BIO_gets(BIO *b, char *buf, int size);
int BIO_write(BIO *b, const void *buf, int len);
int BIO_puts(BIO *b, const char *buf);
int BIO_test_flags(const BIO *b, int flags);

long BIO_ctrl(BIO *bp, int cmd, long larg, void *parg);

int BIO_method_type(const BIO *b);

const BIO_METHOD *BIO_s_mem(void);
BIO *BIO_new_mem_buf(const void *buf, int len);