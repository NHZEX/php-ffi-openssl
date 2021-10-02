typedef struct stack_st {
  int num;
  char **data;
  int sorted;

  int num_alloc;
  int (*comp)(const void *, const void *);
} _STACK;

struct buf_mem_st {
  size_t length;
  char *data;
  size_t max;
};

typedef struct buf_mem_st BUF_MEM;
typedef long int time_t;

// Stack functions
typedef struct stack_st OPENSSL_STACK;
int OPENSSL_sk_num(const OPENSSL_STACK *);

void *OPENSSL_sk_value(const OPENSSL_STACK *, int);
void *OPENSSL_sk_set(OPENSSL_STACK *st, int i, const void *data);

_STACK *OPENSSL_sk_new(int (*cmp)(const void *, const void *));
_STACK *OPENSSL_sk_new_null(void);
void OPENSSL_sk_free(_STACK *);
void OPENSSL_sk_pop_free(_STACK *st, void (*func)(void *));
int OPENSSL_sk_insert(_STACK *sk, void *data, int where);
void *OPENSSL_sk_delete(_STACK *st, int loc);
void *OPENSSL_sk_delete_ptr(_STACK *st, void *p);
int OPENSSL_sk_find(_STACK *st, void *data);
int OPENSSL_sk_find_ex(_STACK *st, void *data);
int OPENSSL_sk_push(_STACK *st, void *data);
int OPENSSL_sk_unshift(_STACK *st, void *data);
void *OPENSSL_sk_shift(_STACK *st);
void *OPENSSL_sk_pop(_STACK *st);
void OPENSSL_sk_zero(_STACK *st);
int (*OPENSSL_sk_set_cmp_func(_STACK *sk,
                      int (*c)(const void *, const void *)))(const void *,
                                                             const void *);
_STACK *OPENSSL_sk_dup(_STACK *st);
void OPENSSL_sk_sort(_STACK *st);
int OPENSSL_sk_is_sorted(const _STACK *st);
