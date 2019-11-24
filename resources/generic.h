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
