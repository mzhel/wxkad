#ifndef _KADNET_H_
#define _KADNET_H_

#define KADNET_THREAD_CMD_EXIT 1
#define KADNET_THREAD_CMD_GET_DATA 2
#define KADNET_THREAD_CMD_START_KWD_SEARCH 3
#define KADNET_THREAD_CMD_START_FILE_SEARCH 4

#define KADNET_THREAD_CMD_LOCK_INIT(knt) pthread_mutex_init(&knt->thread_cmd_lock, NULL)

#define KADNET_THREAD_CMD_LOCK_DESTROY(knt) pthread_mutex_destroy(&knt->thread_cmd_lock)

#define KADNET_THREAD_CMD_LOCK(knt) pthread_mutex_lock(&knt->thread_cmd_lock)

#define KADNET_THREAD_CMD_UNLOCK(knt) pthread_mutex_unlock(&knt->thread_cmd_lock)

#define KADNET_THREAD_DATA_LOCK_INIT(knt) pthread_mutex_init(&knt->thread_data_lock, NULL)

#define KADNET_THREAD_DATA_LOCK_DESTROY(knt) pthread_mutex_destroy(&knt->thread_data_lock)

#define KADNET_THREAD_DATA_LOCK(knt) pthread_mutex_lock(&knt->thread_data_lock)

#define KADNET_THREAD_DATA_UNLOCK(knt) pthread_mutex_unlock(&knt->thread_data_lock)

#define KADNET_THREAD_COND_VAR_INIT(knt) pthread_cond_init(&knt->thread_cond_var, NULL);

#define KADNET_THREAD_COND_VAR_DESTROY(knt) pthread_cond_destroy(&knt->thread_cond_var)

#define KADNET_THREAD_COND_VAR_SIGNAL(knt) pthread_cond_signal(&knt->thread_cond_var)

#define KADNET_THREAD_COND_VAR_WAIT(knt) pthread_cond_wait(&knt->thread_cond_var, &knt->thread_data_lock)

typedef void (*KADNET_KEYWORD_RESULT_CB)(uint32_t search_id, void* file_id, char* file_name, uint64_t file_size, char* file_type, uint64_t length);

typedef struct _listener_ctx {
  struct event_base* base;
  void* arg;
  uint32_t ip4_no;
  uint16_t port_no;
} LISTENER_CTX;

typedef struct _conn_ctx {
  struct bufferevent* bev;
  struct event_base* base;
  void* arg;
  uint32_t ip4_no;
  uint16_t port_no;
} CONN_CTX;

typedef struct _kadnet {
  pthread_t thrd;
  pthread_mutex_t thread_cmd_lock;
  pthread_mutex_t thread_data_lock;
  pthread_cond_t thread_cond_var;
  uint32_t thread_cmd;
  bool new_thread_cmd;
  void* data;
  KADNET_KEYWORD_RESULT_CB kw_res_cb;
  bool kw_search_finished;
  LIST* kw_search_results;
  bool file_search_finished;
  LIST* file_search_results;
} KADNET;

typedef struct _timer_ctx {
  void* kad_session;
  void* mule_session;
  struct event_base* base;
  KADNET* knt;
} TIMER_CTX;

typedef struct _kadnet_status {
  uint32_t loc_ip4_no;
  uint32_t pub_ip4_no;
  uint32_t node_count;
  uint16_t tcp_port_no;
  uint16_t int_udp_port_no;
  uint16_t ext_udp_port_no;
  bool tcp_firewalled;
  bool udp_firewalled;
} KADNET_STATUS;

typedef struct _kadnet_keyword_search {
  char* keyword;
  KADNET_KEYWORD_RESULT_CB kw_res_cb;
  char buf[1];
} KADNET_KEYWORD_SEARCH;

typedef struct _kadnet_search_result_keyword {
  uint8_t file_id[16];
  char* file_name;
  uint64_t file_size;
  char* file_type;
  uint64_t length;
  uint16_t avail;
  char buf[1];
} KADNET_SEARCH_RESULT_KEYWORD;

typedef struct _kadnet_file_search {
  uint8_t file_id[16];
  char* file_name;
  uint64_t file_size;
  char buf[1];
} KADNET_FILE_SEARCH;

#ifdef __cplusplus

extern "C" {

#endif

bool
kadnet_init(
            KADNET** knt_out
           );

bool
kadnet_uninit(
              KADNET* knt
             );

bool
kadnet_start(
             KADNET* knt
            );

bool
kadnet_stop(
            KADNET* knt
           );

bool
kadnet_get_status(
                  KADNET* knt,
                  KADNET_STATUS* knts
                 );

bool
kadnet_search_keyword(
                      KADNET* knt,
                      const char* keyword
                     );

bool
kadnet_is_keyword_search_finished(
                                  KADNET* knt
                                 );

bool
kadnet_get_keyword_result(
                          KADNET* knt,
                          KADNET_SEARCH_RESULT_KEYWORD** ksrk_out 
                         );

bool
kadnet_search_file(
                   KADNET* knt,
                   uint8_t* file_id,
                   char* file_name,
                   uint64_t file_size
                  );

#ifdef __cplusplus

}

#endif

#endif // _KADNET_H_
