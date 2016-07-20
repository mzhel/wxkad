#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <memory.h>
#include <errno.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <zlib.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/util.h>
#include <event2/event.h>
#include <polarssl/md4.h>
#include <polarssl/md5.h>
#include <polarssl/arc4.h>
#include <libkad/libkad.h>
#include <libmule/libmule.h>
#include <mem.h>
#include <list.h>
#include <log.h>
#include <kadnet.h>

#ifdef EXIT_TIMER

/**
    Timer callback for exiting event loop, debugging purposes only.
*/
void
exit_cb(
        evutil_socket_t fd,
        short event,
        void* arg
        )
{

	do {

    LOG_DEBUG("Breaking event loop on timer.");

    event_base_loopbreak((struct event_base*)arg);

	} while (false);

}

#endif // #ifdef EXIT_TIMER

bool
send_control_packet(
                    evutil_socket_t fd,
                    KAD_SESSION* ks
                   )
{
  bool result = false;
  struct sockaddr_in sin;
  socklen_t sin_len = sizeof(sin);
  ssize_t io_len = 0;
  void* pkt_to_send = NULL;
  uint32_t pkt_to_send_len = 0;

  do {

    memset(&sin, 0, sizeof(sin));

    if (kad_get_control_packet_to_send(
                                       ks, 
                                       &sin.sin_addr.s_addr,
                                       &sin.sin_port, 
                                       &pkt_to_send, 
                                       &pkt_to_send_len
                                       )
    ){

      sin.sin_family = AF_INET;

      io_len = sendto(fd, pkt_to_send, pkt_to_send_len, 0, (struct sockaddr*)&sin, sin_len);

      LOG_DEBUG("sent packet_len = %.8x, io_bytes = %.8x", pkt_to_send_len, io_len);

      if (io_len == -1){

        LOG_DEBUG("send error: %s", strerror(errno));

      }

      mem_free(pkt_to_send);

      result = true;

    }

  } while (false);

  return result;
}

void
kadnet_search_result_keyword(
                             void* arg,
                             uint32_t search_id, 
                             void* file_id,
                             char* file_name, 
                             uint64_t file_size, 
                             char* file_type, 
                             uint64_t length,
                             uint16_t avail
                            )
{
  KADNET* knt = (KADNET*)arg;
  KADNET_SEARCH_RESULT_KEYWORD* ksrk = NULL;
  char* p = NULL;

  do {

    if (file_id == NULL && file_name == NULL && file_size == 0 && file_type == NULL && length == 0){

      knt->kw_search_finished = true;

      break;

    }

    ksrk = (KADNET_SEARCH_RESULT_KEYWORD*)mem_alloc(
                                                     sizeof(KADNET_SEARCH_RESULT_KEYWORD) - 1 +
                                                     (file_name?(strlen(file_name) + 1):0) +
                                                     (file_type?(strlen(file_type) + 1):0)
                                                    );

    if (!ksrk){

      LOG_ERROR("Failed to allocate memory for keyword search result.");

      break;

    }

    // [FIXFIX] hardcoded length

    memcpy(ksrk->file_id, file_id, 16);

    p = (char*)ksrk + sizeof(KADNET_SEARCH_RESULT_KEYWORD) - 1;

    if (file_name){

      strcpy(p, file_name);

      ksrk->file_name = p;

      p += strlen(file_name) + 1;

    }

    ksrk->file_size = file_size;

    if (file_type){

      strcpy(p, file_type);

      ksrk->file_type = p;

      p += strlen(file_type) + 1;

    }

    ksrk->length = length;

    ksrk->avail = avail;

    list_add_entry(&knt->kw_search_results, ksrk);

  } while (false);

}

void
kadnet_search_result_file(
                          void* arg,
                          char* file_name,
                          uint64_t file_size,
                          uint8_t type,
                          void* id,
                          uint32_t ip4,
                          uint16_t tcp_port,
                          uint16_t udp_port,
                          uint8_t cipher_opts
                         )
{
  
  do {

#ifdef CONFIG_VERBOSE

    if (file_name){

      LOG_DEBUG("File search result for \"%s\"", file_name);

    }

#endif
  } while (false);

}

void
timer_cb(
         evutil_socket_t fd,
         short event,
         void* arg
        )
{
  KAD_SESSION* ks;
  MULE_SESSION* ms;
  KADNET* knt;
  KADNET_KEYWORD_SEARCH* kwd_srch = NULL;
  KADNET_FILE_SEARCH* file_srch = NULL;
  uint32_t thrd_cmd;

  ks = (KAD_SESSION*)((TIMER_CTX*)arg)->kad_session;

  ms = (MULE_SESSION*)((TIMER_CTX*)arg)->mule_session;

  knt = (KADNET*)((TIMER_CTX*)arg)->knt;

  if (knt->new_thread_cmd){

    KADNET_THREAD_CMD_LOCK(knt);

    thrd_cmd = knt->thread_cmd;

    knt->new_thread_cmd = false;

    KADNET_THREAD_CMD_UNLOCK(knt);

    switch (thrd_cmd){

      case KADNET_THREAD_CMD_EXIT:

        LOG_DEBUG("Command exit.");

        event_base_loopbreak(((TIMER_CTX*)arg)->base);

      break;

      case KADNET_THREAD_CMD_GET_DATA:

        KADNET_THREAD_DATA_LOCK(knt);

        // Copy data
        
        kad_get_user_data(ks, (KAD_USER_DATA*)knt->data);

        KADNET_THREAD_COND_VAR_SIGNAL(knt); 

        KADNET_THREAD_DATA_UNLOCK(knt);

      break;

      case KADNET_THREAD_CMD_START_KWD_SEARCH:

        kwd_srch = (KADNET_KEYWORD_SEARCH*)knt->data; 

        LOG_DEBUG("Starting search for \"%s\" keyword.", kwd_srch->keyword);

        kad_search_keyword(
                           ks,
                           kwd_srch->keyword,
                           knt,
                           kadnet_search_result_keyword
                          );

        mem_free(kwd_srch);

      break;

      case KADNET_THREAD_CMD_START_FILE_SEARCH:

        file_srch = (KADNET_FILE_SEARCH*)knt->data; 

        LOG_DEBUG("Starting search for file \"%s\"", file_srch->file_name);

        kad_search_file(
                        ks,
                        file_srch->file_id,
                        file_srch->file_name,
                        file_srch->file_size,
                        knt,
                        kadnet_search_result_file
                       );
        
        mem_free(file_srch);

      break;

    }

  }

  kad_timer(ks);

  while (send_control_packet(fd, ks));

  mule_session_timer(ms);

}

void
udp_sock_cb(
            evutil_socket_t fd,
            short event,
            void* arg
            )
{
  uint8_t buf[4096];
  struct sockaddr_in sin;
  socklen_t sin_len = sizeof(sin);
  ssize_t io_len = 0;

  do {

    switch (event){

      case EV_READ:

        io_len = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr*)&sin, &sin_len);

        LOG_DEBUG("received io_len = %.8x", io_len);

        if (io_len > 0){

          kad_control_packet_received((KAD_SESSION*)arg, sin.sin_addr.s_addr, sin.sin_port, buf, io_len);

        }

      break;

    }

  } while (false);

}

void
outbound_conn_data_to_read(
                           struct bufferevent* bev,
                           void* ctx
                          )
{
  CONN_CTX* cctx = (CONN_CTX*)ctx;
  struct evbuffer* evb = NULL;
  uint8_t data[1024];
  uint32_t n = 0;
  
  do {

    evb = bufferevent_get_input(bev);

    while ((n = evbuffer_remove(evb, data, sizeof(data))) > 0) {

      mule_session_data_received((MULE_SESSION*)cctx->arg, cctx, data, n);

    }

  } while (false);
  
}

void
outbound_conn_data_can_be_written(
                                  struct bufferevent* bev,
                                  void* ctx
                                 )
{
  
  do {

  } while (false);

}

void
outbound_conn_event(
                    struct bufferevent* bev,
                    short events,
                    void* ctx
                   )
{
  CONN_CTX* cctx = ctx;

  do {

    if (events & BEV_EVENT_CONNECTED){

      LOG_DEBUG("Connected to %s:%d", inet_ntoa(*(struct in_addr*)&cctx->ip4_no), ntohs(cctx->port_no));

      LOG_DEBUG("fd = %.8x", bev);

      cctx->bev = bev;

      mule_session_connected_to_peer((MULE_SESSION*)cctx->arg, cctx->ip4_no, cctx->port_no, cctx);   

	  } else if ((events & BEV_EVENT_EOF) || (events & BEV_EVENT_ERROR)) {
      
      LOG_DEBUG("Disconnected from %s:%d", inet_ntoa(*(struct in_addr*)&cctx->ip4_no), ntohs(cctx->port_no));

      mule_session_peer_disconnected((MULE_SESSION*)cctx->arg, cctx);

      bufferevent_free(bev);

      mem_free(ctx);

    }

  } while (false);

}

void
inbound_conn_data_to_read(
                          struct bufferevent* bev,
                          void* ctx
                         )
{
  CONN_CTX* cctx = (CONN_CTX*)ctx;
  struct evbuffer* evb = NULL;
  uint8_t data[1024];
  uint32_t n = 0;
  
  do {

    evb = bufferevent_get_input(bev);

    while ((n = evbuffer_remove(evb, data, sizeof(data))) > 0) {

      mule_session_data_received((MULE_SESSION*)cctx->arg, cctx, data, n);

    }

  } while (false);

}

void
inbound_conn_data_can_be_written(
                                 struct bufferevent* bev,
                                 void* ctx
                                )
{
  
  do {

  } while (false);

}

void
inbound_conn_event(
                   struct bufferevent* bev,
                   short events,
                   void* ctx
                  )
{
  CONN_CTX* cctx = NULL;

  do {

    cctx = (CONN_CTX*)ctx;

    if ((events & BEV_EVENT_EOF) || (events & BEV_EVENT_ERROR)){

      LOG_DEBUG("Disconnected from %s:%d", inet_ntoa(*(struct in_addr*)&cctx->ip4_no), ntohs(cctx->port_no));

      mule_session_peer_disconnected((MULE_SESSION*)cctx->arg, ctx);

      LOG_DEBUG("%.8x %.8x", bev, cctx->bev);

      bufferevent_free(bev);

      mem_free(ctx);

    }

  } while (false);

}

void
listener_cb(
            struct evconnlistener* listener,
            evutil_socket_t fd,
            struct sockaddr* sa,
            int socklen,
            void* user_data
           )
{
  struct sockaddr_in sin = {0};
  struct bufferevent* bev = NULL;
  bool error = false;
  uint32_t ip4_no = 0;
  uint16_t port_no = 0;
  LISTENER_CTX* ctx = (LISTENER_CTX*)user_data;
  CONN_CTX* cctx = NULL;
  struct event_base* base = NULL;
  MULE_SESSION* ms = NULL;
  
  do {

    ms = (MULE_SESSION*)ctx->arg;

    base = ctx->base;

    ip4_no = ((struct sockaddr_in*)sa)->sin_addr.s_addr;

    port_no = ((struct sockaddr_in*)sa)->sin_port;

    LOG_DEBUG("Incoming connection from %s:%d", inet_ntoa(*(struct in_addr*)&ip4_no), ntohs(port_no));

    // Create event for connected client
    
    bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);

    if (!bev){

      LOG_ERROR("Failed to create bufferevent for client.");

      error = true;

      break;

    }

    cctx = (CONN_CTX*)mem_alloc(sizeof(CONN_CTX));

    if (!cctx){

      LOG_ERROR("Failed to allocate memory for connection context.");

      break;

    }

    cctx->bev = bev;

    cctx->base = ctx->base;

    cctx->arg = ctx->arg;

    cctx->ip4_no = ip4_no;

    cctx->port_no = port_no;

    bufferevent_setcb(
                      bev,
                      inbound_conn_data_to_read,
                      inbound_conn_data_can_be_written,
                      inbound_conn_event,
                      cctx
                     );

    bufferevent_enable(bev, EV_WRITE);

    bufferevent_enable(bev, EV_READ);

    mule_session_new_connection(ms, ip4_no, port_no, cctx);

  } while (false);

  if (error && bev) bufferevent_free(bev);

}

bool
connect_cb(
           void* handle,
           uint32_t ip4_no,
           uint16_t port_no,
           void* arg
          )
{
  bool result = false;
  struct bufferevent* bev;
  struct event_base* base;
  CONN_CTX* ctx = NULL;
  struct sockaddr_in sin = {0};

  do {

    if (!handle) break;

    base = (struct event_base*)handle;

    ctx = (CONN_CTX*)mem_alloc(sizeof(CONN_CTX));

    if (!ctx){

      LOG_ERROR("Failed to allocate memory for context.");

      break;

    }

    LOG_DEBUG("Connecting to %s:%d", inet_ntoa(*(struct in_addr*)&ip4_no), ntohs(port_no));

    ctx->base = base;

    ctx->arg = arg;

    ctx->ip4_no = ip4_no;

    ctx->port_no = port_no;

    bev = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);

    if (!bev){

      LOG_ERROR("Failed to create bufferevent.");

      break;

    }

    ctx->bev = bev;

    bufferevent_setcb(
                      bev,
                      outbound_conn_data_to_read,
                      outbound_conn_data_can_be_written,
                      outbound_conn_event,
                      ctx
                     );

    bufferevent_enable(bev, EV_WRITE);

    bufferevent_enable(bev, EV_READ);

    sin.sin_family = AF_INET;

    sin.sin_addr.s_addr = ip4_no;

    sin.sin_port = port_no;

    // If connection fail bufferevent will be freed in outbout_conn_event callback.

    if (0 > bufferevent_socket_connect(bev, (struct sockaddr*)&sin, sizeof(sin))){

      LOG_ERROR("Failed to schedule connection.");

      break;

    }

    result = true;

  } while (false);

  return result;
}

bool
send_cb(
        void* conn_handle,
        uint8_t* pkt,
        uint32_t pkt_len
       )
{
  bool result = false;
  CONN_CTX* cctx = NULL;

  do {

    if (!conn_handle || !pkt) break;

    cctx = (CONN_CTX*)conn_handle;

    bufferevent_write(cctx->bev, pkt, pkt_len);

    result = true;

  } while (false);

  return result;
}

bool
disconnect_cb(
              void* conn_handle 
             )
{
  bool result = false;
  CONN_CTX* cctx = NULL;

  do {

    if (!conn_handle) break;

    cctx = (CONN_CTX*)conn_handle;

    LOG_DEBUG("fd = %.8x", conn_handle);

    bufferevent_free(cctx->bev);
    
    mem_free(cctx);

    result = true;

  } while (false);

  return result;
}

bool
init_tcp_listener(
                  uint16_t port,
                  void* arg,
                  struct event_base* base,
                  struct evconnlistener** listener_out
                 )
{
  bool result = false;
  struct sockaddr_in sin = {0};
  struct evconnlistener* listener;

  do {

    if (!port || !listener_out) break;

    LOG_DEBUG("Polling method %s", event_base_get_method(base));

    memset(&sin, 0, sizeof(sin));

    sin.sin_family = AF_INET;

    sin.sin_port = htons(port);

    listener = evconnlistener_new_bind(
                                       base,
                                       listener_cb,
                                       arg,
                                       LEV_OPT_REUSEABLE | LEV_OPT_CLOSE_ON_FREE,
                                       -1,
                                       (struct sockaddr*)&sin,
                                       sizeof(sin)
                                      );

    if (!listener){

      LOG_ERROR("Failed to create listener.");

      break;

    }

    *listener_out = listener;

    result = true;

  } while (false);

  return result;
}

bool
init_udp_listener(
                  uint16_t port,
                  struct event_base* base,
                  void* arg,
                  evutil_socket_t* sock_out,
                  struct event** udp_sock_evt_out
                 )
{
  bool result = false;
  struct sockaddr_in sin;
  evutil_socket_t sock;
  struct event* udp_sock_evt;

  do {

    memset(&sin, 0, sizeof(sin));

    sock = socket(AF_INET, SOCK_DGRAM, 0);

    sin.sin_family = AF_INET;

    evutil_make_socket_nonblocking(sock);

    sin.sin_addr.s_addr = INADDR_ANY;

    sin.sin_port = htons(3331);

    if (0 != bind(sock, (struct sockaddr*)&sin, sizeof(sin))) {

      LOG_ERROR("Failed to bind udp socket to port %.4d", port);

      break;

    }

    udp_sock_evt = event_new(base, sock, EV_READ | EV_PERSIST, udp_sock_cb, arg);

    event_add(udp_sock_evt, NULL);

    *sock_out = sock;

    *udp_sock_evt_out = udp_sock_evt;

    result = true;

  } while (false);

  return result;
}

bool
enable_core_dump()
{
  bool result = false;
  struct rlimit core_limits;

  do {

    core_limits.rlim_cur = core_limits.rlim_max = RLIM_INFINITY;

    setrlimit(RLIMIT_CORE, &core_limits);

    result = true;

  } while (false);

  return result;
}

void*
kadnet_thread(
              void* arg
             )
{
  void* result = NULL;
  struct event_base* base;
  struct event* udp_sock_evt;
  struct event* timer_evt;
  struct evconnlistener* listener;
  struct timeval itvl;
  KAD_SESSION* ks = NULL;
  MULE_SESSION* ms = NULL;
  MULE_NETWORK_CALLBACKS ncbs;
  KAD_CALLBACKS kcbs;
  ZLIB_CALLBACKS zcbs;
  MULE_CALLBACKS mcbs;
  CIPHER_CALLBACKS ccbs;
  LISTENER_CTX* ctx = NULL;
  TIMER_CTX* timer_ctx = NULL;
  evutil_socket_t udp_sock;
#ifdef EXIT_TIMER
    struct event* exit_timer_evt = NULL;
    struct timeval exit_timer_itvl;
#endif

  do {

        
    base = event_base_new();

    if (!base){

      LOG_ERROR("Failed to create event base.");

      break;

    }

    if (!kad_session_init(3332, 3331, "nodes.dat", &ks)){

      LOG_ERROR("Failed to initialize kad session.");

      break;

    }

    if (!mule_session_init(3332, &ms)){

      LOG_ERROR("Failed to intialize kad session.");

      break;

    }

    // Setup network callbacks for mule.

    ncbs.connect = connect_cb;

    ncbs.send = send_cb;

    ncbs.disconnect = disconnect_cb;

    mule_session_set_network_callbacks(ms, base, &ncbs);

    // Setup kad callbacks for mule.
    
    memset(&kcbs, 0, sizeof(KAD_CALLBACKS));
    
    kcbs.kad_get_status = kadses_get_status;

    kcbs.kad_calc_verify_key = kadses_calc_verify_key;

    kcbs.kad_bootstrap_from_node = kadses_bootstrap_from_node;

    kcbs.kad_send_fw_check_udp = kadses_send_fw_check_udp;

    kcbs.kad_fw_check_response = kadses_fw_check_response;

    kcbs.kad_fw_dec_checks_running = kadses_fw_dec_checks_running;

    kcbs.kad_fw_dec_checks_running_udp = kadses_fw_dec_checks_running_udp;

    mule_session_set_kad_callbacks(ms, ks, &kcbs);

    // Setup mule callbacks for kad.

    mcbs.add_source_for_udp_fw_check = mule_session_add_source_for_udp_fw_check;

    mcbs.add_source_for_tcp_fw_check = mule_session_add_source_for_tcp_fw_check;

    mcbs.session_create_file = mule_session_create_file;

    mcbs.session_add_source_to_file = mule_session_add_source_to_file;

    mcbs.session_add_pub_file = mule_session_add_pub_file;

    kadses_set_mule_callbacks(ks, ms, &mcbs);

    // Setup zlib callbacks for mule and kad.

    memset(&zcbs, 0, sizeof(zcbs));

    zcbs.uncompress = uncompress;

    kadses_set_zlib_callbacks(ks, &zcbs);

    memset(&ccbs, 0, sizeof(ccbs));

    // Setup cipher callbacks for mule and kad.

    ccbs.md4 = md4;

    ccbs.md5 = md5;

    ccbs.arc4_setup = arc4_setup;

    ccbs.arc4_crypt = arc4_crypt;

    kadses_set_cipher_callbacks(ks, &ccbs);

    mule_session_set_cipher_callbacks(ms, &ccbs);

#ifdef EXIT_TIMER

    // Creating timer to break event loop, debugging purposes.

    exit_timer_evt = evtimer_new(base, exit_cb, (void*)base);

    if (!exit_timer_evt) {

      LOG_ERROR("Failed to create timer event.");

      break;

    }

    exit_timer_itvl.tv_sec = 360;

    exit_timer_itvl.tv_usec = 0;

    if (0 != evtimer_add(exit_timer_evt, &exit_timer_itvl)){

      LOG_ERROR("Failed to add exit timer event.");

    }

#endif // #ifdef EXIT_TIMER

    init_udp_listener(3331, base, ks, &udp_sock, &udp_sock_evt);

    ctx = (LISTENER_CTX*)mem_alloc(sizeof(LISTENER_CTX));

    if (!ctx){

      LOG_ERROR("Failed to allocate memory for listener context.");

      break;

    }

    ctx->base = base;

    ctx->arg = ms;

    init_tcp_listener(3332, ctx, base, &listener);

    timer_ctx = (TIMER_CTX*)mem_alloc(sizeof(TIMER_CTX));

    if (!timer_ctx){

      LOG_ERROR("Failed to allocate memory for timer context.");

      break;

    }

    timer_ctx->base = base;

    timer_ctx->kad_session = ks;

    timer_ctx->mule_session = ms;

    timer_ctx->knt = (KADNET*)arg;

    timer_evt = event_new(base, udp_sock, EV_PERSIST, timer_cb, timer_ctx); 

    if (!timer_evt){

      LOG_ERROR("Failed to create timer event.");

      break;

    }

    itvl.tv_sec = 0;

    itvl.tv_usec = 10000; // 10 miliseconds - 1/100 of a second.

    if (0 != evtimer_add(timer_evt, &itvl)){

      LOG_ERROR("Failed to add timer event.");

      break;

    }

    event_base_dispatch(base);

  } while (false);

 #ifdef EXIT_TIMER

  if (exit_timer_evt) event_free(exit_timer_evt);

#endif

  if (timer_evt) event_free(timer_evt);

  if (listener) evconnlistener_free(listener);

  if (udp_sock_evt) event_free(udp_sock_evt);

  if (ms) mule_session_uninit(ms);

  if (ks) kad_session_uninit(ks, "nodes.dat");

  if (base) event_base_free(base);

  if (timer_ctx) mem_free(timer_ctx);

  if (ctx) mem_free(ctx);

  return (void*)result;

}

bool
kadnet_thread_cmd(
                  KADNET* knt,
                  uint32_t cmd
                 )
{
  bool result = false;

  do {

    if (!knt) break;

    KADNET_THREAD_CMD_LOCK(knt);

    knt->thread_cmd = cmd;

    knt->new_thread_cmd = true;

    KADNET_THREAD_CMD_UNLOCK(knt);

    result = true;

  } while (false);

  return result;
}

bool
kadnet_init(
            KADNET** knt_out
           )
{
  bool result = false;
  KADNET* knt = NULL;

  do {

    if (!knt_out) break;

    LOG_PREFIX("[kad] ");

    LOG_LEVEL_DEBUG;

    LOG_FILE_NAME("kadnet.log");

    LOG_OUTPUT_CONSOLE_AND_FILE;

    enable_core_dump();

    knt = (KADNET*)mem_alloc(sizeof(KADNET));

    if (!knt){

      LOG_ERROR("Failed to allocate memory for KADNET structure.");

      break;

    }

    KADNET_THREAD_CMD_LOCK_INIT(knt);

    KADNET_THREAD_DATA_LOCK_INIT(knt);

    KADNET_THREAD_COND_VAR_INIT(knt);

    *knt_out = knt;

    result = true;

  } while (false);

  return result;
}

bool
kadnet_uninit(
              KADNET* knt
             )
{
  bool result = false;

  do {

    if (!knt) break;

    KADNET_THREAD_CMD_LOCK_DESTROY(knt);

    KADNET_THREAD_DATA_LOCK_DESTROY(knt);

    KADNET_THREAD_COND_VAR_DESTROY(knt);

    mem_free(knt);

    result = true;

  } while (false);

  return result;
}

bool
kadnet_start(
             KADNET* knt
            )
{
  bool result = false;
  pthread_t thrd;

  do {

    if (!knt) break;

    if (0 != pthread_create(&thrd, NULL, kadnet_thread, (void*)knt)) break;

     knt->thrd = thrd;

    result = true;

  } while (false);

  return result;
}

bool
kadnet_stop(
            KADNET* knt
           )
{
  bool result = false;

  do {

    if (!knt) break;

    KADNET_THREAD_CMD_LOCK(knt);

    knt->thread_cmd = KADNET_THREAD_CMD_EXIT;

    knt->new_thread_cmd = true; 

    KADNET_THREAD_CMD_UNLOCK(knt);

    result = true;

  } while (false);

  return result;
}

bool
kadnet_get_status(
                  KADNET* knt,
                  KADNET_STATUS* knts
                 )
{
  bool result = false;
  KAD_USER_DATA kud;

  do {

    if (!knt || !knts) break;

    KADNET_THREAD_DATA_LOCK(knt);

    KADNET_THREAD_CMD_LOCK(knt);

    knt->thread_cmd = KADNET_THREAD_CMD_GET_DATA;

    knt->new_thread_cmd = true; 

    knt->data = &kud;

    KADNET_THREAD_CMD_UNLOCK(knt);

    KADNET_THREAD_COND_VAR_WAIT(knt);

    memcpy(knts, &kud, sizeof(KAD_USER_DATA));

    KADNET_THREAD_DATA_UNLOCK(knt);

    result = true;

  } while (false);

  return result;
}

bool
kadnet_search_keyword(
                      KADNET* knt,
                      const char* keyword
                     )
{
  bool result = false;
  KADNET_KEYWORD_SEARCH* kwd_srch = NULL;
  char* p = NULL;

  do {

    if (!keyword) break;

    kwd_srch = (KADNET_KEYWORD_SEARCH*)mem_alloc(sizeof(KADNET_KEYWORD_SEARCH) - 1 + strlen(keyword) + 1); 

    if (!kwd_srch){

      LOG_ERROR("Failed to allocate memory for keyword search.");

      break;

    }

    p = (char*)kwd_srch + sizeof(KADNET_KEYWORD_SEARCH) - 1;

    strcpy(p, keyword);

    kwd_srch->keyword = p;

    knt->kw_search_finished = false;

    knt->kw_search_results = NULL;

    KADNET_THREAD_CMD_LOCK(knt);

    knt->thread_cmd = KADNET_THREAD_CMD_START_KWD_SEARCH;

    knt->new_thread_cmd = true; 

    knt->data = kwd_srch;

    KADNET_THREAD_CMD_UNLOCK(knt);

    result = true;

  } while (false);

  return result;
}

bool
kadnet_is_keyword_search_finished(
                                  KADNET* knt
                                 )
{
  bool result = false;

  do {

    result = knt->kw_search_finished;

  } while (false);

  return result;
}

bool
kadnet_get_keyword_result(
                          KADNET* knt,
                          KADNET_SEARCH_RESULT_KEYWORD** ksrk_out 
                         )
{
  bool result = false;
  KADNET_SEARCH_RESULT_KEYWORD* ksrk = NULL;

  do {

    if (!knt || !ksrk_out) break;

    list_remove_first_entry(&knt->kw_search_results, (void**)&ksrk);

    if (!ksrk) break;

    *ksrk_out = ksrk;

    result = true;

  } while (false);

  return result;
}

bool
kadnet_search_file(
                   KADNET* knt,
                   uint8_t* file_id,
                   char* file_name,
                   uint64_t file_size
                  )
{
  bool result = false;
  KADNET_FILE_SEARCH* file_srch = NULL;
  char* p = NULL;

  do {

    file_srch = (KADNET_FILE_SEARCH*)mem_alloc(sizeof(KADNET_FILE_SEARCH) - 1 + strlen(file_name) + 1); 

    if (!file_srch){

      LOG_ERROR("Failed to allocate memory for file search.");

      break;

    }

    p = (char*)file_srch + sizeof(KADNET_FILE_SEARCH) - 1;

    strcpy(p, file_name);

    file_srch->file_name = p;

    memcpy(file_srch->file_id, file_id, sizeof(file_srch->file_id));

    file_srch->file_size = file_size;

    knt->file_search_finished = false;

    knt->file_search_results = NULL;

    KADNET_THREAD_CMD_LOCK(knt);

    knt->thread_cmd = KADNET_THREAD_CMD_START_FILE_SEARCH;

    knt->new_thread_cmd = true; 

    knt->data = file_srch;

    KADNET_THREAD_CMD_UNLOCK(knt);

  result = true;

  } while (false);

  return result;
}
