#define SERVER_PORT "11111"
#define LOCAL_HOST "127.0.0.1"
#define DEFAULT_IP LOCAL_HOST
#define BUF_SIZE 32*1024 // 32kb buffer

int rand_bytes(uint8_t* dest, size_t destlen);

void rand_cb(uint8_t* dest, size_t destlen, const ngtcp2_rand_ctx* rand_ctx);

int get_new_connection_id_cb(ngtcp2_conn* conn, ngtcp2_cid* cid, uint8_t* token, size_t cidlen, void* user_data);

uint64_t timestamp(void);

void debug_log(void *user_data, const char *format, ...);
