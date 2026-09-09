#ifndef _SAMPLE_POSIX_H_
#define _SAMPLE_POSIX_H_

#define PROTOCOL_MAGIC          0x504B5431
#define PROTOCOL_VERSION        (1 + 2)
#define MAX_RING_ENTRIES        (1 << 8)
#define RING_BUFFER_SIZE        (MAX_RING_ENTRIES * 64)

enum protocol_state {
    STATE_IDLE = 0,
    STATE_CONNECTING = 1,
    STATE_CONNECTED = 2,
    STATE_DISCONNECTED = 3
};

struct __attribute__((packed)) wire_header {
    uint32_t magic;
    uint16_t version;
    uint16_t length;
    uint32_t checksum;
};

struct driver_context {
    uint32_t context_id;
    struct wire_header last_hdr;
    enum protocol_state state;
};

int init_protocol_driver(struct driver_context *ctx);
void shutdown_protocol_driver(struct driver_context *ctx);

#endif // _SAMPLE_POSIX_H_
