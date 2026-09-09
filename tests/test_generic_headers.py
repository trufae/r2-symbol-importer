import pytest
from r2_symbol_importer.core.pipeline import SymbolPipeline


def test_network_protocol_header():
    header = """
    #define IP_HEADER_MIN_LEN   20
    #define TCP_FLAG_FIN        (1 << 0)
    #define TCP_FLAG_SYN        (1 << 1)
    #define TCP_FLAG_RST        (1 << 2)
    #define TCP_FLAG_PSH        (1 << 3)
    #define TCP_FLAG_ACK        (1 << 4)
    #define TCP_FLAGS_CONN      (TCP_FLAG_SYN | TCP_FLAG_ACK)

    enum transport_proto {
        PROTO_ICMP = 1,
        PROTO_TCP = 6,
        PROTO_UDP = 17
    };

    struct ip_header {
        uint8_t  version_ihl;
        uint8_t  tos;
        uint16_t total_length;
        uint16_t id;
        uint16_t flags_fo;
        uint8_t  ttl;
        uint8_t  protocol;
        uint16_t checksum;
        uint32_t src_ip;
        uint32_t dst_ip;
    };

    struct tcp_header {
        uint16_t src_port;
        uint16_t dst_port;
        uint32_t seq_num;
        uint32_t ack_num;
        uint8_t  data_offset;
        uint8_t  flags;
        uint16_t window_size;
        uint16_t checksum;
        uint16_t urgent_ptr;
    };

    int parse_packet(const struct ip_header *ip, const struct tcp_header *tcp, uint8_t *payload, size_t len);
    """

    pipeline = SymbolPipeline()
    result = pipeline.extract_from_text(header)

    assert len(result.types) >= 3  # enum + 2 structs
    assert len(result.prototypes) == 1
    assert len(result.constants) == 7

    const_map = {c.name: c.value for c in result.constants}
    assert const_map["TCP_FLAG_SYN"] == 2
    assert const_map["TCP_FLAGS_CONN"] == 18
    assert result.prototypes[0].name == "parse_packet"


def test_embedded_firmware_register_map():
    header = """
    #define PERIPH_BASE         0x40000000
    #define APB1_OFFSET         0x00000000
    #define APB2_OFFSET         0x00010000
    #define USART1_BASE         (PERIPH_BASE + APB2_OFFSET + 0x3800)
    #define USART_CR1_UE        (1 << 13)
    #define USART_CR1_TE        (1 << 3)
    #define USART_CR1_RE        (1 << 2)
    #define USART_ENABLE_TXRX   (USART_CR1_UE | USART_CR1_TE | USART_CR1_RE)

    typedef struct {
        volatile uint32_t SR;
        volatile uint32_t DR;
        volatile uint32_t BRR;
        volatile uint32_t CR1;
        volatile uint32_t CR2;
        volatile uint32_t CR3;
        volatile uint32_t GTPR;
    } USART_TypeDef;

    void usart_init(USART_TypeDef *usart, uint32_t baudrate);
    void usart_send_byte(USART_TypeDef *usart, uint8_t data);
    """

    pipeline = SymbolPipeline()
    result = pipeline.extract_from_text(header)

    const_map = {c.name: c.value for c in result.constants}
    assert const_map["USART1_BASE"] == 0x40013800
    assert const_map["USART_ENABLE_TXRX"] == 0x200C
    assert len(result.types) >= 1
    assert len(result.prototypes) == 2


def test_userland_library_with_extern_c():
    header = """
    #ifdef __cplusplus
    extern "C" {
    #endif

    #define IMAGE_MAGIC         0x89504E47
    #define MAX_CHANNELS        4

    typedef enum {
        COLOR_RGB = 0,
        COLOR_RGBA = 1,
        COLOR_GRAYSCALE = 2
    } color_format_t;

    typedef struct image_info {
        uint32_t width;
        uint32_t height;
        uint8_t channels;
        color_format_t format;
    } image_info_t;

    image_info_t *image_load(const char *filename);
    void image_free(image_info_t *img);

    #ifdef __cplusplus
    }
    #endif
    """

    pipeline = SymbolPipeline()
    result = pipeline.extract_from_text(header)

    assert len(result.constants) == 2
    assert len(result.types) >= 2
    assert len(result.prototypes) == 2
    proto_names = [p.name for p in result.prototypes]
    assert "image_load" in proto_names
    assert "image_free" in proto_names
