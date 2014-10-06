import core.sys.posix.poll;

extern (C):

// alias <unimplemented> callback_function;
// alias <unimplemented> extension_callback_function;

enum lws_log_levels
{
	LLL_ERR = 1,
	LLL_WARN = 2,
	LLL_NOTICE = 4,
	LLL_INFO = 8,
	LLL_DEBUG = 16,
	LLL_PARSER = 32,
	LLL_HEADER = 64,
	LLL_EXT = 128,
	LLL_CLIENT = 256,
	LLL_LATENCY = 512,
	LLL_COUNT = 10
}

enum libwebsocket_context_options
{
	LWS_SERVER_OPTION_REQUIRE_VALID_OPENSSL_CLIENT_CERT = 2,
	LWS_SERVER_OPTION_SKIP_SERVER_CANONICAL_NAME = 4
}

enum libwebsocket_callback_reasons
{
	LWS_CALLBACK_ESTABLISHED = 0,
	LWS_CALLBACK_CLIENT_CONNECTION_ERROR = 1,
	LWS_CALLBACK_CLIENT_FILTER_PRE_ESTABLISH = 2,
	LWS_CALLBACK_CLIENT_ESTABLISHED = 3,
	LWS_CALLBACK_CLOSED = 4,
	LWS_CALLBACK_RECEIVE = 5,
	LWS_CALLBACK_CLIENT_RECEIVE = 6,
	LWS_CALLBACK_CLIENT_RECEIVE_PONG = 7,
	LWS_CALLBACK_CLIENT_WRITEABLE = 8,
	LWS_CALLBACK_SERVER_WRITEABLE = 9,
	LWS_CALLBACK_HTTP = 10,
	LWS_CALLBACK_HTTP_FILE_COMPLETION = 11,
	LWS_CALLBACK_FILTER_NETWORK_CONNECTION = 12,
	LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION = 13,
	LWS_CALLBACK_OPENSSL_LOAD_EXTRA_CLIENT_VERIFY_CERTS = 14,
	LWS_CALLBACK_OPENSSL_LOAD_EXTRA_SERVER_VERIFY_CERTS = 15,
	LWS_CALLBACK_OPENSSL_PERFORM_CLIENT_CERT_VERIFICATION = 16,
	LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER = 17,
	LWS_CALLBACK_CONFIRM_EXTENSION_OKAY = 18,
	LWS_CALLBACK_CLIENT_CONFIRM_EXTENSION_SUPPORTED = 19,
	LWS_CALLBACK_PROTOCOL_INIT = 20,
	LWS_CALLBACK_PROTOCOL_DESTROY = 21,
	LWS_CALLBACK_ADD_POLL_FD = 22,
	LWS_CALLBACK_DEL_POLL_FD = 23,
	LWS_CALLBACK_SET_MODE_POLL_FD = 24,
	LWS_CALLBACK_CLEAR_MODE_POLL_FD = 25
}

enum libwebsocket_extension_callback_reasons
{
	LWS_EXT_CALLBACK_SERVER_CONTEXT_CONSTRUCT = 0,
	LWS_EXT_CALLBACK_CLIENT_CONTEXT_CONSTRUCT = 1,
	LWS_EXT_CALLBACK_SERVER_CONTEXT_DESTRUCT = 2,
	LWS_EXT_CALLBACK_CLIENT_CONTEXT_DESTRUCT = 3,
	LWS_EXT_CALLBACK_CONSTRUCT = 4,
	LWS_EXT_CALLBACK_CLIENT_CONSTRUCT = 5,
	LWS_EXT_CALLBACK_CHECK_OK_TO_REALLY_CLOSE = 6,
	LWS_EXT_CALLBACK_CHECK_OK_TO_PROPOSE_EXTENSION = 7,
	LWS_EXT_CALLBACK_DESTROY = 8,
	LWS_EXT_CALLBACK_DESTROY_ANY_WSI_CLOSING = 9,
	LWS_EXT_CALLBACK_ANY_WSI_ESTABLISHED = 10,
	LWS_EXT_CALLBACK_PACKET_RX_PREPARSE = 11,
	LWS_EXT_CALLBACK_PACKET_TX_PRESEND = 12,
	LWS_EXT_CALLBACK_PACKET_TX_DO_SEND = 13,
	LWS_EXT_CALLBACK_HANDSHAKE_REPLY_TX = 14,
	LWS_EXT_CALLBACK_FLUSH_PENDING_TX = 15,
	LWS_EXT_CALLBACK_EXTENDED_PAYLOAD_RX = 16,
	LWS_EXT_CALLBACK_CAN_PROXY_CLIENT_CONNECTION = 17,
	LWS_EXT_CALLBACK_1HZ = 18,
	LWS_EXT_CALLBACK_REQUEST_ON_WRITEABLE = 19,
	LWS_EXT_CALLBACK_IS_WRITEABLE = 20,
	LWS_EXT_CALLBACK_PAYLOAD_TX = 21,
	LWS_EXT_CALLBACK_PAYLOAD_RX = 22
}

enum libwebsocket_write_protocol
{
	LWS_WRITE_TEXT = 0,
	LWS_WRITE_BINARY = 1,
	LWS_WRITE_CONTINUATION = 2,
	LWS_WRITE_HTTP = 3,
	LWS_WRITE_CLOSE = 4,
	LWS_WRITE_PING = 5,
	LWS_WRITE_PONG = 6,
	LWS_WRITE_NO_FIN = 64,
	LWS_WRITE_CLIENT_IGNORE_XOR_MASK = 128
}

enum lws_token_indexes
{
	WSI_TOKEN_GET_URI = 0,
	WSI_TOKEN_HOST = 1,
	WSI_TOKEN_CONNECTION = 2,
	WSI_TOKEN_KEY1 = 3,
	WSI_TOKEN_KEY2 = 4,
	WSI_TOKEN_PROTOCOL = 5,
	WSI_TOKEN_UPGRADE = 6,
	WSI_TOKEN_ORIGIN = 7,
	WSI_TOKEN_DRAFT = 8,
	WSI_TOKEN_CHALLENGE = 9,
	WSI_TOKEN_KEY = 10,
	WSI_TOKEN_VERSION = 11,
	WSI_TOKEN_SWORIGIN = 12,
	WSI_TOKEN_EXTENSIONS = 13,
	WSI_TOKEN_ACCEPT = 14,
	WSI_TOKEN_NONCE = 15,
	WSI_TOKEN_HTTP = 16,
	WSI_TOKEN_MUXURL = 17,
	_WSI_TOKEN_CLIENT_SENT_PROTOCOLS = 18,
	_WSI_TOKEN_CLIENT_PEER_ADDRESS = 19,
	_WSI_TOKEN_CLIENT_URI = 20,
	_WSI_TOKEN_CLIENT_HOST = 21,
	_WSI_TOKEN_CLIENT_ORIGIN = 22,
	WSI_TOKEN_COUNT = 23,
	WSI_TOKEN_NAME_PART = 24,
	WSI_TOKEN_SKIPPING = 25,
	WSI_TOKEN_SKIPPING_SAW_CR = 26,
	WSI_PARSING_COMPLETE = 27,
	WSI_INIT_TOKEN_MUXURL = 28
}

enum lws_close_status
{
	LWS_CLOSE_STATUS_NOSTATUS = 0,
	LWS_CLOSE_STATUS_NORMAL = 1000,
	LWS_CLOSE_STATUS_GOINGAWAY = 1001,
	LWS_CLOSE_STATUS_PROTOCOL_ERR = 1002,
	LWS_CLOSE_STATUS_UNACCEPTABLE_OPCODE = 1003,
	LWS_CLOSE_STATUS_RESERVED = 1004,
	LWS_CLOSE_STATUS_NO_STATUS = 1005,
	LWS_CLOSE_STATUS_ABNORMAL_CLOSE = 1006,
	LWS_CLOSE_STATUS_INVALID_PAYLOAD = 1007,
	LWS_CLOSE_STATUS_POLICY_VIOLATION = 1008,
	LWS_CLOSE_STATUS_MESSAGE_TOO_LARGE = 1009,
	LWS_CLOSE_STATUS_EXTENSION_REQUIRED = 1010,
	LWS_CLOSE_STATUS_UNEXPECTED_CONDITION = 1011,
	LWS_CLOSE_STATUS_TLS_FAILURE = 1015
}

struct lws_tokens
{
	char* token;
	int token_len;
}

struct libwebsocket_protocols
{
	const(char)* name;
	int function (libwebsocket_context*, libwebsocket*, libwebsocket_callback_reasons, void*, void*, size_t) callback;
	size_t per_session_data_size;
	size_t rx_buffer_size;
	libwebsocket_context* owning_server;
	int protocol_index;
}

struct libwebsocket_extension
{
	const(char)* name;
	int function (libwebsocket_context*, libwebsocket_extension*, libwebsocket*, libwebsocket_extension_callback_reasons, void*, void*, size_t) callback;
	size_t per_session_data_size;
	void* per_context_private_data;
}

struct lws_context_creation_info
{
	int port;
	const(char)* iface;
	libwebsocket_protocols* protocols;
	libwebsocket_extension* extensions;
	const(char)* ssl_cert_filepath;
	const(char)* ssl_private_key_filepath;
	const(char)* ssl_ca_filepath;
	int gid;
	int uid;
	uint options;
	void* user;
	int ka_time;
	int ka_probes;
	int ka_interval;
}

struct libwebsocket;


struct libwebsocket_context;


void _lws_log (int filter, const(char)* format, ...);
int callback (libwebsocket_context* context, libwebsocket* wsi, libwebsocket_callback_reasons reason, void* user, void* in_, size_t len);
int extension_callback (libwebsocket_context* context, libwebsocket_extension* ext, libwebsocket* wsi, libwebsocket_extension_callback_reasons reason, void* user, void* in_, size_t len);
void lws_set_log_level (int level, void function (int, const(char)*) log_emit_function);
void lwsl_emit_syslog (int level, const(char)* line);
libwebsocket_context* libwebsocket_create_context (lws_context_creation_info* info);
void libwebsocket_context_destroy (libwebsocket_context* context);
int libwebsocket_service (libwebsocket_context* context, int timeout_ms);
int libwebsocket_service_fd (libwebsocket_context* context, pollfd* pollfd);
void* libwebsocket_context_user (libwebsocket_context* context);
int libwebsocket_write (libwebsocket* wsi, ubyte* buf, size_t len, libwebsocket_write_protocol protocol);
int libwebsockets_serve_http_file (libwebsocket_context* context, libwebsocket* wsi, const(char)* file, const(char)* content_type);
int libwebsockets_serve_http_file_fragment (libwebsocket_context* context, libwebsocket* wsi);
const(libwebsocket_protocols)* libwebsockets_get_protocol (libwebsocket* wsi);
int libwebsocket_callback_on_writable (libwebsocket_context* context, libwebsocket* wsi);
int libwebsocket_callback_on_writable_all_protocol (const(libwebsocket_protocols)* protocol);
int libwebsocket_get_socket_fd (libwebsocket* wsi);
int libwebsocket_is_final_fragment (libwebsocket* wsi);
ubyte libwebsocket_get_reserved_bits (libwebsocket* wsi);
void* libwebsocket_ensure_user_space (libwebsocket* wsi);
int libwebsocket_rx_flow_control (libwebsocket* wsi, int enable);
size_t libwebsockets_remaining_packet_payload (libwebsocket* wsi);
libwebsocket* libwebsocket_client_connect (libwebsocket_context* clients, const(char)* address, int port, int ssl_connection, const(char)* path, const(char)* host, const(char)* origin, const(char)* protocol, int ietf_version_or_minus_one);
libwebsocket* libwebsocket_client_connect_extended (libwebsocket_context* clients, const(char)* address, int port, int ssl_connection, const(char)* path, const(char)* host, const(char)* origin, const(char)* protocol, int ietf_version_or_minus_one, void* userdata);
const(char)* libwebsocket_canonical_hostname (libwebsocket_context* context);
void libwebsockets_get_peer_addresses (libwebsocket_context* context, libwebsocket* wsi, int fd, char* name, int name_len, char* rip, int rip_len);
int libwebsockets_get_random (libwebsocket_context* context, void* buf, int len);
int lws_daemonize (const(char)* _lock_path);
int lws_send_pipe_choked (libwebsocket* wsi);
int lws_frame_is_binary (libwebsocket* wsi);
ubyte* libwebsockets_SHA1 (const(ubyte)* d, size_t n, ubyte* md);
int lws_b64_encode_string (const(char)* in_, int in_len, char* out_, int out_size);
int lws_b64_decode_string (const(char)* in_, char* out_, int out_size);
const(char)* lws_get_library_version ();
int lws_hdr_total_length (libwebsocket* wsi, lws_token_indexes h);
int lws_hdr_copy (libwebsocket* wsi, char* dest, int len, lws_token_indexes h);
int libwebsocket_read (libwebsocket_context* context, libwebsocket* wsi, ubyte* buf, size_t len);
libwebsocket_extension* libwebsocket_get_internal_extensions ();
