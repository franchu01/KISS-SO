#include "shared_utils.h"
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>

bool starts_with(const char *str, const char *pre)
{
    return strncmp(str, pre, strlen(pre)) == 0;
}

char *codigo_msg_to_string(enum codigo_mensaje code)
{
    static char *CODIGO_MENSAJE_STRING_TABLE[] = {
        "CODIGO_INVALIDO",
        "HANDHSHAKE",
        "NUEVO_PROCESO",
        "HANDSHAKE_CPU_MEMORIA",
        "MEMORIA_READWRITE",
        "MEMORIA_PAGEREAD",
        "MEMORIA_NEW_PROCESS",
        "MEMORIA_PROCESS_SUSPENDED",
        "MEMORIA_PROCESS_UNSUSPENDED",
        "MEMORIA_END_PROCESS",
        "DISPATCH_PROCESS",
        "INTERRUPT_PROCESS",
    };
    int num_msgs = sizeof(CODIGO_MENSAJE_STRING_TABLE) / sizeof(*CODIGO_MENSAJE_STRING_TABLE);
    return code < num_msgs ? CODIGO_MENSAJE_STRING_TABLE[(int)code] : "CODIGO DESCONOCIDO (Ni siquiera invalido)";
}

char *inst_code_str(enum inst_code code)
{
    static char *INST_STRING_TABLE[] = {
        "INST_INVALIDA",
        "INST_NO_OP",
        "INST_IO",
        "INST_READ",
        "INST_WRITE",
        "INST_COPY",
        "INST_EXIT",
    };
    int num_msgs = sizeof(INST_STRING_TABLE) / sizeof(*INST_STRING_TABLE);
    return code < num_msgs ? INST_STRING_TABLE[(int)code] : "INSTRUCCION DESCONOCIDA (Ni siquiera invalida)";
}

int64_t timestamp()
{
    struct timespec tms;
    if (clock_gettime(CLOCK_REALTIME, &tms))
    {
        log_error(logger, "Error clock_gettime(CLOCK_REALTIME, &tms) strerror: %s", strerror(errno));
        exit(-1);
    }
    /* seconds, multiplied with 1 million */
    int64_t micros = tms.tv_sec * (int64_t)1000000;
    /* Add full microseconds */
    micros += tms.tv_nsec / (int64_t)1000;
    return micros;
}

void start_detached_thread(void *(*f)(void *), void *param)
{
    pthread_attr_t attrs = {};
    int ret = pthread_attr_setdetachstate(&attrs, PTHREAD_CREATE_DETACHED);
    if (ret != 0 || errno)
    {
        log_error(logger, "error start_detached_thread(f: 0x%p, param: 0x%p) "
                          "pthread_attr_setdetachstate(&attrs, PTHREAD_CREATE_DETACHED) strerror: %s",
                  f, param, strerror(errno));
        log_destroy(logger);
        exit(-1);
    }

    pthread_t t_id;
    ret = pthread_create(&t_id, &attrs, f, param);
    if (ret != 0 || errno)
    {
        log_error(logger, "error start_detached_thread(f: 0x%p, param: 0x%p) pthread_create strerror: %s", f, param, strerror(errno));
        log_destroy(logger);
        exit(-1);
    }
}

void ensure_buffer_size(t_buflen *buffer, u32 required_size)
{
    if (required_size > buffer->len)
    {
        buffer->buf = realloc(buffer->buf, required_size);
        buffer->len = required_size;
    }
}
int send_buffer(int sock, char *buf, int len)
{
    // send puede enviar parcialmente un buffer. Loopear hasta que enviemos los `len` bytes
    while (len > 0)
    {
        int sent = send(sock, buf, len, 0);
        if (sent <= 0)
        {
            log_error(logger, "Error send(socket:%d, buf: 0x%p, len: %d, 0) strerror: %s", sock, buf, len, strerror(errno));
            return -1;
        }
        len -= sent;
        buf += sent;
    }
    return 0;
}
int recv_buffer(int sock, char *buf, int len)
{
    // recv puede recibir parcialmente un buffer. Loopear hasta que tengamos los `len` bytes
    while (len > 0)
    {
        int recvd = recv(sock, buf, len, 0);
        if (recvd <= 0)
        {
            log_error(logger, "Error recv(socket: %d, buf: 0x%p, len: %d, 0) strerror: %s", sock, buf, len, strerror(errno));
            return -1;
        }
        len -= recvd;
        buf += recvd;
    }
    return 0;
}

int open_listener_socket(int port)
{

    struct sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    server.sin_addr.s_addr = INADDR_ANY;
    bzero(&(server.sin_zero), 8);
    int sockfd;
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        log_error(logger, "error open_listener_socket(%d) socket(AF_INET, SOCK_STREAM, 0) strerror: %s", port, strerror(errno));
        log_destroy(logger);
        exit(-1);
    }

    int activado = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &activado, sizeof(activado));
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &activado, sizeof(activado));

    if (bind(sockfd, (struct sockaddr *)&server, sizeof(struct sockaddr)) == -1)
    {
        log_error(logger, "error open_listener_socket(%d) bind(%d) strerror: %s", port, port, strerror(errno));
        log_destroy(logger);
        exit(-1);
    }

    if (listen(sockfd, 5) == -1)
    {
        log_error(logger, "error open_listener_socket(%d) listen(%d) strerror: %s", port, sockfd, strerror(errno));
        log_destroy(logger);
        exit(-1);
    }

    return sockfd;
}

struct handshake_msg
{
    t_msgheader header;
    //enum codigo_mensaje msg_code;
    //u32 content_len;
    u8 handshake_signature;
    u8 trailer_signature;
} __attribute__((packed));
int open_socket_conn(char *ip, int port)
{
    struct sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    server.sin_addr.s_addr = inet_addr(ip);
    bzero(&(server.sin_zero), 8);

    int fd;
    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        log_error(logger, "Error open_socket_conn(%s:%d) socket(AF_INET, SOCK_STREAM, 0) strerror: %s", ip, port, strerror(errno));
        log_destroy(logger);
        exit(-1);
    }

    if (connect(fd, (struct sockaddr *)&server,
                sizeof(struct sockaddr)) == -1)
    {
        log_error(logger, "Error open_socket_conn(%s:%d) connect(%d, &server, sizeof(struct sockaddr)) strerror: %s",
                  ip, port, fd, strerror(errno));
        log_destroy(logger);
        exit(-1);
    }

    struct handshake_msg data = {};
    data.header.codigo = HANDHSHAKE;
    data.header.cant_bytes_contenido = 1;
    data.handshake_signature = HANDSHAKE_SIGNATURE;
    data.trailer_signature = MSG_TRAILER_SIGNATURE;

    send_buffer(fd, &data, sizeof(data));
    recv_buffer(fd, &data, sizeof(data));

    if (data.header.codigo != HANDHSHAKE ||
        data.handshake_signature != HANDSHAKE_SIGNATURE_RES ||
        data.header.cant_bytes_contenido != 1 ||
        data.trailer_signature != MSG_TRAILER_SIGNATURE)
    {
        log_error(logger,
                  "Error open_socket_conn(%s:%d) handshake failed msg_code(%d): %s handshake: %#08X trailer: %#08X len: %d",
                  ip, port, data.header.codigo, codigo_msg_to_string(data.header.codigo), data.handshake_signature, data.trailer_signature, data.header.cant_bytes_contenido);
        log_destroy(logger);
        exit(-1);
    }

    return fd;
}
int accept_new_conn(int sock_listen)
{

    log_info(logger, "Aceptando nueva conexion");
    struct sockaddr_storage their_addr;
    socklen_t sin_size = sizeof their_addr;
    int new_sock = accept(sock_listen, (struct sockaddr *)&their_addr, &sin_size);
    if (new_sock == -1)
    {
        log_error(logger, "Error accept_new_conn(%d) strerror: %s", sock_listen, strerror(errno));
        log_destroy(logger);
        exit(-1);
    }

    struct handshake_msg data = {};

    assert_and_log(recv_buffer(new_sock, &data, sizeof(data)) == 0, "recv handshake");
    if (data.header.codigo != HANDHSHAKE ||
        data.handshake_signature != HANDSHAKE_SIGNATURE ||
        data.header.cant_bytes_contenido != 1 ||
        data.trailer_signature != MSG_TRAILER_SIGNATURE)
    {
        log_error(logger,
                  "Error accept_new_conn(%d) new_sock: %d handshake failed msg_code(%d): %s handshake: %#08X trailer: %#08X len: %d",
                  sock_listen, new_sock, data.header.cant_bytes_contenido, codigo_msg_to_string(data.header.cant_bytes_contenido), data.handshake_signature, data.trailer_signature, data.header.cant_bytes_contenido);
        log_destroy(logger);
        exit(-1);
    }

    data.header.codigo = HANDHSHAKE;
    data.header.cant_bytes_contenido = 1;
    data.handshake_signature = HANDSHAKE_SIGNATURE_RES;
    data.trailer_signature = MSG_TRAILER_SIGNATURE;
    assert_and_log(send_buffer(new_sock, &data, sizeof(data)) == 0, "send handshake");

    return new_sock;
}

t_msgheader recv_msg(int sock, t_buflen *buf)
{
    static t_msgheader header_invalido = {};
    t_msgheader header;
    int err = recv_buffer(sock, (char *)&header, sizeof(header));
    if (err == -1)
        return header_invalido;

    // + 1 por el trailer_signature
    ensure_buffer_size(buf, header.cant_bytes_contenido + 1);
    err = recv_buffer(sock, buf->buf, header.cant_bytes_contenido + 1);
    if (err == -1)
        return header_invalido;

    u8 trailer_signature = ((u8 *)buf->buf)[header.cant_bytes_contenido];
    assert_and_log(trailer_signature == MSG_TRAILER_SIGNATURE, "Invalid trailer recv_msg");

    return header;
}

#define HEADER_SIZE (sizeof(codigo) + sizeof(u32))
#define WRITE_CODE_AND_LENGTH(buffer, buf_ptr_var_name, code, length) \
    do                                                                \
    {                                                                 \
        ensure_buffer_size(buffer, HEADER_SIZE + length);             \
        buf_ptr_var_name = buffer->buf;                               \
        *((enum codigo_mensaje *)buf_ptr_var_name) = code;            \
        buf_ptr_var_name += sizeof(enum codigo_mensaje);              \
                                                                      \
        *((u32 *)buf_ptr_var_name) = length;                          \
        buf_ptr_var_name += sizeof(u32);                              \
    } while (0)

typedef struct writer
{
    t_buflen *buf;
    u32 written;
} t_writer;
#define WRITE_AUX_MACRO(w, v)                                   \
    int to_write = sizeof v;                                    \
    ensure_buffer_size(w->buf, w->written + to_write);          \
    memcpy(((char *)(w->buf->buf)) + w->written, &v, to_write); \
    w->written += to_write;
void write_u32(t_writer *w, u32 v)
{
    WRITE_AUX_MACRO(w, v);
}
void write_u8(t_writer *w, u8 v)
{
    WRITE_AUX_MACRO(w, v);
}
void finish_writing(t_writer *w)
{
    t_msgheader *h = w->buf->buf;
    h->cant_bytes_contenido = w->written - (sizeof(u32) * 2);
    write_u8(w, MSG_TRAILER_SIGNATURE);
}
t_writer writer(enum codigo_mensaje cod, t_buflen *buf)
{
    t_writer w = {};
    w.buf = buf;
    w.written = 0;
    write_u32(&w, cod);
    // cant_bytes_contenido, escrito en finish_writing
    write_u32(&w, 0);
    return w;
}

u32 read_u32(u32 *p)
{
    return *p;
}

u32 send_nuevo_proceso(int sockfd, t_buflen *buf, u32 num_insts, inst_t *insts, u32 tamanio)
{
    t_writer ww = writer(NUEVO_PROCESO, buf);
    t_writer *w = &ww;
    write_u32(w, tamanio);
    write_u32(w, num_insts);
    for (inst_t *end = insts + num_insts; insts != end; insts++)
    {
        write_u32(w, insts->code);
        write_u32(w, insts->args[0]);
        write_u32(w, insts->args[1]);
    }
    finish_writing(w);
    assert_and_log(send_buffer(sockfd, buf->buf, w->written) == 0, "error send NUEVO_PROCESO");

    log_info(logger, "Proceso enviado al kernel, esperando respuesta ...");

    assert_and_log(recv_buffer(sockfd, buf->buf, sizeof(u32)) == 0, "error recv NUEVO_PROCESO");
    return read_u32(buf->buf);
}
void send_handshake_cpu_memoria(int sockfd, t_buflen *buf, u32 *out_cant_entradas_x_pagina, u32 *out_tam_pagina)
{
    t_writer ww = writer(HANDSHAKE_CPU_MEMORIA, buf);
    finish_writing(&ww);
    assert_and_log(send_buffer(sockfd, buf->buf, ww.written) == 0, "error send HANDSHAKE_CPU_MEMORIA");

    assert_and_log(recv_buffer(sockfd, buf->buf, sizeof(u32) * 2) == 0, "error recv HANDSHAKE_CPU_MEMORIA");
    *out_cant_entradas_x_pagina = read_u32(buf->buf);
    *out_tam_pagina = read_u32(buf->buf + sizeof(u32));
}
u32 send_mem_new_process(int sockfd, t_buflen *buf, u32 pid)
{
    t_writer ww = writer(MEMORIA_NEW_PROCESS, buf);
    write_u32(&ww, pid);
    finish_writing(&ww);
    assert_and_log(send_buffer(sockfd, buf->buf, ww.written) == 0, "error send MEMORIA_NEW_PROCESS");

    assert_and_log(recv_buffer(sockfd, buf->buf, sizeof(u32)) == 0, "error recv MEMORIA_NEW_PROCESS");
    return read_u32(buf->buf);
}
u32 send_mem_readwrite(int sockfd, t_buflen *buf, u32 addr, u32 is_write, u32 val, u32 page_lvl2_num, u32 page_offset)
{
    t_writer ww = writer(MEMORIA_READWRITE, buf);
    t_writer *w = &ww;
    write_u32(w, addr);
    write_u32(w, is_write);
    write_u32(w, val);
    write_u32(w, page_lvl2_num);
    write_u32(w, page_offset);
    finish_writing(w);
    assert_and_log(send_buffer(sockfd, buf->buf, w->written) == 0, "error send MEMORIA_READWRITE");

    assert_and_log(recv_buffer(sockfd, buf->buf, sizeof(u32)) == 0, "error recv MEMORIA_READWRITE");
    return read_u32(buf->buf);
}
u32 send_mem_page_read(int sockfd, t_buflen *buf, u32 num_page, u32 page_offset, u32 *count_invals, u32 **marcos)
{
    t_writer ww = writer(MEMORIA_PAGEREAD, buf);
    t_writer *w = &ww;
    write_u32(w, num_page);
    write_u32(w, page_offset);
    finish_writing(w);
    assert_and_log(send_buffer(sockfd, buf->buf, w->written) == 0, "error send MEMORIA_PAGEREAD");

    assert_and_log(recv_buffer(sockfd, buf->buf, sizeof(u32) * 2) == 0, "error recv MEMORIA_PAGEREAD");
    u32 read_val = read_u32(buf->buf);
    *count_invals = read_u32(buf->buf + 4);
    if (*count_invals > 0)
    {
        recv_buffer(sockfd, buf->buf, sizeof(u32) * (*count_invals));
        *marcos = buf->buf;
    }
    else
    {
        *marcos = 0;
    }
    return read_val;
}
void send_mem_process_suspended(int sockfd, t_buflen *buf, u32 pid, u32 nro_pagina_1er_nivel)
{
    t_writer ww = writer(MEMORIA_PROCESS_UNSUSPENDED, buf);
    write_u32(&ww, pid);
    write_u32(&ww, nro_pagina_1er_nivel);
    finish_writing(&ww);
    assert_and_log(send_buffer(sockfd, buf->buf, ww.written) == 0, "error send MEMORIA_PROCESS_UNSUSPENDED");
}
void send_mem_process_unsuspended(int sockfd, t_buflen *buf, u32 pid, u32 nro_pagina_1er_nivel)
{
    t_writer ww = writer(MEMORIA_PROCESS_SUSPENDED, buf);
    write_u32(&ww, pid);
    write_u32(&ww, nro_pagina_1er_nivel);
    finish_writing(&ww);
    assert_and_log(send_buffer(sockfd, buf->buf, ww.written) == 0, "error send MEMORIA_PROCESS_SUSPENDED");
}
void send_mem_end_process(int sockfd, t_buflen *buf, u32 pid, u32 nro_pagina_1er_nivel)
{
    t_writer ww = writer(MEMORIA_END_PROCESS, buf);
    write_u32(&ww, pid);
    write_u32(&ww, nro_pagina_1er_nivel);
    finish_writing(&ww);
    assert_and_log(send_buffer(sockfd, buf->buf, ww.written) == 0, "error send MEMORIA_END_PROCESS");
}
struct dispatch_res send_dispatch(int sockfd, t_buflen *buf, u32 pid, u32 pc, u32 tab_pags_niv_1, u32 num_insts, inst_t *insts)
{
    t_writer ww = writer(DISPATCH_PROCESS, buf);
    t_writer *w = &ww;
    write_u32(w, pid);
    write_u32(w, pc);
    write_u32(w, tab_pags_niv_1);
    write_u32(w, num_insts);
    for (inst_t *end = insts + num_insts; insts != end; insts++)
    {
        write_u32(w, insts->code);
        write_u32(w, insts->args[0]);
        write_u32(w, insts->args[1]);
    }
    finish_writing(w);
    assert_and_log(send_buffer(sockfd, buf->buf, w->written) == 0, "error send DISPATCH_PROCESS");

    assert_and_log(recv_buffer(sockfd, buf->buf, sizeof(u32) * 4) == 0, "error recv DISPATCH_PROCESS");
    struct dispatch_res res;
    res.pid = read_u32(buf->buf);
    res.pc = read_u32(buf->buf + 4);
    res.rafaga = read_u32(buf->buf + 8);
    res.bloqueo_io = read_u32(buf->buf + 12);
    return res;
}
void send_interrupt(int sockfd, t_buflen *buf, u32 pid)
{
    t_writer ww = writer(INTERRUPT_PROCESS, buf);
    write_u32(&ww, pid);
    finish_writing(&ww);
    assert_and_log(send_buffer(sockfd, buf->buf, ww.written) == 0, "error send INTERRUPT_PROCESS");
}