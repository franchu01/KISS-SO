#ifndef SHARED_UTILS_H
#define SHARED_UTILS_H

#include <stdio.h>
#include <stdbool.h>
#include <inttypes.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>
#include <assert.h>

#include <commons/log.h>
#include <commons/config.h>
#include <commons/string.h>
#include <commons/log.h>
#include <commons/config.h>
#include <commons/collections/list.h>

#include <readline/readline.h>
#include <readline/history.h>

#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <signal.h>
#include <pthread.h>
#include <semaphore.h>

#define thread_local __thread
typedef uint32_t u32;
typedef uint8_t u8;

// Declaracion del logger global. La definicion va en cada modulo `t_log* logger;`
extern t_log *logger;

static inline void assert_and_log(int b, char *s)
{
    if (!b)
    {
        log_error(logger, s);
        log_destroy(logger);
        assert(b);
    }
}

// Funciones de utilidad para sockets

// Se conecta a un server
int open_socket_conn(char *ip, int port);
// Crea un socket de escucha (servidor)
int open_listener_socket(int port);
// Acepta una nueva conexion en un socket de escucha. Bloqueante
int accept_new_conn(int sock_listen);

// Devuelve true si el string del primer parametro empieza con el string del 2do parametro
bool starts_with(const char *str, const char *pre);

// Para claridad y no castear tanto a mano
u32 read_u32(u32 *p);

int64_t timestamp();

enum inst_code
{
    // Start at 1 so 0 is not a valid code
    INST_NO_OP = 1,
    INST_IO,
    INST_READ,
    INST_WRITE,
    INST_COPY,
    INST_EXIT

};
// Devuelve un string para imprimir en logs el codigo de instruccion
char *inst_code_str(enum inst_code);
typedef struct inst
{
    enum inst_code code;
    u32 args[2];
} inst_t;
static inline void log_inst(inst_t *insts, inst_t *inst)
{
    int c = (((int)inst) - ((int)insts)) / sizeof(inst_t);
    log_info(logger, "inst %04d: code(%d) %-10s arg0 %d arg1 %d",
             c, inst->code, inst_code_str(inst->code), insts->args[0], inst->args[1]);
}
static inline void log_insts(inst_t *insts, u32 count)
{
    inst_t *end = insts + count;
    inst_t *inst_it = insts;
    while (inst_it != end && inst_it->code != 0)
    {
        log_inst(insts, inst_it);
        inst_it++;
    }
}

// Un struct con un puntero a memoria y su tamanio
// Nota: `len` es el tamanio TOTAL del buffer que se alloco
//       y NO el tamanio de lo que se haya escrito.
typedef struct buflen
{
    void *buf;
    int len;
} t_buflen;
static inline t_buflen make_buf(int size)
{
    t_buflen b = {malloc(size), size};
    return b;
}

// Asegurarse que el buffer tenga cierta cantidad de bytes. realloca de
// ser necesario.
void ensure_buffer_size(t_buflen *buffer, u32 required_size);

void start_detached_thread(void *(*f)(void *), void *param);

// `buf` debe apuntar a una region de memoria de por lo menos `len` bytes
// Retorna 0 si OK, -1 si hubo errores
int send_buffer(int sock, char *buf, int len);
// `buf` debe apuntar a una region de memoria de por lo menos `len` bytes
// Retorna 0 si OK, -1 si hubo errores
int recv_buffer(int sock, char *buf, int len);

// El protocolo de envio de mensajes lo definimos asi (Entre parentesis esta el tipo de dato/tamanio de cada dato):
// El cliente envia:
//                       [ codigo_mensaje(32) longitud_contenido(u32) CONTENIDO_IN MSG_TRAILER_SIGNATURE(u8) ]
// Luego cliente recibe:
//                       [ CONTENIDO_OUT ]
// CONTENIDO_OUT y CONTENIDO_IN es especifico de cada `enum codigo_mensaje`.
// Ver los comentarios en enum codigo_mensaje para definiciones de IN/OUT.
//
// Ademas, al iniciar una conexion tenemos un HANDSHAKE. Ver HANDSHAKE en `enum codigo_mensaje`
//
// Las funciones send_* envian los mensajes. Bloquean en el envio de la respuesta y
//  bloquean de vuelta para recibir la respuesta.
// Del otro lado los mensajes se reciben con recv_msg, que deja en el puntero buf->buf el contenido IN del mensaje
//  y devuelve el header con el codigo. El parseo del mensaje IN desde ese buffer se hace a mano en el lugar de uso
//  y se escribe en el mismo buffer la respuesta OUT, que se envia con send_buffer.

#define HANDSHAKE_SIGNATURE ((u8)0xBB)
#define HANDSHAKE_SIGNATURE_RES ((u8)0xAA)
#define MSG_TRAILER_SIGNATURE ((u8)0xCC)
// Mensajes que se pueden enviar
// - Mantener al dia con CODIGO_MENSAJE_STRING_TABLE en shared_utils.c para convertirlos a string
//   en los logs.
enum codigo_mensaje
{
    CODIGO_INVALIDO = 0,
    // Cuando iniciamos una conexion enviamos un HANDSHAKE
    // Para asegurarnos de que es una conexion valida
    // IN: [ 0xBB ]
    //
    // OUT: [ 0xAA ]
    HANDHSHAKE,
    // CONSOLA -> KERNEL
    // El valor de retorno deberia ser 0xBB. Es simplemente para que se bloquie la consola hasta que termine el proceso.
    //
    // IN: [ tamanio(u32) cantidad_inst(u32) array_instrucciones(inst_t {u32, 32[2]}) ]
    //
    // OUT: [ ret_code(u32) ]
    NUEVO_PROCESO,
    // CPU -> MEMORIA
    // IN: [ ]
    //
    // OUT: [ cant_entradas_x_pagina(u32) tam_pagina(u32) ]
    HANDSHAKE_CPU_MEMORIA,
    // CPU -> MEMORIA
    // is_write == 0 : write_val se ignora y es un read
    // is_write != 0 : write_val se escribe en addr. OUT tiene write_val
    // page_offset y campo page_lvl2_num solo se envia para que la memoria marque el bit de uso/modificado
    //
    // IN: [ addr(u32) is_write(u32) write_val(u32) page_lvl2_num(u32) page_offset(u32) ]
    //
    // OUT: [ read(u32) ]
    MEMORIA_READWRITE,
    // CPU -> MEMORIA
    // Devuelve los marcos invalidados para quitar de la TLB
    //
    //
    // IN: [ page_num(u32) page_offset(u32) ]
    //
    // OUT: [ read(u32) num_invalidations(u32) N*marco_invalidado(u32) ]
    MEMORIA_PAGEREAD,
    // KERNEL -> MEMORIA
    //
    // IN: [ pid(u32) ]
    //
    // OUT: [ nro_pagina_1er_nivel(u32) ]
    MEMORIA_NEW_PROCESS,
    // CPU -> MEMORIA
    //
    // IN: [ pid(u32) nro_pagina_1er_nivel(u32) ]
    //
    // OUT: [ ]
    MEMORIA_PROCESS_SUSPENDED,
    // CPU -> MEMORIA
    //
    // IN: [ pid(u32) nro_pagina_1er_nivel(u32) ]
    //
    // OUT: [ ]
    MEMORIA_PROCESS_UNSUSPENDED,
    // CPU -> MEMORIA
    //
    // IN: [ pid(u32) nro_pagina_1er_nivel(u32) ]
    //
    // OUT: [ ]
    MEMORIA_END_PROCESS,
    // KERNEL -> CPU
    // rafaga son los ms de ejecucion
    // Si bloqueo_io es 0, no se bloqueo el proceso. Caso contrario, es los ms de bloqueo
    // pc es el nuevo pc luego de la rafaga
    //
    // IN: [ pid(u32) pc(u32) tabla_pags_niv_1(u32) num_insts(u32) N*inst({u32, u32[4]}) ]
    //
    // OUT: [ pid(u32) pc(u32) rafaga(u32) bloqueo_io(u32) ]
    DISPATCH_PROCESS,
    // KERNEL -> CPU
    //
    // IN: [ pid(u32) ]
    //
    // OUT: [ ]
    INTERRUPT_PROCESS,

};
// Devuelve un string estatico, no hace falta hacerle free(), son estaticos
char *codigo_msg_to_string(enum codigo_mensaje);

typedef struct msgheader
{
    enum codigo_mensaje codigo;
    u32 cant_bytes_contenido;
} __attribute__((packed)) t_msgheader;

// Retorna codigo CODIGO_INVALIDO en .codigo si hubo algun error
t_msgheader recv_msg(int sock, t_buflen *buf);

u32 send_nuevo_proceso(int sockfd, t_buflen *buf, u32 inst_count, inst_t *insts, u32 tamanio);
void send_handshake_cpu_memoria(int sockfd, t_buflen *buf, u32 *out_cant_entradas_x_pagina, u32 *out_tam_pagina);
// Devuelve valor leido o escrito
u32 send_mem_readwrite(int sockfd, t_buflen *buf, u32 addr, u32 is_write, u32 val, u32 page_lvl2_num, u32 page_offset);
// Devuelve el valor leido (num pagina 2do nivel o direccion de memoria del marco)
// Luego de la llamada, *count_invals tiene la cantidad de marcos invalidados
// y si es mayor a 0, *marcos tiene un puntero a un array con los marcos
// NOTA: *marcos termina apuntando al buffer `buf, NO llamar a free() con ese puntero
u32 send_mem_page_read(int sockfd, t_buflen *buf, u32 num_page, u32 page_offset, u32 *count_invals, u32 **marcos);
// Devuelve nro pagina 1er nivel
u32 send_mem_new_process(int sockfd, t_buflen *buf, u32 pid);
void send_mem_process_suspended(int sockfd, t_buflen *buf, u32 pid, u32 nro_pagina_1er_nivel);
void send_mem_process_unsuspended(int sockfd, t_buflen *buf, u32 pid, u32 nro_pagina_1er_nivel);
void send_mem_end_process(int sockfd, t_buflen *buf, u32 pid, u32 nro_pagina_1er_nivel);
struct dispatch_res
{
    u32 pid;
    u32 pc;
    u32 rafaga;
    u32 bloqueo_io;
} __attribute__((packed));
struct dispatch_res send_dispatch(int sockfd, t_buflen *buf, u32 pid, u32 pc, u32 tab_pags_niv_1, u32 num_insts, inst_t *insts);
void send_interrupt(int sockfd, t_buflen *buf, u32 pid);

#endif