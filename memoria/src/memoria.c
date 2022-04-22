#include "memoria.h"

void *connection_handler_thread(void *);
t_log *logger;

enum alg_reemplazo
{
    ALG_CLOCK_M,
    ALG_CLOCK
};
enum alg_reemplazo alg;
int tam_mem;
int tam_pag;
int pags_x_tabl;
int marcos_x_proc;
int retardo_memoria;
int retardo_swap;

struct page2_table_entry
{
    u32 frame_number;
};

struct page1_table_entry
{
    u32 page2_page_number;
};
struct page_table_entry
{
    // Presente si != 0
    u8 flag_presencia;
    u8 flag_uso;
    // Modificada si != 0
    u8 flag_modif;
    union {
        struct page1_table_entry p1;
        struct page2_table_entry p2;
        u32 val;
    };
};
typedef struct page_table
{
    // zero if unused
    u8 in_use;
    struct page_table_entry *entries;
} page_table;

page_table *page_tables = NULL;
u32 page_tables_elem_count = 0;
u32 *memoria_ram = NULL;

u32 get_unused_pagetable()
{
    for (page_table *it = page_tables, *end = page_tables + page_tables_elem_count; it != end; it++)
    {
        if (it->in_use == 0)
        {
            it->in_use = 1;
            memset(it->entries, 0, pags_x_tabl * sizeof(struct page_table_entry));
            u32 page_num = ((int)it - (int)page_tables) / sizeof(struct page_table);
            log_info(logger, "usando nro de pagina vacia %d", page_num);
            return page_num;
        }
    }
    int old_count = page_tables_elem_count;
    page_tables_elem_count *= 2;
    page_tables = realloc(page_tables, page_tables_elem_count * sizeof(struct page_table));
    for (page_table *it = page_tables + old_count, *end = page_tables + page_tables_elem_count; it != end; it++)
    {
        it->entries = malloc(pags_x_tabl * sizeof(struct page_table_entry));
        memset(it->entries, 0, pags_x_tabl * sizeof(struct page_table_entry));
        it->in_use = 0;
    }
    page_tables[old_count].in_use = 1;
    return old_count;
}

int main(int argc, char **argv)
{
    if (argc > 1 && strcmp(argv[1], "-test") == 0)
        return run_tests();

    t_config *conf = config_create("./cfg/memoria.config");

    char *path_logger = config_get_string_value(conf, "ARCHIVO_LOG");

    logger = log_create(path_logger, "memoria", true, LOG_LEVEL_INFO);

    int puerto = config_get_int_value(conf, "PUERTO_ESCUCHA");

    tam_mem = config_get_int_value(conf, "TAM_MEMORIA");
    tam_pag = config_get_int_value(conf, "TAM_PAGINA");
    pags_x_tabl = config_get_int_value(conf, "PAGINAS_POR_TABLA");
    marcos_x_proc = config_get_int_value(conf, "MARCOS_POR_PROCESO");

    retardo_memoria = config_get_int_value(conf, "RETARDO_MEMORIA");
    retardo_swap = config_get_int_value(conf, "RETARDO_SWAP");

    char *path_swap = config_get_string_value(conf, "PATH_SWAP");

    char *alg_reemplazo = config_get_string_value(conf, "ALGORITMO_REEMPLAZO");
    if (starts_with(alg_reemplazo, "CLOCK-M"))
    {
        alg = ALG_CLOCK_M;
    }
    else if (starts_with(alg_reemplazo, "CLOCK"))
    {
        alg = ALG_CLOCK;
    }
    else
    {
        log_error(logger, "Algoritmo de reemplazo invalido: %s", alg_reemplazo);
        log_destroy(logger);
        return -1;
    }

    log_info(logger, "Inicio proceso MEMORIA mem_size:%d page_size:%d retardo_swap:%d "
                     "retardo_mem:%d path_swap:%s alg_reemplazo:%s pags_x_tabla:%d marcos_x_proc:%d",
             tam_mem, tam_pag, retardo_swap, retardo_memoria, path_swap, alg_reemplazo, pags_x_tabl, marcos_x_proc);

    int sock_listen = open_listener_socket(puerto);

    memoria_ram = malloc(tam_mem);
    memset(memoria_ram, 0, tam_mem);
    page_tables_elem_count = 1024;
    page_tables = malloc(sizeof(page_table) * page_tables_elem_count);
    for (page_table *it = page_tables, *end = page_tables + page_tables_elem_count; it != end; it++)
    {
        it->entries = malloc(pags_x_tabl * sizeof(struct page_table_entry));
        memset(it->entries, 0, pags_x_tabl * sizeof(struct page_table_entry));
        it->in_use = 0;
    }

    while (true)
    {
        log_info(logger, "Esperando nueva conexion ...");
        int new_conn_sock = accept_new_conn(sock_listen);
        log_info(logger, "Nueva conexion socket %d", new_conn_sock);
        start_detached_thread(connection_handler_thread, (void *)new_conn_sock);
    }

    close(sock_listen);

    log_info(logger, "Fin proceso MEMORIA");
    log_destroy(logger);
    config_destroy(conf);
}

pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;

void *connection_handler_thread(void *_sock)
{
    int sock = (int)_sock;
    t_buflen network_buf = make_buf(1024);

    while (true)
    {
        log_info(logger, "Esperando nuevo mensaje en socket %d", sock);
        t_msgheader h = recv_msg(sock, &network_buf);
        log_info(logger, "Mensaje tipo %s recibido en socket %d", codigo_msg_to_string(h.codigo), sock);

        switch (h.codigo)
        {
        case HANDSHAKE_CPU_MEMORIA:
        {
            *(u32 *)(network_buf.buf) = marcos_x_proc;
            *(u32 *)(network_buf.buf + 4) = tam_pag;
            log_info(logger, "Respondiendo HANDSHAKE_CPU_MEMORIA tam_pag %d marcos_x_proc %d", tam_pag, marcos_x_proc);
            send_buffer(sock, network_buf.buf, sizeof(u32) * 2);
            break;
        }
        case MEMORIA_NEW_PROCESS:
        {
            u32 pid = read_u32(network_buf.buf);

            pthread_mutex_lock(&m);
            u32 nro_pagina_1er_nivel = get_unused_pagetable();
            page_tables[nro_pagina_1er_nivel].in_use = 2;
            //TODO: Create file
            pthread_mutex_unlock(&m);
            log_info(logger, "Recibido NEW_PROCESS pid %d respondiendo nro_pagina_1er_nivel: %d", pid, nro_pagina_1er_nivel);

            *(u32 *)(network_buf.buf) = nro_pagina_1er_nivel;
            send_buffer(sock, network_buf.buf, sizeof(u32));
            break;
        }
        case MEMORIA_PROCESS_SUSPENDED:
        {
            u32 pid = read_u32(network_buf.buf);
            u32 nro_pag1 = read_u32(network_buf.buf + 4);
            log_info(logger, "Recibido PROCESS_SUSPENDED pid %d", pid);
            // TODO: SUSPEND
            pthread_mutex_lock(&m);
            pthread_mutex_unlock(&m);
            break;
        }
        case MEMORIA_PROCESS_UNSUSPENDED:
        {
            u32 pid = read_u32(network_buf.buf);
            u32 nro_pag1 = read_u32(network_buf.buf + 4);
            log_info(logger, "Recibido PROCESS_UNSUSPENDED pid %d", pid);
            // TODO: UNSUSPEND
            pthread_mutex_lock(&m);
            pthread_mutex_unlock(&m);
            break;
        }
        case MEMORIA_END_PROCESS:
        {
            u32 pid = read_u32(network_buf.buf);
            u32 nro_pag1 = read_u32(network_buf.buf + 4);
            log_info(logger, "Recibido END_PROCESS pid %d", pid);

            pthread_mutex_lock(&m);
            page_tables[nro_pag1].in_use = 0;
            struct page_table_entry *entry = page_tables[nro_pag1].entries;
            for (struct page_table_entry *end = entry + pags_x_tabl; end != entry; entry++)
            {
                if (entry->flag_presencia != 0)
                {
                    u32 num_pag2 = entry->val;
                    page_tables[num_pag2].in_use = 0;
                }
            }
            pthread_mutex_unlock(&m);
            break;
        }
        case MEMORIA_READWRITE:
        {
            usleep(retardo_memoria * 1000);

            u32 addr = read_u32(network_buf.buf);
            u32 is_write = read_u32(network_buf.buf + 4);
            u32 val = read_u32(network_buf.buf + 8);
            log_info(logger, "Recibido READWRITE addr %d is_write %d val %d", addr, is_write, val);
            assert_and_log(addr < tam_mem, "La direccion de lectura/escritura debe ser menor al tamanio de la memoria");

            u32 *addr_ptr = ((u8 *)memoria_ram) + addr;

            pthread_mutex_lock(&m);
            if (is_write == 0)
            { // READ
                *(u32 *)(network_buf.buf) = *addr_ptr;
            }
            else
            { // WRITE
                *addr_ptr = val;
                *(u32 *)(network_buf.buf) = val;
            }
            pthread_mutex_unlock(&m);

            send_buffer(sock, network_buf.buf, sizeof(u32));
            break;
        }
        case MEMORIA_PAGEREAD:
        {
            usleep(retardo_memoria * 1000);

            u32 page_num = read_u32(network_buf.buf);
            u32 page_offset = read_u32(network_buf.buf + 4);
            log_info(logger, "Recibido PAGEREAD page_num %d offset %d", page_num, page_offset);

            pthread_mutex_lock(&m);
            assert_and_log(page_tables[page_num].in_use != 0, "La tabla de paginas de la que se lee debe estar en uso");

            struct page_table *p = &page_tables[page_num];
            struct page_table_entry *e = &(p->entries[page_offset]);
            u32 offset_present = e->flag_presencia != 0;
            log_info(logger, "presencia %d in_use %d", e->flag_presencia, p->in_use);
            if (!offset_present)
            {
                if (p->in_use == 2)
                { // Pag 1er nivel
                    e->val = get_unused_pagetable();
                    e->flag_presencia = 1;
                }
                else if (p->in_use == 1)
                { // Pag 2do nivel
                    //TODO: Asignar marco
                    e->val = 0;
                    e->flag_presencia = 1;
                }
                else
                {
                    assert(0);
                }
            }
            u32 page_num_or_frame_num = e->val;
            pthread_mutex_unlock(&m);

            *(u32 *)(network_buf.buf) = page_num_or_frame_num;
            // TODO: Invalidations
            u32 invalidation_count = 0;
            *(u32 *)(network_buf.buf + 4) = invalidation_count;
            send_buffer(sock, network_buf.buf, sizeof(u32) * 2);
            break;
        }

        default:
            log_error(logger, "Recibido mensaje desconocido (%d) %s cant_bytes %d",
                      h.codigo, codigo_msg_to_string(h.codigo), h.cant_bytes_contenido);
            log_destroy(logger);
            exit(-1);
            break;
        }
    }

    close(sock);
    free(network_buf.buf);
    return 0;
}