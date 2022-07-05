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

typedef struct page1_table_entry
{
    u32 page2_page_idxptr;
} page1_table_entry;
typedef struct page_table_entry
{
    // Presente si != 0
    // != 0 si la pagina esta presente en memoria en el frame indicado por
    //      el valor. Caso contrario el valor de la entrada se debe ignorar
    u8 flag_presencia;
    // != 0 si se leyo o escribio
    u8 flag_uso;
    // != 0 si se escribio
    u8 flag_modif;
    // Capaz cada pagina podria tener el PID de su proceso
    union {
        struct page1_table_entry p1;
        struct page2_table_entry p2;
        u32 val;
    };
} page_table_entry;

enum page_table_state
{
    PT_STATE_UNUSED = 0,
    PT_STATE_LVL2,
    PT_STATE_LVL1,
};
typedef struct page_table
{
    enum page_table_state state;
    struct page_table_entry *entries;
} page_table;

page_table *page_tables = NULL;
u32 page_tables_elem_count = 0;
u8 *memoria_ram = NULL;
int path_dir_fd;
u32 cant_marcos = 0;
int *estado_marcos = NULL;
enum estado_marco
{
    MARCO_LIBRE = 0,
    MARCO_EN_USO,
};

#define MAX_PAGS_X_PROC (256)
typedef struct proc_info
{
    u32 pid;
    u32 tam_proc;
    u32 pag_lvl1_idxptr;
    int proc_swap_file_fd;
    // 1 if suspended; 0 otherwise
    u32 is_suspended;
    // Cantidad de elementos en pags_en_memoria
    u32 num_pags_en_memoria;
    // indice del array pags_en_memoria donde quedo la ultima ejecucion
    // del algoritmo de reemplazo
    u32 idx_last_clock_ptr;
    // Array con nros de pagina ordenados como FIFO para alg clock
    u32 pags_en_memoria[MAX_PAGS_X_PROC];
} proc_info;
#define MAX_PROCS (1024 * 10)
proc_info procs_info[MAX_PROCS] = {0};

void logear_estado_pags(int idx_ptr)
{

    struct page_table_entry *entry = page_tables[idx_ptr].entries;
    int nro_pag = 0;
    for (struct page_table_entry *end = entry + pags_x_tabl; end != entry; entry++)
    {
        if (entry->flag_presencia != 0)
        {
            u32 num_pag2 = entry->val;
            struct page_table_entry *entry_lvl2 = page_tables[num_pag2].entries;
            for (struct page_table_entry *end = entry_lvl2 + pags_x_tabl; end != entry_lvl2; entry_lvl2++)
            {
                if (entry_lvl2->flag_presencia != 0)
                {
                    log_info_colored(ANSI_COLOR_CYAN, "P: %d B: %d M: %d", nro_pag, entry_lvl2->flag_uso, entry_lvl2->flag_modif);
                }
                nro_pag += 1;
            }
        }
        else
        {
            nro_pag += pags_x_tabl;
        }
    }
}

u32 get_unused_pagetable()
{
    for (page_table *it = page_tables, *end = page_tables + page_tables_elem_count; it != end; it++)
    {
        if (it->state == PT_STATE_UNUSED)
        {
            it->state = PT_STATE_LVL2;
            memset(it->entries, 0, pags_x_tabl * sizeof(struct page_table_entry));
            u32 page_num = ((int)it - (int)page_tables) / sizeof(struct page_table);
            log_info_colored(ANSI_COLOR_CYAN, "usando nro de pagina vacia %d", page_num);
            return page_num;
        }
    }
    // No hay tablas de paginas libres, reallocar el array incrementado x2 el tamanio
    int old_count = page_tables_elem_count;
    page_tables_elem_count *= 2;
    page_tables = realloc(page_tables, page_tables_elem_count * sizeof(struct page_table));
    for (page_table *it = page_tables + old_count, *end = page_tables + page_tables_elem_count; it != end; it++)
    {
        it->entries = malloc(pags_x_tabl * sizeof(struct page_table_entry));
        memset(it->entries, 0, pags_x_tabl * sizeof(struct page_table_entry));
        it->state = 0;
    }
    page_tables[old_count].state = PT_STATE_LVL2;
    return old_count;
}

void add_pag_en_memoria_a_proc(u32 logical_addr, u32 pid)
{
    assert_and_log(procs_info[pid].num_pags_en_memoria < MAX_PAGS_X_PROC,
                   "Se supero el nro max de pags x proc que soportamos. Es un bug o hay que incrementar el tamanio del array");

    // Si habia 1, num=1 y nuevo indice =1 (Empiezan en 0)
    int nuevo_idx = procs_info[pid].num_pags_en_memoria;
    procs_info[pid].pags_en_memoria[nuevo_idx] = logical_addr;
    procs_info[pid].num_pags_en_memoria++;
}
void remove_pag_en_memoria_de_proc(int idx, u32 pid)
{
    assert_and_log(procs_info[pid].num_pags_en_memoria > 0,
                   "No se puede quitar una pagina en memoria de un proc si no tiene ninguna");

    int cant_pags_a_la_derecha = procs_info[pid].num_pags_en_memoria - idx - 1;
    if (cant_pags_a_la_derecha > 0)
    {
        // Ej: [A, B, C, D] y quitamos idx=1 osea B. cant = 4
        // a la derecha: 4-1-1 = 2 (C y D)
        // Entonces copiamos C, D encima de B, C y queda [A, C, D, D]
        // Y finalmente reducimos num_pags_en_memoria a 3 y queda [A, C, D]
        u32 *dest = procs_info[pid].pags_en_memoria + idx;
        u32 *src = dest + 1;
        memmove(dest, src, cant_pags_a_la_derecha * sizeof(u32));
    }
    procs_info[pid].num_pags_en_memoria--;
}

void swapear_pagina_a_disco(struct page_table_entry *pagina_a_reemplazar, u32 direc_logica, u32 pid)
{
    assert_and_log(pagina_a_reemplazar->flag_presencia != 0,
                   "No se puede swaper a disco una pagina que no este presente");
    int swap_file_fd = procs_info[pid].proc_swap_file_fd;
    u32 marco = pagina_a_reemplazar->p2.frame_number;
    log_info_colored(ANSI_COLOR_CYAN, "Escribiendo pag:%d(addr:%d) en swap marco_nro:%d(addr:%d)",
                     direc_logica / tam_pag, direc_logica, marco / tam_pag, marco);
    pwrite(swap_file_fd, memoria_ram + marco, tam_pag, direc_logica);
    pagina_a_reemplazar->flag_presencia = 0;
    estado_marcos[marco / tam_pag] = MARCO_LIBRE;
}

u32 reemplazar_pagina_clock(int pid)
{
    struct page_table_entry *pagina_a_reemplazar = NULL;
    int idx_current_iteration = procs_info[pid].idx_last_clock_ptr;
    logear_estado_pags(procs_info[pid].pag_lvl1_idxptr);
    // Esta variable indica cuantas vueltas ya se dieron al array pags_en_memoria
    u8 iteracion = 0;

    while (true)
    {
        u32 indice_pag = procs_info[pid].pags_en_memoria[idx_current_iteration] / tam_pag;
        u32 indice_pag_lvl1 = indice_pag / pags_x_tabl;
        u32 indice_pag_lvl2 = indice_pag % pags_x_tabl;
        u32 index_pag_lvl2 = page_tables[procs_info[pid].pag_lvl1_idxptr].entries[indice_pag_lvl1].val;
        int pag_victima;
        int iteracion_clock_m_paso1 = iteracion % 2 == 0;

        struct page_table_entry *entrada = &(page_tables[index_pag_lvl2].entries[indice_pag_lvl2]);
        int bit_de_uso = entrada->flag_uso;
        int flag_de_modif = entrada->flag_modif;

        assert_and_log(page_tables[procs_info[pid].pag_lvl1_idxptr].entries[indice_pag_lvl1].flag_presencia != 0,
                       "Una tabla de paginas en proc.pags_en_memoria siempre debe estar presente");
        assert_and_log(entrada->flag_presencia != 0,
                       "Una tabla de paginas en proc.pags_en_memoria siempre debe estar presente");

        //log_info(logger, "idx: %d U %d M %d", idx_current_iteration, bit_de_uso, flag_de_modif);
        if (alg == ALG_CLOCK_M)
        {
            if (iteracion_clock_m_paso1)
            {
                pag_victima = bit_de_uso == 0 && flag_de_modif == 0;
            }
            else
            {
                pag_victima = bit_de_uso == 0 && flag_de_modif == 1;
            }
        }
        else
        {
            pag_victima = bit_de_uso == 0;
        }

        if (pag_victima)
        {
            pagina_a_reemplazar = entrada;
            break;
        }

        if (alg == ALG_CLOCK || !iteracion_clock_m_paso1)
        {
            // CLOCK normal siempre setea, clock_m solo en paso2
            entrada->flag_uso = 0;
        }

        idx_current_iteration = (idx_current_iteration + 1) % procs_info[pid].num_pags_en_memoria;

        if (idx_current_iteration == procs_info[pid].idx_last_clock_ptr)
        {
            iteracion += 1;
        }
        assert_and_log(iteracion < 4, "CLOCK_M no deberia hacer mas de 4 iteraciones");
    }

    assert_and_log(pagina_a_reemplazar != NULL, "siempre se debe poder encontrar una pagina a reemplazar");

    log_info(logger, "Swapeada pg idx en array %d a dico\n"
                     "========================================================================\n"
                     "========================================================================",
             idx_current_iteration);
    swapear_pagina_a_disco(pagina_a_reemplazar, procs_info[pid].pags_en_memoria[idx_current_iteration], pid);

    remove_pag_en_memoria_de_proc(idx_current_iteration, pid);
    procs_info[pid].idx_last_clock_ptr = idx_current_iteration % procs_info[pid].num_pags_en_memoria;
    //log_info(logger, "idx_last_clock_ptr: %d", procs_info[pid].idx_last_clock_ptr);
    logear_estado_pags(procs_info[pid].pag_lvl1_idxptr);
    return pagina_a_reemplazar->p2.frame_number;
}

int main(int argc, char **argv)
{
    if (argc > 1 && strcmp(argv[1], "-test") == 0)
        return run_tests();

    t_config *conf = config_create("./cfg/memoria.config");
    if (!conf)
    {
        errno = 0;
        conf = config_create("./memoria/cfg/memoria.config");
        if (!conf)
        {
            puts("No se encontro el config ./cfg/memoria.config o ./memoria/cfg/memoria.config");
            return -1;
        }
    }

    char *path_logger = config_get_string_value(conf, "ARCHIVO_LOG");

    logger = log_create(path_logger, "memoria", true, LOG_LEVEL_INFO);

    int puerto = config_get_int_value(conf, "PUERTO_ESCUCHA");

    tam_mem = config_get_int_value(conf, "TAM_MEMORIA");
    tam_pag = config_get_int_value(conf, "TAM_PAGINA");
    pags_x_tabl = config_get_int_value(conf, "ENTRADAS_POR_TABLA");
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

    path_dir_fd = open(path_swap, 0);
    if (path_dir_fd == -1)
    {
        errno = 0;
        int created = mkdir(path_swap, 0777);
        if (created != 0)
        {
            log_error(logger, "Error creando directorio de swap \"%s\" strerror: %s", path_swap, strerror(errno));
            log_destroy(logger);
            return -1;
        }
        path_dir_fd = open(path_swap, 0);
        if (path_dir_fd == -1)
        {
            log_error(logger, "Error abriendo directorio de swap \"%s\" strerror: %s", path_swap, strerror(errno));
            log_destroy(logger);
            return -1;
        }
    }

    log_info(logger, "Inicio proceso MEMORIA mem_size:%d page_size:%d retardo_swap:%d "
                     "retardo_mem:%d path_swap:%s alg_reemplazo:%s pags_x_tabla:%d marcos_x_proc:%d",
             tam_mem, tam_pag, retardo_swap, retardo_memoria, path_swap, alg_reemplazo, pags_x_tabl, marcos_x_proc);

    int sock_listen = open_listener_socket(puerto);

    cant_marcos = tam_mem / tam_pag;
    estado_marcos = malloc(cant_marcos * sizeof(int));
    for (int i = 0; i < cant_marcos; i++)
    {
        estado_marcos[i] = MARCO_LIBRE;
    }
    memoria_ram = malloc(tam_mem);
    memset(memoria_ram, 0, tam_mem);
    page_tables_elem_count = 16;
    page_tables = malloc(sizeof(page_table) * page_tables_elem_count);
    for (page_table *it = page_tables, *end = page_tables + page_tables_elem_count; it != end; it++)
    {
        it->entries = malloc(pags_x_tabl * sizeof(struct page_table_entry));
        memset(it->entries, 0, pags_x_tabl * sizeof(struct page_table_entry));
        it->state = PT_STATE_UNUSED;
    }

    while (true)
    {
        log_info(logger, "Esperando nueva conexion ...");
        int new_conn_sock = accept_new_conn(sock_listen);
        log_info(logger, "Nueva conexion socket %d", new_conn_sock);
        start_detached_thread(connection_handler_thread, (void *)new_conn_sock);
    }

    close(sock_listen);
    close(path_dir_fd);

    log_info(logger, "Fin proceso MEMORIA");
    log_destroy(logger);
    config_destroy(conf);
}

pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;

#define PID_TO_STACK_STR_PATH(pid, bufname)                                                                                             \
    int __pid = (pid);                                                                                                                  \
    char bufname[1024] = {0};                                                                                                           \
    int snprintf_ret = snprintf(bufname, 1024, "./%d.swap", __pid);                                                                     \
    if (snprintf_ret <= 0 || snprintf_ret >= 1024)                                                                                      \
    {                                                                                                                                   \
        log_error(logger, "Error snprintf creando archivo de swap pid %d dir_fd %d strerror: %s", __pid, path_dir_fd, strerror(errno)); \
        log_destroy(logger);                                                                                                            \
        exit(-1);                                                                                                                       \
    }

void *connection_handler_thread(void *_sock)
{
    int sock = (int)_sock;
    t_buflen network_buf = make_buf(1024);

    while (true)
    {
        log_info(logger, "Esperando nuevo mensaje en socket %d", sock);
        t_msgheader h = recv_msg(sock, &network_buf);
        log_info_colored(ANSI_COLOR_YELLOW, "Mensaje tipo %s recibido en socket %d", codigo_msg_to_string(h.codigo), sock);

        switch (h.codigo)
        {
        case HANDSHAKE_CPU_MEMORIA:
        {
            *(u32 *)(network_buf.buf) = pags_x_tabl;
            *(u32 *)(network_buf.buf + 4) = tam_pag;
            log_info_colored(ANSI_COLOR_YELLOW, "Respondiendo HANDSHAKE_CPU_MEMORIA tam_pag %d marcos_x_proc %d", tam_pag, marcos_x_proc);
            send_buffer(sock, network_buf.buf, sizeof(u32) * 2);
            break;
        }
        case MEMORIA_NEW_PROCESS:
        {
            u32 pid = read_u32(network_buf.buf);
            u32 tam_proc = read_u32(network_buf.buf + 4);

            pthread_mutex_lock(&m);
            u32 pagina_1er_nivel_idxptr = get_unused_pagetable();
            page_tables[pagina_1er_nivel_idxptr].state = PT_STATE_LVL1;
            log_info_colored(ANSI_COLOR_YELLOW, "Recibido NEW_PROCESS pid %d tam_proc %d respondiendo pagina_1er_nivel_idxptr:%d "
                                                "y creando archivo de swap",
                             pid, tam_proc, pagina_1er_nivel_idxptr);

            // Create file
            assert_and_log(pid < MAX_PROCS, "pid menor a MAX_PROCS");
            PID_TO_STACK_STR_PATH(pid, stackbuf);
            int swap_file_fd = openat(path_dir_fd, stackbuf, O_CREAT | O_RDWR, S_IRWXU | S_IRWXG | S_IRWXO);
            if (swap_file_fd == -1)
            {
                log_error(logger, "Error openat creando archivo de swap pid %d dir_fd %d strerror: %s", pid, path_dir_fd, strerror(errno));
                log_destroy(logger);
                exit(-1);
            }
            assert_and_log(ftruncate(swap_file_fd, tam_proc) == 0, "ftruncate de fd abierto no falla");
            proc_info *proc_info = &procs_info[pid];
            proc_info->pid = pid;
            proc_info->tam_proc = tam_proc;
            proc_info->pag_lvl1_idxptr = pagina_1er_nivel_idxptr;
            proc_info->is_suspended = 0;
            proc_info->proc_swap_file_fd = swap_file_fd;
            proc_info->num_pags_en_memoria = 0;
            proc_info->idx_last_clock_ptr = 0;
            memset(proc_info->pags_en_memoria, 0, sizeof(u32) * MAX_PAGS_X_PROC);
            pthread_mutex_unlock(&m);

            *(u32 *)(network_buf.buf) = pagina_1er_nivel_idxptr;
            send_buffer(sock, network_buf.buf, sizeof(u32));
            break;
        }
        case MEMORIA_PROCESS_SUSPENDED:
        {
            u32 pid = read_u32(network_buf.buf);
            u32 nro_pag1 = read_u32(network_buf.buf + 4);
            log_info_colored(ANSI_COLOR_YELLOW, "Recibido PROCESS_SUSPENDED pid %d", pid);
            pthread_mutex_lock(&m);
            procs_info[pid].is_suspended = 1;
            int swap_file_fd = procs_info[pid].proc_swap_file_fd;
            struct page_table_entry *entry_lvl1 = page_tables[nro_pag1].entries;
            int nro_pag = 0;
            for (struct page_table_entry *end = entry_lvl1 + pags_x_tabl; end != entry_lvl1; entry_lvl1++)
            {
                if (entry_lvl1->flag_presencia != 0)
                {
                    u32 num_pag2 = entry_lvl1->val;
                    struct page_table_entry *entry_lvl2 = page_tables[num_pag2].entries;
                    for (struct page_table_entry *end2 = entry_lvl2 + pags_x_tabl; end2 != entry_lvl2; entry_lvl2++)
                    {
                        if (entry_lvl2->flag_presencia != 0)
                        {
                            u32 marco = entry_lvl2->val;
                            if (entry_lvl2->flag_modif != 0)
                            {
                                log_info_colored(ANSI_COLOR_CYAN, "Escribiendo por SUSPEND en swap nro_pag:%d(addr %d) marco:%d(addr %d) pid %d",
                                                 nro_pag, nro_pag * tam_pag, (int)marco / tam_pag, (int)marco, pid);
                                assert_and_log(marco < tam_mem, "Se intento escribir a disco una direccion de marco mayor al tamanio de la memoria");
                                int offset =
                                    pwrite(swap_file_fd, memoria_ram + marco, tam_pag, nro_pag * tam_pag);
                            }
                            log_info(logger, "Swapeada nro_pag %d a dico\n"
                                             "========================================================================\n"
                                             "========================================================================",
                                     nro_pag);
                            entry_lvl2->flag_presencia = 0;
                            estado_marcos[marco / tam_pag] = MARCO_LIBRE;
                        }
                        nro_pag += 1;
                    }
                }
                else
                {
                    nro_pag += pags_x_tabl;
                }
            }
            procs_info[pid].num_pags_en_memoria = 0;
            procs_info[pid].idx_last_clock_ptr = 0;
            memset(procs_info[pid].pags_en_memoria, 0, sizeof(u32) * MAX_PAGS_X_PROC);
            pthread_mutex_unlock(&m);
            break;
        }
        case MEMORIA_PROCESS_UNSUSPENDED:
        {
            u32 pid = read_u32(network_buf.buf);
            u32 nro_pag1 = read_u32(network_buf.buf + 4);
            log_info_colored(ANSI_COLOR_YELLOW, "Recibido PROCESS_UNSUSPENDED pid %d", pid);

            pthread_mutex_lock(&m);
            procs_info[pid].is_suspended = 0;
            pthread_mutex_unlock(&m);
            break;
        }
        case MEMORIA_END_PROCESS:
        {
            u32 pid = read_u32(network_buf.buf);
            u32 idx_ptr = read_u32(network_buf.buf + 4);
            log_info_colored(ANSI_COLOR_YELLOW, "Recibido END_PROCESS pid %d", pid);

            pthread_mutex_lock(&m);
            int swap_file_fd = procs_info[pid].proc_swap_file_fd;
            PID_TO_STACK_STR_PATH(pid, stackbuf);
            assert_and_log(close(swap_file_fd) == 0, "close swap file fd");
            assert_and_log(unlinkat(path_dir_fd, stackbuf, 0) == 0, "remove swap file");

            page_tables[idx_ptr].state = PT_STATE_UNUSED;
            struct page_table_entry *entry = page_tables[idx_ptr].entries;
            logear_estado_pags(idx_ptr);
            for (struct page_table_entry *end = entry + pags_x_tabl; end != entry; entry++)
            {
                if (entry->flag_presencia != 0)
                {
                    u32 num_pag2 = entry->val;
                    page_tables[num_pag2].state = PT_STATE_UNUSED;
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
            u32 pid = read_u32(network_buf.buf + 12);
            u32 page_lvl1_idxptr = procs_info[pid].pag_lvl1_idxptr;
            u32 frame_addr = (addr / tam_pag) * tam_pag;
            log_info_colored(ANSI_COLOR_YELLOW, "Recibido READWRITE phys_addr %d is_write %d val %d", addr, is_write, val);
            assert_and_log(addr < tam_mem, "La direccion de lectura/escritura debe ser menor al tamanio de la memoria");

            u32 *addr_ptr = (u32 *)(memoria_ram + addr);

            pthread_mutex_lock(&m);
            struct page_table_entry *entry_lvl1 = page_tables[page_lvl1_idxptr].entries;
            struct page_table_entry *addr_pagetable_entry = NULL;
            for (struct page_table_entry *end = entry_lvl1 + pags_x_tabl; end != entry_lvl1; entry_lvl1++)
            {
                if (entry_lvl1->flag_presencia != 0)
                {
                    u32 num_pag2 = entry_lvl1->val;
                    struct page_table_entry *entry_lvl2 = page_tables[num_pag2].entries;
                    for (struct page_table_entry *end2 = entry_lvl2 + pags_x_tabl; end2 != entry_lvl2; entry_lvl2++)
                    {
                        if (entry_lvl2->flag_presencia != 0 && entry_lvl2->val == frame_addr)
                        {
                            addr_pagetable_entry = entry_lvl2;
                            log_info(logger, "Encontrado marco de addr_phys %d en tabla_lvl1 %d de pid %d, en entrada tabla_lvl1 %d num_tabla_lvl2 %d offset_lvl2 %d addr_marco %d",
                                     addr, page_lvl1_idxptr, pid,
                                     ((int)entry_lvl1 - (int)page_tables[page_lvl1_idxptr].entries) / sizeof(struct page_table_entry),
                                     num_pag2,
                                     ((int)entry_lvl2 - (int)page_tables[num_pag2].entries) / sizeof(struct page_table_entry), frame_addr);
                        }
                    }
                }
            }

            assert_and_log(addr_pagetable_entry != NULL, "No se encontro el marco de la direccion en la tabla de paginas del pid");
            if (is_write == 0)
            { // READ
                *(u32 *)(network_buf.buf) = *addr_ptr;

                addr_pagetable_entry->flag_uso = 1;
            }
            else
            { // WRITE
                *addr_ptr = val;
                *(u32 *)(network_buf.buf) = val;

                addr_pagetable_entry->flag_uso = 1;
                addr_pagetable_entry->flag_modif = 1;
            }
            pthread_mutex_unlock(&m);

            send_buffer(sock, network_buf.buf, sizeof(u32));
            break;
        }
        case MEMORIA_PAGEREAD:
        {
            usleep(retardo_memoria * 1000);

            u32 pagetable_idxptr = read_u32(network_buf.buf);
            u32 page_offset = read_u32(network_buf.buf + 4);
            u32 logical_addr = read_u32(network_buf.buf + 8);
            u32 pid = read_u32(network_buf.buf + 12);
            log_info_colored(ANSI_COLOR_YELLOW, "Recibido PAGEREAD pagetable_idxptr:%d offset:%d log_addr:%d pid:%d",
                             pagetable_idxptr, page_offset, logical_addr, pid);

            pthread_mutex_lock(&m);
            assert_and_log(page_tables[pagetable_idxptr].state != PT_STATE_UNUSED,
                           "La tabla de paginas de la que se lee debe estar en uso");

            struct page_table *t = &page_tables[pagetable_idxptr];

            // Para asserts
            u32 indice_pag_from_logical_addr = logical_addr / tam_pag;
            u32 indice_pag_lvl1_from_logical_addr = indice_pag_from_logical_addr / pags_x_tabl;
            u32 indice_pag_lvl2_from_logical_addr = indice_pag_from_logical_addr % pags_x_tabl;
            log_info_colored(ANSI_COLOR_YELLOW, "Recibido PAGEREAD indice_pag_from_logical_addr:%d indice_pag_lvl1_from_logical_addr:%d indice_pag_lvl2_from_logical_addr:%d",
                             indice_pag_from_logical_addr, indice_pag_lvl1_from_logical_addr, indice_pag_lvl2_from_logical_addr);
            if (t->state == PT_STATE_LVL1)
            {
                assert_and_log(pagetable_idxptr == procs_info[pid].pag_lvl1_idxptr,
                               "pid.tabla_lvl1 == tabla_lvl1 recibida PAGEREAD");
                assert_and_log(page_offset == indice_pag_lvl1_from_logical_addr,
                               "page_offset == indice_pag_lvl1_from_logical_addr");
            }
            else if (t->state == PT_STATE_LVL2)
            {
                assert_and_log(page_offset == indice_pag_lvl2_from_logical_addr,
                               "page_offset == indice_pag_lvl2_from_logical_addr");
            }

            struct page_table_entry *e = &(t->entries[page_offset]);
            u32 offset_present = e->flag_presencia != 0;
            log_info_colored(ANSI_COLOR_CYAN, "antes: presencia %d state %d", e->flag_presencia, t->state);
            u32 invalidation_count = 0;
            u32 invalidated_frames[1];
            if (!offset_present)
            {
                // PAGE FAULT
                e->flag_modif = 0;
                e->flag_uso = 0;
                if (t->state == PT_STATE_LVL1)
                { // Pag 1er nivel, asignar pagina de 2do nivel
                    e->val = get_unused_pagetable();
                    e->flag_presencia = 1;

                    // No es necesario agregar a proc.pags_en_memoria ya que es entrada de una tabla de 1er nivel
                    // Osea una pagina de 2do nivel, que nunca swapeamos
                }
                else if (t->state == PT_STATE_LVL2)
                { // Pag 2do nivel, asignar marco

                    assert_and_log(page_offset == indice_pag_lvl2_from_logical_addr,
                                   "page_offset == indice_pag_lvl2_from_logical_addr");
                    if (procs_info[pid].num_pags_en_memoria < marcos_x_proc)
                    { // Hay algun frame libre?
                        int i = 0;
                        for (; i < cant_marcos; i++)
                        {
                            if (estado_marcos[i] == MARCO_LIBRE)
                            {
                                break;
                            }
                        }

                        assert_and_log(i < cant_marcos, "Fallo, se intento asignar un marco cuando estaban todos en uso");

                        e->val = i * tam_pag;
                        e->flag_presencia = 1;
                        add_pag_en_memoria_a_proc(logical_addr, pid);
                        estado_marcos[i] = MARCO_EN_USO;
                        logear_estado_pags(procs_info[pid].pag_lvl1_idxptr);
                    }
                    else
                    {
                        invalidation_count = 1;
                        u32 marco_nuevo_libre = reemplazar_pagina_clock(pid);
                        invalidated_frames[0] = marco_nuevo_libre;

                        e->val = marco_nuevo_libre;
                        e->flag_presencia = 1;
                        add_pag_en_memoria_a_proc(logical_addr, pid);
                        estado_marcos[marco_nuevo_libre / tam_pag] = MARCO_EN_USO;

                        int swap_file_fd = procs_info[pid].proc_swap_file_fd;
                        log_info(logger, "Leyendo pag:%d(addr:%d) de swap marco_nro:%d(addr:%d)",
                                 logical_addr / tam_pag, logical_addr, marco_nuevo_libre / tam_pag, marco_nuevo_libre);
                        pread(swap_file_fd, memoria_ram + marco_nuevo_libre, tam_pag, logical_addr);
                    }
                }
                else
                {
                    assert_and_log(0, "una pagina solo puede ser de lvl1 o lvl2");
                }
            }
            log_info_colored(ANSI_COLOR_CYAN, "dsps: presencia %d state %d", e->flag_presencia, t->state);
            u32 page_num_or_frame_num = e->val;
            pthread_mutex_unlock(&m);

            *(u32 *)(network_buf.buf) = page_num_or_frame_num;
            *(u32 *)(network_buf.buf + 4) = invalidation_count;
            if (invalidation_count > 0)
            {
                assert(invalidation_count == 1);
                *(u32 *)(network_buf.buf + 8) = invalidated_frames[0];
            }
            send_buffer(sock, network_buf.buf, sizeof(u32) * (2 + invalidation_count));
            break;
        }

        default:
            log_info_colored(ANSI_COLOR_YELLOW, "Recibido mensaje desconocido (%d) %s cant_bytes %d",
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
