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
    u32 page2_page_number;
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
u32 *memoria_ram = NULL;
int path_dir_fd;
#define MAX_PAGS_x_PROC (256)
typedef struct proc_info
{
    u32 pid;
    u32 tam_proc;
    u32 nro_pag_lvl1;
    int proc_swap_file_fd;
    // 1 if suspended; 0 otherwise
    u32 is_suspended;
    // TODO: FIFO pagetable intrusive list?
    u32 pags_en_memoria[MAX_PAGS_x_PROC]; // vector lleva en cuenta las paginas en memoria
} proc_info;
#define MAX_PROCS (1024 * 10)
proc_info procs_info[MAX_PROCS] = {0};

/* Comento la funcion porque rompe

void limpiar_pags_en_memoria(int nro_de_proc){
    struct procs_info *p = malloc(sizeof(procs_info));
    *p = procs_info;
    for(int i=0;i < MAX_PAGS_x_PROC;i++){
        p[nro_de_proc]->pags_en_memoria[i]=(-1); // -1 Representa que no hay paginas
    }
    free(p);
}

*/

u32 get_unused_pagetable()
{
    for (page_table *it = page_tables, *end = page_tables + page_tables_elem_count; it != end; it++)
    {
        if (it->state == PT_STATE_UNUSED)
        {
            it->state = PT_STATE_LVL2;
            memset(it->entries, 0, pags_x_tabl * sizeof(struct page_table_entry));
            u32 page_num = ((int)it - (int)page_tables) / sizeof(struct page_table);
            log_info(logger, "usando nro de pagina vacia %d", page_num);
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

/*

int cant_pags_x_proc(int nro_de_proc){
    int k=0;
    struct proceso = procs_info[nro_de_proc];
    while(proceso.pags_en_memoria[k] != (-1) ){
        k++;
    }
    return k;
}

void lista_de_marcos_x_pagina

struct page_table_entry* reemplazar_pagina_clock(int pid){ 
    struct page_table_entry* pagina_a_reemplazar = NULL;
    // TODO: Aca capaz un semaforo mutex
    while(pagina_a_reemplazar == NULL){
        struct pagina_a_reemplazar* aux_page = list_get(  , puntero_clock); //TODO: en lista get tendria q poner una lista de pags por proceso
        if(aux_page->flag_uso == 0){
            pagina_a_reemplazar = aux_page;
        }
        else{
            aux_page -> flag_uso = 0;
        }
        int pags_x_proc = cant_pags_x_proc(pid)
        if(puntero_clock+1 ==  pags_x_proc){
            puntero_clock = 0; // Reinicio el puntero para que arranque del principio
        }
        else{
            puntero_clock++;
        }
    }
    // TODO: Aca cierro el semaforo
    return pagina_a_reemplazar;
}

*/
/*

struct page_table_entry* reemplazar_pagina_clock_m( int pid ){ 
    struct page_table_entry* pagina_a_reemplazar = NULL;
    // TODO: Aca capaz un semaforo mutex
    while(pagina_a_reemplazar == NULL){
        struct pagina_a_reemplazar* aux_page = list_get( , puntero_clock);  //TODO: en lista get tendria q poner una lista de pags por proceso
        if(aux_page->flag_uso == 0 && aux_page->modif == 0){
            pagina_a_reemplazar = aux_page;
        }
        else{
            aux_page -> flag_uso = 0;
        }
        int pags_x_proc = cant_pags_x_proc(pid);
        if(puntero_clock+1 == pags_x_proc ){
            puntero_clock = 0; // Reinicio el puntero para que arranque del principio
        }
        else{
            puntero_clock++;
        }
    }
    // TODO: Aca cierro el semaforo
    return pagina_a_reemplazar;
}


void reemplazar_pagina_por (struct page_table_entry* nueva_pagina){
    // Aca capaz un semaforo
    struct page_table_entry* pagina_a_reemplazar = NULL;
    assert_and_log(alg == ALG_CLOCK_M || alg == ALG_CLOCK, "alg reemplazo pags es clock o clock-M");
    if(alg == ALG_CLOCK_M){
        pagina_a_reemplazar = reemplazar_pagina_clock(pid);
    }
    else if(alg == ALG_CLOCK){
        pagina_a_reemplazar = reemplazar_pagina_clock_m(pid);
    }
    int numero_de_frame = pagina_a_reemplazar -> p2 -> frame_number
    // Aca vendria a ser el SWAPEO de paginas
}

*/

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

    path_dir_fd = open(path_swap, 0); // Inicializar Swap?
    if (path_dir_fd == -1)
    {
        log_error(logger, "Error abriendo directorio de swap \"%s\" strerror: %s", path_swap, strerror(errno));
        log_destroy(logger);
        return -1;
    }

    log_info(logger, "Inicio proceso MEMORIA mem_size:%d page_size:%d retardo_swap:%d "
                     "retardo_mem:%d path_swap:%s alg_reemplazo:%s pags_x_tabla:%d marcos_x_proc:%d",
             tam_mem, tam_pag, retardo_swap, retardo_memoria, path_swap, alg_reemplazo, pags_x_tabl, marcos_x_proc);

    int sock_listen = open_listener_socket(puerto);

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
            u32 tam_proc = read_u32(network_buf.buf + 4);

            pthread_mutex_lock(&m);
            u32 nro_pagina_1er_nivel = get_unused_pagetable();
            page_tables[nro_pagina_1er_nivel].state = PT_STATE_LVL1;
            log_info(logger, "Recibido NEW_PROCESS pid %d tam_proc %d respondiendo nro_pagina_1er_nivel:%d "
                             "y creando archivo de swap",
                     pid, tam_proc, nro_pagina_1er_nivel);

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
            proc_info->nro_pag_lvl1 = nro_pagina_1er_nivel;
            proc_info->is_suspended = 0;
            proc_info->proc_swap_file_fd = swap_file_fd;
            limpiar_pags_en_memoria(pid); // nuevo proceso no tiene pags en memoria
            pthread_mutex_unlock(&m);

            *(u32 *)(network_buf.buf) = nro_pagina_1er_nivel;
            send_buffer(sock, network_buf.buf, sizeof(u32));
            break;
        }
        case MEMORIA_PROCESS_SUSPENDED:
        {
            u32 pid = read_u32(network_buf.buf);
            u32 nro_pag1 = read_u32(network_buf.buf + 4);
            log_info(logger, "Recibido PROCESS_SUSPENDED pid %d", pid);
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
                            log_info(logger, "Escribiendo por SUSPEND en swap nro de pagina lvl2 %d entrada %d marco %d pid %d",
                                     num_pag2, (int)(((int)end2 - (int)entry_lvl2) / sizeof(*end2)), (int)marco, pid);
                            limpiar_pags_en_memoria(pid); // proceso suspendido no tiene pags en memoria
                            assert_and_log(marco < tam_mem, "Se intento escribir a disco una direccion de marco mayor al tamanio de la memoria");
                            int offset =
                                pwrite(swap_file_fd, memoria_ram + marco, tam_pag, nro_pag * tam_pag);
                            entry_lvl2->flag_presencia = 0;
                        }
                        nro_pag += 1;
                    }
                }
                else
                {
                    nro_pag += pags_x_tabl;
                }
            }
            pthread_mutex_unlock(&m);
            break;
        }
        case MEMORIA_PROCESS_UNSUSPENDED:
        {
            u32 pid = read_u32(network_buf.buf);
            u32 nro_pag1 = read_u32(network_buf.buf + 4);
            log_info(logger, "Recibido PROCESS_UNSUSPENDED pid %d", pid);

            pthread_mutex_lock(&m);
            procs_info[pid].is_suspended = 0;
            pthread_mutex_unlock(&m);
            break;
        }
        case MEMORIA_END_PROCESS:
        {
            u32 pid = read_u32(network_buf.buf);
            u32 nro_pag1 = read_u32(network_buf.buf + 4);
            log_info(logger, "Recibido END_PROCESS pid %d", pid);

            pthread_mutex_lock(&m);
            int swap_file_fd = procs_info[pid].proc_swap_file_fd;
            PID_TO_STACK_STR_PATH(pid, stackbuf);
            assert_and_log(close(swap_file_fd) == 0, "close swap file fd");
            assert_and_log(unlinkat(path_dir_fd, stackbuf, 0) == 0, "remove swap file");

            page_tables[nro_pag1].state = PT_STATE_UNUSED;
            struct page_table_entry *entry = page_tables[nro_pag1].entries;
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
            u32 page_lvl1_num = procs_info[pid].nro_pag_lvl1;
            u32 frame_addr = (addr / tam_pag) * tam_pag;
            log_info(logger, "Recibido READWRITE addr %d is_write %d val %d", addr, is_write, val);
            assert_and_log(addr < tam_mem, "La direccion de lectura/escritura debe ser menor al tamanio de la memoria");

            u32 *addr_ptr = ((u8 *)memoria_ram) + addr;

            pthread_mutex_lock(&m);
            struct page_table_entry *entry_lvl1 = page_tables[page_lvl1_num].entries;
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
                                     addr, page_lvl1_num, pid,
                                     ((int)entry_lvl1 - (int)page_tables[page_lvl1_num].entries) / sizeof(struct page_table_entry),
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

            u32 page_num = read_u32(network_buf.buf);
            u32 page_offset = read_u32(network_buf.buf + 4);
            log_info(logger, "Recibido PAGEREAD page_num %d offset %d", page_num, page_offset);

            pthread_mutex_lock(&m);
            assert_and_log(page_tables[page_num].state != PT_STATE_UNUSED,
                           "La tabla de paginas de la que se lee debe estar en uso");

            struct page_table *p = &page_tables[page_num];
            struct page_table_entry *e = &(p->entries[page_offset]);
            u32 offset_present = e->flag_presencia != 0;
            log_info(logger, "presencia %d state %d", e->flag_presencia, p->state);
            if (!offset_present)
            {
                // PAGE FAULT
                if (p->state == PT_STATE_LVL1)
                { // Pag 1er nivel, asignar pagina de 2do nivel
                    e->val = get_unused_pagetable();
                    e->flag_presencia = 1;
                }
                else if (p->state == PT_STATE_LVL2)
                { // Pag 2do nivel, asignar marco
                    // TODO: Asignar marco, invalidar de ser necesario
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
            // TODO: devolver las paginas invalidadas de cuando se asigno el marco
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
