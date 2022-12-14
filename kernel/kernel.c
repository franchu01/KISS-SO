#include "kernel.h"

t_log *logger;

void *dispatcher_thread(void *_p);
void *io_device_thread(void *_params);

int estimacion_inicial;
int grado_multiprogramacion;
volatile int multiprogramacion;
int tiempo_maximo_bloqueado;
double alfa;

enum alg_planif
{
    ALG_FIFO,
    ALG_SRT
};
enum alg_planif alg_planif;

volatile int cpu_dispatch_sock;
volatile int cpu_int_sock;
volatile int mem_sock;

enum estado_proceso
{
    PROC_STATE_INVALID,
    // Usado por los nodos sentinelas de las listas
    PROC_STATE_INVALID_IS_LIST,
    PROC_STATE_NEW,
    PROC_STATE_RDY,
    PROC_STATE_EXEC,
    PROC_STATE_EXIT,
    PROC_STATE_BLOCKED,
    PROC_STATE_SUSPENDED_BLOCKED,
    PROC_STATE_SUSPENDED_RDY
};
char *estado_proces_a_str(enum estado_proceso s)
{
    static char *LISTA_STRINGS_ESTADOS[] = {
        "INVALID",
        "INVALID_IS_LIST",
        "NEW",
        "RDY",
        "EXEC",
        "EXIT",
        "BLOCKED",
        "SUSPENDED_BLOCKED",
        "SUSPENDED_RDY",
    };
    const int cant_entradas = sizeof(LISTA_STRINGS_ESTADOS) / sizeof(*LISTA_STRINGS_ESTADOS);
    return s < cant_entradas ? LISTA_STRINGS_ESTADOS[(int)s] : "ESTADO PROCESO DESCONOCIDO!";
}
typedef struct pcb
{
    u32 pid;
    enum estado_proceso state;
    // Acumulador de la rafaga actual, para cuando se interrumpe/desaloja un proceso
    u32 rafaga_actual;
    u32 estimacion_rafaga;
    u32 pc;
    u32 tamanio;
    u32 inst_count;
    inst_t *insts;
    u32 pag_1er_niv;

    // Metadata para logs
    u32 timestamp_recibido;
    u32 timestamp_ingreso_sistema;
    u32 contador_suspensiones;

    // Usado solo para mandar este dato al hilo de IO
    u32 block_ms;
    // timestamp de cuando se paso a bloqueado
    i64 timestamp_inicio_block;

    // socket para avisar a la consola cuando finaliza el proceso
    int consola_sock;

    // Punteros para cuando el pcb esta en una lista
    struct pcb *next;
    struct pcb *prev;
} pcb_t;
void set_proc_state(pcb_t *p, enum estado_proceso s);

pthread_mutex_t scheduling_mutex = PTHREAD_MUTEX_INITIALIZER;
// Para no tener espera activa en el hilo dispatcher, usamos un semaforo
sem_t dispatcher_sema;
// Para no tener espera activa en el hilo que simula un dispositivo de IO
sem_t io_device_sema;
// Son pcb's sentinelas para listas. La lista es circular, el fin es cuando ->next == &lista_X
// ->next es el 1er elem, ->prev es el ultimo
//
// Diagrama de ejemplo:
//
//                 next               next
//   | sentinela | ----> |primer_pcb| ----> |segundo_cb| <------
//   |           | <---- |          | <---- |          |       |
//  prev |  ^      prev               prev        next |       |
//       |  |                                          |       |
//       |  --------------------------------------------       |
//       |                                                     |
//       -------------------------------------------------------
//
// Lista vacia: (Apunta a si mismo el sentinela)
//
//
//       |  sentinela  | <---------
//       |             |          |
//  prev |  ^     next |          |
//       |  |          |          |
//       |  ------------          |
//       |                        |
//       --------------------------
pcb_t lista_new = {0};
pcb_t lista_rdy = {0};
pcb_t lista_susp_rdy = {0};
pcb_t lista_bloq = {0};
pcb_t lista_susp_bloq = {0};
// 0/null cuando no hay proceso en EXEC
pcb_t *executing_pcb = NULL;

void init_pcb_list(pcb_t *l)
{
    l->next = l;
    l->prev = l;
    l->state = PROC_STATE_INVALID_IS_LIST;
    l->pid = 0;

    l->contador_suspensiones = 0;
    l->timestamp_recibido = 0;
    l->timestamp_ingreso_sistema = 0;
}
// Assert que `l` es una lista y no un pcb
void assert_es_lista(pcb_t *l)
{
    // pid 0 es invalido para un PCB, empiezan en 1
    assert_and_log(l != NULL && l->state == PROC_STATE_INVALID_IS_LIST && l->pid == 0, "Se llamo una funcion de lista con un pcb");
}
void push(pcb_t *l, pcb_t *pcb)
{
    assert_es_lista(l);
    pcb->prev = l;
    pcb->next = l->next;
    l->next = pcb;
    pcb->next->prev = pcb;
}
void remove_from_list(pcb_t *p)
{
    if (p->next)
    {
        assert_and_log(p->prev != NULL, "Si next nonnull prev debe ser nonnull");
        p->next->prev = p->prev;
    }
    if (p->prev)
    {
        assert_and_log(p->next != NULL, "Si prev nonnull next debe ser nonnull");
        p->prev->next = p->next;
    }
    p->next = NULL;
    p->prev = NULL;
}
int is_empty_list(pcb_t *l)
{
    assert_es_lista(l);
    return l == l->next;
}
int list_len(pcb_t *l)
{
    assert_es_lista(l);
    int x = 0;
    for (pcb_t *it = l->next; it != l; it = it->next)
        x++;
    return x;
}
pcb_t *pop(pcb_t *l)
{
    assert_es_lista(l);
    if (l->next == l)
        return 0;
    pcb_t *p = l->next;
    remove_from_list(p);
    return p;
}
pcb_t *list_last(pcb_t *l)
{
    assert_es_lista(l);
    return l->prev == l ? NULL : l->prev;
}

void short_term_scheduling(void);
void mid_term_scheduling(void);
void long_term_scheduling(void);

int main(int argc, char **argv)
{
    init_pcb_list(&lista_new);
    init_pcb_list(&lista_rdy);
    init_pcb_list(&lista_susp_rdy);
    init_pcb_list(&lista_bloq);
    init_pcb_list(&lista_susp_bloq);
    assert(sem_init(&dispatcher_sema, 0, 0) == 0);
    assert(sem_init(&io_device_sema, 0, 0) == 0);

    if (argc > 1 && strcmp(argv[1], "-test") == 0)
        return run_tests();

    t_config *conf = config_create("./cfg/kernel.config");
    if (!conf)
    {
        errno = 0;
        conf = config_create("./kernel/cfg/kernel.config");
        if (!conf)
        {
            puts("No se encontro el config ./cfg/kernel.config o ./kernel/cfg/kernel.config");
            return -1;
        }
    }

    char *path_logger = config_get_string_value(conf, "ARCHIVO_LOG");

    logger = log_create(path_logger, "kernel", true, LOG_LEVEL_INFO);

    int puerto = config_get_int_value(conf, "PUERTO_ESCUCHA");

    char *ip_memoria = config_get_string_value(conf, "IP_MEMORIA");
    int puerto_memoria = config_get_int_value(conf, "PUERTO_MEMORIA");

    char *ip_cpu = config_get_string_value(conf, "IP_CPU");
    int puerto_cpu_dispatch = config_get_int_value(conf, "PUERTO_CPU_DISPATCH");
    int puerto_cpu_interrupt = config_get_int_value(conf, "PUERTO_CPU_INTERRUPT");

    estimacion_inicial = config_get_int_value(conf, "ESTIMACION_INICIAL");
    grado_multiprogramacion = config_get_int_value(conf, "GRADO_MULTIPROGRAMACION");
    tiempo_maximo_bloqueado = config_get_int_value(conf, "TIEMPO_MAXIMO_BLOQUEADO");
    alfa = config_get_double_value(conf, "ALFA");

    char *algo_planificacion = config_get_string_value(conf, "ALGORITMO_PLANIFICACION");
    if (starts_with(algo_planificacion, "FIFO"))
    {
        alg_planif = ALG_FIFO;
    }
    else if (starts_with(algo_planificacion, "SRT"))
    {
        alg_planif = ALG_SRT;
    }
    else
    {
        log_error(logger, "Algoritmo de planificacion invalido: %s", algo_planificacion);
        log_destroy(logger);
        return -1;
    }
    log_info(logger, "Inicio proceso KERNEL escucha %d memoria:%s:%d cpu D/I %s:%d:%d alfa %f alg %s EI/GM/TMB %d/%d/%d",
             puerto, ip_memoria, puerto_memoria, ip_cpu, puerto_cpu_dispatch, puerto_cpu_interrupt, alfa, algo_planificacion, estimacion_inicial, grado_multiprogramacion, tiempo_maximo_bloqueado);

    log_info(logger, "Conectando a cpu DISPATCH ...");
    cpu_dispatch_sock = open_socket_conn(ip_cpu, puerto_cpu_dispatch);
    log_info(logger, "Conectado a cpu DISPATCH socket: %d", cpu_dispatch_sock);
    log_info(logger, "Conectando a cpu INTERRUPT ...");
    cpu_int_sock = open_socket_conn(ip_cpu, puerto_cpu_interrupt);
    log_info(logger, "Conectado a cpu INTERRUPT socket: %d", cpu_int_sock);
    log_info(logger, "Conectando a MEMORIA ...");
    mem_sock = open_socket_conn(ip_memoria, puerto_memoria);
    log_info(logger, "Conectado a MEMORIA socket: %d", mem_sock);

    int sock_listen = open_listener_socket(puerto);

    start_detached_thread(dispatcher_thread, (void *)0);
    start_detached_thread(io_device_thread, (void *)0);

    t_buflen network_buf = make_buf(1024);
    while (true)
    {
        int new_conn_sock = accept_new_conn(sock_listen);
        log_info(logger, "Nueva conexion socket %d", new_conn_sock);

        t_msgheader h = recv_msg(new_conn_sock, &network_buf);
        assert_and_log(h.codigo == NUEVO_PROCESO, "kernel solo recibe NUEVO_PROCESO");

        u32 tamanio = read_u32(network_buf.buf);
        u32 inst_count = read_u32(network_buf.buf + 4);
        inst_t *insts_in_buf = network_buf.buf + 8;
        inst_t *insts = malloc(sizeof(inst_t) * inst_count);
        memcpy(insts, insts_in_buf, sizeof(inst_t) * inst_count);

        static u32 last_pid = 1;
        u32 new_pid = last_pid++;
        log_info_colored(ANSI_COLOR_BLUE, "Recibido nuevo proceso pid: %d inst_count: %d", new_pid, inst_count);
        log_insts(insts, inst_count);

        pcb_t *pcb = malloc(sizeof(pcb_t));
        *pcb = (pcb_t){0};
        pcb->pc = 0;
        pcb->rafaga_actual = 0;
        pcb->pid = new_pid;
        pcb->tamanio = tamanio;
        pcb->inst_count = inst_count;
        pcb->insts = insts;
        pcb->estimacion_rafaga = estimacion_inicial;
        pcb->consola_sock = new_conn_sock;

        pcb->timestamp_recibido = timestamp();
        pcb->contador_suspensiones = 0;
        pcb->timestamp_ingreso_sistema = 0;

        pthread_mutex_lock(&scheduling_mutex);
        log_info_colored(ANSI_COLOR_BLUE, "Avisando a MEMORIA...");
        pcb->pag_1er_niv = send_mem_new_process(mem_sock, &network_buf, new_pid, tamanio);
        log_info_colored(ANSI_COLOR_BLUE, "Nro de tabla de 1er nivel dado por MEMORIA: %d", pcb->pag_1er_niv);
        set_proc_state(pcb, PROC_STATE_NEW);
        long_term_scheduling();
        pthread_mutex_unlock(&scheduling_mutex);
    }

    close(sock_listen);
    free(network_buf.buf);

    log_info(logger, "Fin proceso KERNEL");
    log_destroy(logger);
    config_destroy(conf);

    assert(sem_destroy(&dispatcher_sema) == 0);
    assert(sem_destroy(&io_device_sema) == 0);
}
void set_proc_state(pcb_t *p, enum estado_proceso s)
{
    log_info_colored(ANSI_COLOR_MAGENTA, "Pasando proceso pid %d del estado %s a %s",
                     p->pid, estado_proces_a_str(p->state), estado_proces_a_str(s));
    assert_and_log(p->pid > 0,
                   "Se llamo a set_proc_state con pcb invalido (pid=0), probablemente fue una lista");

    pcb_t *lista;
    switch (s)
    {
    case PROC_STATE_NEW:
        assert_and_log(p->state == PROC_STATE_INVALID,
                       "A NEW solo se llega desde un PCB inicializado en ceros (PROC_STATE_INVALID)");
        lista = &lista_new;
        break;
    case PROC_STATE_RDY:
        // Si viene de exec(interrupt) o bloqueado no cambiamos multiprogramacion
        if (p->state == PROC_STATE_NEW || p->state == PROC_STATE_SUSPENDED_RDY)
        {
            multiprogramacion++;

            char stackbuf[1024];
            t_buflen buf = {stackbuf, 1024};
            if (p->state == PROC_STATE_SUSPENDED_RDY)
                send_mem_process_unsuspended(mem_sock, &buf, p->pid, p->pag_1er_niv);
            else
            { // NEW
                p->timestamp_ingreso_sistema = timestamp();
                //  Se hace cuando se crea, no es necesario
                // send_mem_new_process(mem_sock, &buf, p->pid);
            }
        }
        else
        {
            assert_and_log(p->state == PROC_STATE_EXEC || p->state == PROC_STATE_BLOCKED,
                           "A RDY solo se llega desde EXEC, BLOQUEADO, SUSP_RDY o NEW");
        }
        lista = &lista_rdy;
        break;
    case PROC_STATE_BLOCKED:
        assert_and_log(p->state == PROC_STATE_EXEC, "A BLOQ solo se llega desde EXEC");
        lista = &lista_bloq;
        break;
    case PROC_STATE_SUSPENDED_BLOCKED:
        assert_and_log(p->state == PROC_STATE_BLOCKED, "A SUSP_BLOQ solo se llega desde BLOQ");
        multiprogramacion--;
        lista = &lista_susp_bloq;

        p->contador_suspensiones++;

        char stackbuf[1024];
        t_buflen buf = {stackbuf, 1024};
        send_mem_process_suspended(mem_sock, &buf, p->pid, p->pag_1er_niv);
        break;
    case PROC_STATE_SUSPENDED_RDY:
        assert_and_log(p->state == PROC_STATE_SUSPENDED_BLOCKED, "A SUSP_RDY solo se llega desde SUSP_BLOQ");
        lista = &lista_susp_rdy;
        break;
    case PROC_STATE_EXEC:
        assert_and_log(p->state == PROC_STATE_RDY, "A EXEC solo se llega desde RDY");

        if (executing_pcb)
        {
            char stackbuf[1024];
            t_buflen buf = {stackbuf, 1024};
            // "fire and forget", no es necesario desbloquear el mutex
            send_interrupt(cpu_int_sock, &buf, executing_pcb->pid);
        }
        remove_from_list(p);
        executing_pcb = p;
        p->state = PROC_STATE_EXEC;
        assert(sem_post(&dispatcher_sema) == 0);

        return;
        break;
    case PROC_STATE_EXIT:
        assert_and_log(p->state == PROC_STATE_EXEC, "A EXIT solo se llega desde EXEC");

        u32 timestamp_actual = timestamp();
        u32 dur_rdy = (timestamp_actual - p->timestamp_ingreso_sistema) / 1000;
        u32 dur_rec = (timestamp_actual - p->timestamp_recibido) / 1000;
        log_info_colored(ANSI_COLOR_MAGENTA, "Cantidad suspensiones:%d tiempo_ejec_desde_rdy:%dms tiempo_ejec_desde_recibido:%dms",
                         p->contador_suspensiones, dur_rdy, dur_rec);

        free(p->insts);
        free(p);
        multiprogramacion--;
        return;
        break;
    default:
        log_error(logger, "Llamado a set_proc_state con estado invalido");
        log_destroy(logger);
        exit(-1);
    }
    remove_from_list(p);
    p->state = s;
    push(lista, p);
}

void *dispatcher_thread(void *_p)
{
    t_buflen network_buf = make_buf(1024);
    while (true)
    {
        assert(sem_wait(&dispatcher_sema) == 0);

        pthread_mutex_lock(&scheduling_mutex);
        pcb_t *p = executing_pcb;
        if (!p)
        {
            // Spurious wakeup
            pthread_mutex_unlock(&scheduling_mutex);
            continue;
        }
        u32 pid = p->pid;
        u32 pc = p->pc;
        u32 tab = p->pag_1er_niv;
        u32 n_insts = p->inst_count;
        inst_t *insts = p->insts;
        pthread_mutex_unlock(&scheduling_mutex);

        struct dispatch_res res = send_dispatch(cpu_dispatch_sock, &network_buf, pid, pc, tab, n_insts, insts);
        log_info(logger, "Retorno de dispatch pid %d pc %d io %d rafaga %d", res.pid, res.pc, res.bloqueo_io, res.rafaga);

        pthread_mutex_lock(&scheduling_mutex);
        assert_and_log(pid == res.pid, "dispatch devuelve el mismo pid que se le dio");
        int finished = res.pc == n_insts;
        if (executing_pcb == p)
        {
            executing_pcb = NULL;
        }
        if (finished)
        { // EXIT
            u32 consola_ret = HANDSHAKE_SIGNATURE;
            if (send_buffer(p->consola_sock, &consola_ret, sizeof(u32)) != 0)
            {
                log_error(logger, "Error enviando aviso de fin de proceso a consola pid %d", p->pid);
            }
            else
            {
                log_info_colored(ANSI_COLOR_BLUE, "Enviado aviso de fin de proceso a consola pid %d", p->pid);
            }

            send_mem_end_process(mem_sock, &network_buf, p->pid, p->pag_1er_niv);

            set_proc_state(p, PROC_STATE_EXIT);
            mid_term_scheduling();
        }
        else
        {
            // TODO: Verificar calculo estimacion
            p->rafaga_actual += res.rafaga;
            p->pc = res.pc;
            if (res.bloqueo_io != 0)
            { // BLOQUEADO
                double ultima_estimacion = p->estimacion_rafaga;
                double ultima_rafaga_real = res.rafaga;
                p->estimacion_rafaga = (u32)floor(ultima_estimacion * (1.0 - alfa) + alfa * ultima_rafaga_real);
                log_info_colored(ANSI_COLOR_GREEN, "actualizando pid %d estimacion_rafaga: %d ultima_estimacion %f ultima_rafaga_real %f alfa %f", p->pid, p->estimacion_rafaga, ultima_estimacion, ultima_rafaga_real, alfa);
                p->rafaga_actual = 0;

                p->block_ms = res.bloqueo_io;
                p->timestamp_inicio_block = timestamp();
                set_proc_state(p, PROC_STATE_BLOCKED);
                assert(sem_post(&io_device_sema) == 0);
                short_term_scheduling();
            }
            else
            { // Vuelta a RDY (interrupt)
                set_proc_state(p, PROC_STATE_RDY);
            }
        }
        pthread_mutex_unlock(&scheduling_mutex);
    }

    free(network_buf.buf);
    close(cpu_dispatch_sock);
    return (void *)0;
}

void *io_device_thread(void *_unused)
{
    while (true)
    {
        assert(sem_wait(&io_device_sema) == 0);

        pthread_mutex_lock(&scheduling_mutex);
        pcb_t *pcb = pop(&lista_bloq);
        if (pcb == NULL)
        {
            // Spurious wakeup
            pthread_mutex_unlock(&scheduling_mutex);
            continue;
        }
        u32 wait_ms = pcb->block_ms;
        i64 timestamp_inicio_block = pcb->timestamp_inicio_block;
        u32 tiempo_en_espera_antes_de_io = ((timestamp() - timestamp_inicio_block) / 1000);
        u32 tiempo_hasta_suspendido = tiempo_en_espera_antes_de_io > tiempo_maximo_bloqueado ? 0 : tiempo_maximo_bloqueado - tiempo_en_espera_antes_de_io;

        assert(pcb->state == PROC_STATE_BLOCKED);

        if (wait_ms > tiempo_hasta_suspendido)
        {
            u32 remaining_wait_ms_after_suspend = wait_ms - tiempo_hasta_suspendido;
            if (tiempo_hasta_suspendido > 0)
            {
                log_info_colored(ANSI_COLOR_CYAN, "Ejecutando IO de pid %d por %d ms, bloqueando (Va a suspenderse en %d)", pcb->pid, wait_ms, tiempo_hasta_suspendido);
                pthread_mutex_unlock(&scheduling_mutex);

                usleep(1000 * tiempo_hasta_suspendido);

                pthread_mutex_lock(&scheduling_mutex);
            }

            log_info_colored(ANSI_COLOR_CYAN, "Pasando pid %d a SUSPENDED_BLOCKED luego de %d ms de bloqueo, quedan %d ms, bloqueando",
                             pcb->pid, tiempo_hasta_suspendido, remaining_wait_ms_after_suspend);
            set_proc_state(pcb, PROC_STATE_SUSPENDED_BLOCKED);
            mid_term_scheduling();
            pthread_mutex_unlock(&scheduling_mutex);

            usleep(1000 * remaining_wait_ms_after_suspend);

            pthread_mutex_lock(&scheduling_mutex);
            log_info_colored(ANSI_COLOR_CYAN, "Terminada IO pid %d", pcb->pid);
            set_proc_state(pcb, PROC_STATE_SUSPENDED_RDY);
            mid_term_scheduling();
            pthread_mutex_unlock(&scheduling_mutex);
        }
        else
        {
            log_info_colored(ANSI_COLOR_CYAN, "Ejecutando IO de pid %d por %d ms, bloqueando", pcb->pid, wait_ms);
            pthread_mutex_unlock(&scheduling_mutex);

            usleep(1000 * wait_ms);

            pthread_mutex_lock(&scheduling_mutex);
            log_info_colored(ANSI_COLOR_CYAN, "Terminada IO pid %d", pcb->pid);
            set_proc_state(pcb, PROC_STATE_RDY);
            mid_term_scheduling();
            pthread_mutex_unlock(&scheduling_mutex);
        }
    }

    return (void *)0;
}

void short_term_scheduling(void)
{
    if (alg_planif == ALG_FIFO)
    {
        if (executing_pcb == NULL)
        {
            pcb_t *first_in_rdy = list_last(&lista_rdy);
            pcb_t *first_in_susp_rdy = list_last(&lista_susp_rdy);
            pcb_t *first_in = first_in_susp_rdy ? first_in_susp_rdy : first_in_rdy;
            if (first_in)
            {
                log_info_colored(ANSI_COLOR_GREEN, "No hay nadie en EXEC, planificando pid %d para ejecucion (FIFO)", first_in->pid);
                set_proc_state(first_in, PROC_STATE_EXEC);
            }
        }
    }
    else
    { // SRT
        pcb_t *best_rdy_pcb = NULL;
        for (pcb_t *it = lista_rdy.next; it != &lista_rdy; it = it->next)
        {
            if (best_rdy_pcb == NULL || best_rdy_pcb->estimacion_rafaga >= it->estimacion_rafaga)
            {
                best_rdy_pcb = it;
            }
        }
        u32 estimacion_del_pcb_exec = executing_pcb ? executing_pcb->estimacion_rafaga : 0;
        if (best_rdy_pcb != NULL && (executing_pcb == NULL || estimacion_del_pcb_exec > best_rdy_pcb->estimacion_rafaga))
        {
            log_info_colored(ANSI_COLOR_GREEN, "estimacion %d de pid %d mejor que estimacion de EXEC %d (0=no habia nada en exec), "
                                               "planificando para ejecucion (SRT)",
                             best_rdy_pcb->estimacion_rafaga, best_rdy_pcb->pid, estimacion_del_pcb_exec);
            set_proc_state(best_rdy_pcb, PROC_STATE_EXEC);
        }
    }
}
void mid_term_scheduling(void)
{
    if (multiprogramacion < grado_multiprogramacion)
    {
        for (pcb_t *it = lista_susp_rdy.prev; it != &lista_susp_rdy;)
        {
            pcb_t *prev = it->prev;
            if (multiprogramacion < grado_multiprogramacion)
            {
                set_proc_state(it, PROC_STATE_RDY);
            }
            it = prev;
        }
        for (pcb_t *it = lista_new.prev; it != &lista_new;)
        {
            pcb_t *prev = it->prev;
            if (multiprogramacion < grado_multiprogramacion)
            {
                set_proc_state(it, PROC_STATE_RDY);
            }
            it = prev;
        }
    }
    short_term_scheduling();
}
void long_term_scheduling(void)
{
    for (pcb_t *it = lista_new.prev; it != &lista_new;)
    {
        pcb_t *prev = it->prev;
        if (multiprogramacion < grado_multiprogramacion)
        {
            set_proc_state(it, PROC_STATE_RDY);
        }
        it = prev;
    }
    short_term_scheduling();
}