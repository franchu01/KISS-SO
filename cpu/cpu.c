#include "cpu.h"

t_log *logger;

u32 perform_readwrite(t_buflen *buf, u32 pag_lvl1, u32 addr, u32 is_write, u32 val, u32 pid);
void *interrupt_accept_thread(void *);
volatile int interrupt_pid = 0;
volatile int interrupt = false;
pthread_mutex_t interrupt_pid_mutex = PTHREAD_MUTEX_INITIALIZER;

enum tlb_alg
{
    TLB_ALG_FIFO,
    TLB_ALG_LRU
};
enum tlb_alg tlb_alg;
u32 entradas_x_pagina;
volatile int mem_sock;
u32 tam_pag;
// TODO: Arreglar estructura tlb segun enunciado v1.1
typedef struct entrada_tlb
{
    u32 marco;
    u32 page_digits;
    int64_t use_timestamp;
    int64_t requested_timestamp;
} entrada_tlb;
#define PAGE_DIGITS_UNUSED ((u32)(0x0FFFFFFF))
int entradas_tlb;
entrada_tlb *tlb;

void retornar_dispatch(int sockfd, t_buflen *network_buf, u32 pid, u32 pc, u32 rafaga, u32 bloqueo_io)
{
    u32 *buf = network_buf->buf;

    *(buf++) = pid;
    *(buf++) = pc;
    *(buf++) = rafaga;
    *(buf++) = bloqueo_io;

    send_buffer(sockfd, network_buf->buf, sizeof(u32) * 4);
}
u32 translate_addr(u32 log_addr, u32 page1, u32 pid, int mem_sock, t_buflen *buf, entrada_tlb **out_tlb);

int main(int argc, char **argv)
{
    if (argc > 1 && strcmp(argv[1], "-test") == 0)
        return run_tests();

    t_config *conf = config_create("./cfg/cpu.config");
    if (!conf)
    {
        errno = 0;
        conf = config_create("./cpu/cfg/cpu.config");
        if (!conf)
        {
            puts("No se encontro el config ./cfg/cpu.config o ./cpu/cfg/cpu.config");
            return -1;
        }
    }

    char *path_logger = config_get_string_value(conf, "ARCHIVO_LOG");

    logger = log_create(path_logger, "cpu", true, LOG_LEVEL_INFO);
    if (!logger)
    {
        printf("No se pudo abrir el archivo de log %s\n", path_logger);
        return -1;
    }

    char *ip_memoria = config_get_string_value(conf, "IP_MEMORIA");
    int puerto_memoria = config_get_int_value(conf, "PUERTO_MEMORIA");

    int puerto_dispatch = config_get_int_value(conf, "PUERTO_ESCUCHA_DISPATCH");
    int puerto_interrupt = config_get_int_value(conf, "PUERTO_ESCUCHA_INTERRUPT");

    char *alg_reemplazo_tlb_str = config_get_string_value(conf, "REEMPLAZO_TLB");
    if (starts_with(alg_reemplazo_tlb_str, "FIFO"))
    {
        tlb_alg = TLB_ALG_FIFO;
    }
    else if (starts_with(alg_reemplazo_tlb_str, "LRU"))
    {
        tlb_alg = TLB_ALG_LRU;
    }
    else
    {
        log_error(logger, "Algoritmo de reemplazo invalido: %s", alg_reemplazo_tlb_str);
        log_destroy(logger);
        return -1;
    }
    entradas_tlb = config_get_int_value(conf, "ENTRADAS_TLB");
    int retardo_noop = config_get_int_value(conf, "RETARDO_NOOP");

    log_info(logger, "Inicio proceso CPU escucha D/I %d/%d memoria:%s:%d alg %s cant_entradas_tlb %d retardo noop %d",
             puerto_dispatch, puerto_interrupt, ip_memoria, puerto_memoria, alg_reemplazo_tlb_str, entradas_tlb, retardo_noop);

    int sock_listen_disp = open_listener_socket(puerto_dispatch);
    int sock_listen_int = open_listener_socket(puerto_interrupt);

    tlb = malloc(entradas_tlb * sizeof(entrada_tlb));
    for (entrada_tlb *end = tlb + entradas_tlb, *tlb_entry = tlb; tlb_entry != end; tlb_entry++)
    {
        tlb_entry->page_digits = PAGE_DIGITS_UNUSED;
        tlb_entry->marco = PAGE_DIGITS_UNUSED;
        tlb_entry->use_timestamp = 0;
    }

    t_buflen network_buf = make_buf(1024);
    log_info(logger, "Aceptando conexion DISPATCH ...");
    int sock_disp = accept_new_conn(sock_listen_disp);
    log_info(logger, "Nueva conexion DISPATCH socket: %d", sock_disp);
    log_info(logger, "Aceptando conexion INTERRUPT ...");
    int sock_int = accept_new_conn(sock_listen_int);
    log_info(logger, "Nueva conexion INTERRUPT socket: %d", sock_int);

    close(sock_listen_disp);
    close(sock_listen_int);

    log_info(logger, "Conectando a MEMORIA ...");
    mem_sock = open_socket_conn(ip_memoria, puerto_memoria);
    log_info(logger, "Conexion con MEMORIA establecida socket %d", mem_sock);
    send_handshake_cpu_memoria(mem_sock, &network_buf, &entradas_x_pagina, &tam_pag);
    log_info(logger, "Handshake hecho con MEMORIA: tam_pagina:%d entradas_x_pagina:%d",
             tam_pag, entradas_x_pagina);

    start_detached_thread(interrupt_accept_thread, (void *)sock_int);

    while (true)
    {
        t_msgheader h = recv_msg(sock_disp, &network_buf);
        assert_and_log(h.codigo == DISPATCH_PROCESS, "socket dispatch de cpu solo recibe DISPATCH_PROCESS");

        u32 pid = *(u32 *)(network_buf.buf);
        u32 pc = *(u32 *)(network_buf.buf + 4);
        u32 tabla_pags_1er_niv = *(u32 *)(network_buf.buf + 8);
        u32 num_insts = *(u32 *)(network_buf.buf + 12);

        inst_t *in_insts = network_buf.buf + 16;
        inst_t *insts = malloc(sizeof(inst_t) * num_insts);
        memcpy(insts, in_insts, sizeof(inst_t) * num_insts);

        log_info(logger, "Recibido %s pid:%d pc:%d tab:%d num_insts:%d x socket dispatch fd:%d",
                 codigo_msg_to_string(h.codigo), pid, pc, tabla_pags_1er_niv, num_insts, sock_int);

        assert_and_log(num_insts != 0, "Programa vacio? inst_count=0");
        assert_and_log(pc < num_insts, "Programa terminado? pc >= num_insts");

        int64_t inicio_ejecucion = timestamp();
        log_info(logger, "Inicio ciclo DISPATCH timestamp %" PRId64 "", inicio_ejecucion);
        // Flush TLB
        for (entrada_tlb *end = tlb + entradas_tlb, *tlb_entry = tlb; tlb_entry != end; tlb_entry++)
        {
            tlb_entry->page_digits = PAGE_DIGITS_UNUSED;
            tlb_entry->marco = PAGE_DIGITS_UNUSED;
            tlb_entry->use_timestamp = 0;
        }

        while (true)
        {
            assert(pc < num_insts);
            log_inst(insts, insts + pc);
            // "FETCH"
            inst_t inst = insts[pc];
            pc++;
            // "DECODE"
            enum inst_code inst_op = inst.code;
            // FETCH_OPERANDS
            int fetched_val = 0;
            if (inst_op == INST_COPY)
            {
                u32 copy_src = inst.args[1];
                fetched_val = perform_readwrite(&network_buf, tabla_pags_1er_niv, copy_src, 0, 0, pid);
            }
            // EXECUTE
            switch (inst_op)
            {
            case INST_NO_OP:
            {
                log_info(logger, "Ejecutando NOOP con sleep de %d ms", retardo_noop);
                usleep(retardo_noop * 1000);
                break;
            }
            case INST_EXIT:
            {
                int64_t elapsed = (timestamp() - inicio_ejecucion) / 1000;
                log_info(logger, "Ejecutando EXIT con nuevo pc %d elapsed %" PRId64 " ms", pc, elapsed);

                retornar_dispatch(sock_disp, &network_buf, pid, pc, (u32)elapsed, 0);
                goto after_while;
                break;
            }
            case INST_IO:
            {
                u32 elapsed = (u32)((timestamp() - inicio_ejecucion) / 1000);
                u32 ms_bloqueo = inst.args[0];
                log_info(logger, "Ejecutando IO con nuevo pc %d elapsed %d ms bloqueo %d", pc, elapsed, ms_bloqueo);

                retornar_dispatch(sock_disp, &network_buf, pid, pc, elapsed, ms_bloqueo);
                goto after_while;
                break;
            }
            case INST_READ:
            {
                u32 read_addr = inst.args[0];
                log_info(logger, "Ejecutando READ %d", read_addr);

                u32 read_val = perform_readwrite(&network_buf, tabla_pags_1er_niv, read_addr, 0, 0, pid);
                log_info(logger, "Valor leido: %d", read_val);
                break;
            }
            case INST_WRITE:
            {
                u32 write_addr = inst.args[0];
                u32 write_val = inst.args[1];
                log_info(logger, "Ejecutando WRITE *%d = %d", write_addr, write_val);

                u32 value_written = perform_readwrite(&network_buf, tabla_pags_1er_niv, write_addr, 1, write_val, pid);
                assert_and_log(write_val == value_written, "Valor escrito == valor retornado por memoria");
                break;
            }
            case INST_COPY:
            {
                u32 copy_dest = inst.args[0];
                u32 copy_src = inst.args[1];
                log_info(logger, "Ejecutando COPY *%d = *%d", copy_dest, copy_src);
                u32 value_written = perform_readwrite(&network_buf, tabla_pags_1er_niv, copy_dest, 1, fetched_val, pid);
                assert_and_log(fetched_val == value_written, "Valor escrito == valor retornado por memoria");
                break;
            }
            default:
                log_error(logger, "Se intento ejecutar instruccion invalida %d", (int)inst_op);
                log_destroy(logger);
                exit(-1);
            }
            // CHECK INTERRUPT
            pthread_mutex_lock(&interrupt_pid_mutex);
            u32 interrupted = interrupt;
            interrupt = false;
            u32 interrupted_pid = interrupt_pid;
            pthread_mutex_unlock(&interrupt_pid_mutex);
            if (interrupted)
            {
                if (interrupted_pid == pid)
                {
                    u32 elapsed = (u32)((timestamp() - inicio_ejecucion) / 1000);
                    log_info(logger, "Retornando debido a interrupt con nuevo pc %d elapsed %d ms", pc, elapsed);
                    retornar_dispatch(sock_disp, &network_buf, pid, pc, elapsed, 0);
                    break;
                }
            }
        }
    after_while:
        log_info(logger, "Fin ciclo DISPATCH");

        free(insts);
    }

    close(mem_sock);
    close(sock_disp);
    free(network_buf.buf);

    log_info(logger, "Fin proceso CPU");
    log_destroy(logger);
    config_destroy(conf);

    close(sock_int);
}

void *interrupt_accept_thread(void *_sock_int)
{
    int sock_int = (int)_sock_int;

    t_buflen network_buf = make_buf(1024);
    while (true)
    {
        t_msgheader h = recv_msg(sock_int, &network_buf);
        assert_and_log(h.codigo == INTERRUPT_PROCESS, "socket interrupt de cpu solo recibe INTERRUPT_PROCESS");

        u32 pid = *(u32 *)(network_buf.buf);
        log_info(logger, "Recibido %s pid %d en socket interrupt %d", codigo_msg_to_string(h.codigo), pid, sock_int);

        pthread_mutex_lock(&interrupt_pid_mutex);
        interrupt = true;
        interrupt_pid = pid;
        pthread_mutex_unlock(&interrupt_pid_mutex);
    }

    free(network_buf.buf);
    return 0;
}
entrada_tlb *get_tlb_entry_to_replace()
{
    for (entrada_tlb *end = tlb + entradas_tlb, *tlb_entry = tlb; tlb_entry != end; tlb_entry++)
    {
        if (tlb_entry->page_digits == PAGE_DIGITS_UNUSED)
        {
            return tlb_entry;
        }
    }
    switch (tlb_alg)
    {
    case TLB_ALG_FIFO:
    {
        entrada_tlb *ret = tlb;
        for (entrada_tlb *end = tlb + entradas_tlb, *tlb_entry = tlb; tlb_entry != end; tlb_entry++)
        {
            // min requested timestamp = oldest insertion = FIFO
            if (tlb_entry->requested_timestamp < ret->requested_timestamp)
            {
                ret = tlb_entry;
            }
        }
        ret->page_digits = PAGE_DIGITS_UNUSED;
        log_info(logger, "Reutilizando/Reemplazando entrada tlb nro %d",
                 (int)((((int)ret) - ((int)tlb)) / sizeof(entrada_tlb)));
        return ret;
    }
    case TLB_ALG_LRU:
    {
        entrada_tlb *ret = tlb;
        for (entrada_tlb *end = tlb + entradas_tlb, *tlb_entry = tlb; tlb_entry != end; tlb_entry++)
        {
            // min use timestamp = oldest use = least recently used
            if (tlb_entry->use_timestamp < ret->use_timestamp)
            {
                ret = tlb_entry;
            }
        }
        ret->page_digits = PAGE_DIGITS_UNUSED;
        log_info(logger, "Reutilizando/Reemplazando entrada tlb nro %d",
                 (int)((((int)ret) - ((int)tlb)) / sizeof(entrada_tlb)));
        return ret;
    }
    }
    assert_and_log(0, "algoritmo invalido en get_tlb_entry_to_replace");
    return NULL;
}
u32 translate_addr(u32 log_addr, u32 page_lvl1, u32 pid, int mem_sock, t_buflen *buf, entrada_tlb **out_tlb)
{
    u32 page_digits = log_addr / tam_pag;
    u32 offset_into_frame = log_addr % tam_pag;

    u32 page_lvl1_idx = page_digits / entradas_x_pagina;
    u32 page_lvl2_idx = page_digits % entradas_x_pagina;

    for (entrada_tlb *end = tlb + entradas_tlb, *tlb_entry = tlb; tlb_entry != end; tlb_entry++)
    {
        if (tlb_entry->page_digits == page_digits)
        {
            log_info(logger, "TLB HIT logical addr %#04X pagelvl1 %d page_digits %d page_lvl1_idx %d page_lvl2_idx %d marco %d",
                     log_addr, page_lvl1, tlb_entry->page_digits, page_lvl1_idx, page_lvl2_idx, tlb_entry->marco);
            tlb_entry->use_timestamp = timestamp();
            *out_tlb = tlb_entry;
            return tlb_entry->marco + offset_into_frame;
        }
    }
    log_info(logger, "TLB MISS logical addr %#04X pagelvl1 %d page_digits %d page_lvl1_idx %d page_lvl2_idx %d",
             log_addr, page_lvl1, page_digits, page_lvl1_idx, page_lvl2_idx);

    u32 invalidation_count = 0;
    u32 *invalidations = NULL;

    u32 page_lvl2_num = send_mem_page_read(mem_sock, buf, page_lvl1, page_lvl1_idx, page_digits * tam_pag, pid, &invalidation_count, &invalidations);
    assert_and_log(invalidation_count == 0, "Lectura de pagina de 1er nivel no invalida memoria");

    u32 phys_addr_marco = send_mem_page_read(mem_sock, buf, page_lvl2_num, page_lvl2_idx, page_digits * tam_pag, pid, &invalidation_count, &invalidations);

    for (u32 *inv_end = invalidations + invalidation_count; invalidations != inv_end; invalidations++)
    {
        for (entrada_tlb *end = tlb + entradas_tlb, *tlb_entry = tlb; tlb_entry != end; tlb_entry++)
        {
            if (tlb_entry->marco == *invalidations)
            {
                tlb_entry->page_digits = PAGE_DIGITS_UNUSED;
            }
        }
    }
    entrada_tlb *entry_to_replace = get_tlb_entry_to_replace();

    log_info(logger, "Escribiendo entrada de TLB nro %d addr_marco %d",
             (int)((((int)entry_to_replace) - ((int)tlb)) / sizeof(entrada_tlb)), phys_addr_marco);
    entry_to_replace->marco = phys_addr_marco;
    entry_to_replace->page_digits = page_digits;
    entry_to_replace->use_timestamp = timestamp();
    entry_to_replace->requested_timestamp = entry_to_replace->use_timestamp;

    *out_tlb = entry_to_replace;

    return phys_addr_marco + offset_into_frame;
}

u32 perform_readwrite(t_buflen *buf, u32 pag_lvl1, u32 addr, u32 is_write, u32 val, u32 pid)
{
    entrada_tlb *out_tlb = NULL;
    u32 phys_addr = translate_addr(addr, pag_lvl1, pid, mem_sock, buf, &out_tlb);
    return send_mem_readwrite(mem_sock, buf, phys_addr, is_write, val, pid);
}