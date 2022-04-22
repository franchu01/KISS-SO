#include "consola.h"

t_log *logger;

int main(int argc, char **argv)
{
    if (argc > 1 && strcmp(argv[1], "-test") == 0)
        return run_tests();

    if (argc != 3)
    {
        puts("Missing arguments.\n\n\tUSAGE: ./consola ./archivo_pseudocodigo tamanio_proceso \n\tEjemplo: ./consola ./test.txt 128");
        return -1;
    }

    t_config *conf = config_create("./cfg/consola.config");

    char *path_logger = config_get_string_value(conf, "ARCHIVO_LOG");

    logger = log_create(path_logger, "consola", true, LOG_LEVEL_INFO);

    char *ip_kernel = config_get_string_value(conf, "IP_KERNEL");
    int puerto_kernel = config_get_int_value(conf, "PUERTO_KERNEL");

    log_info(logger, "Inicio proceso CONSOLA %s tamanio %s kernel %s:%d", argv[1], argv[2], ip_kernel, puerto_kernel);

    int tamanio_proceso = atoi(argv[2]);
    FILE *f = fopen(argv[1], "rb");
    if (f == 0)
    {
        log_error(logger, "Error fopen(\"%s\", \"rb\") strerror: %s", argv[1], strerror(errno));
        log_destroy(logger);
        return -1;
    }
    fseek(f, 0, SEEK_END);
    int file_size = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *file_content = malloc(file_size);
    if (fread(file_content, file_size, 1, f) == 0)
    {
        log_error(logger, "Error fread(buf:0x%p, size:%d, 1, file:0x%p) strerror: %s", file_content, file_size, f, strerror(errno));
        log_destroy(logger);
        return -1;
    }
    fclose(f);
    int num_insts;
    log_info(logger, "Parseando archivo ...");
    inst_t *insts = parse_codigo(file_content, file_size, &num_insts);
    log_info(logger, "Archivo parseado:");
    free(file_content);
    log_insts(insts, num_insts);

    log_info(logger, "Conectando al kernel ...");
    int conn_sock = open_socket_conn(ip_kernel, puerto_kernel);
    log_info(logger, "Conectado al kernel socket %d", conn_sock);
    t_buflen network_buf = make_buf(num_insts * sizeof(inst_t) + 64);
    log_info(logger, "Enviando proceso al kernel...");
    send_nuevo_proceso(conn_sock, &network_buf, num_insts, insts, tamanio_proceso);

    close(conn_sock);
    free(network_buf.buf);

    log_info(logger, "Fin proceso CONSOLA");
    log_destroy(logger);
    config_destroy(conf);
}

inst_t *parse_codigo(char *b, int len, int *out_count)
{
    char *end = b + len;

    static inst_t inst_storage[5000] = {};
    inst_t *out_buf = inst_storage;
    inst_t *out_buf_end = inst_storage + sizeof(inst_storage) / sizeof(*inst_storage);

    char *line_start = b;
    char *line_end = line_start;
    int finished = 0;
    while (true)
    {
        while (line_end != end && *line_end != '\n' && *line_end != '\0')
            line_end++;
        finished = line_end == end;
        if (finished)
        {
            static char buf[1024] = {};
            int count = line_end - line_start;
            memcpy(buf, line_start, count);
            buf[count] = '\0';
            line_start = buf;
            line_end = buf + count;
        }
        else
        {
            *line_end = '\0';
        }

        int repeat_count = 1;
        inst_t inst = {};
        if (starts_with(line_start, "NO_OP "))
        {
            inst.code = INST_NO_OP;
            repeat_count = atoi(line_start + 6);
        }
        else if (starts_with(line_start, "READ "))
        {
            inst.code = INST_READ;
            inst.args[0] = atoi(line_start + 5);
        }
        else if (starts_with(line_start, "WRITE "))
        {
            inst.code = INST_WRITE;
            inst.args[0] = atoi(line_start + 6);
            char *second_arg = line_end;
            while (*second_arg != ' ')
                second_arg--;
            inst.args[1] = atoi(second_arg);
        }
        else if (starts_with(line_start, "I/O "))
        {
            inst.code = INST_IO;
            inst.args[0] = atoi(line_start + 4);
        }
        else if (starts_with(line_start, "COPY "))
        {
            inst.code = INST_COPY;
            inst.args[0] = atoi(line_start + 5);
            char *second_arg = line_end;
            while (*second_arg != ' ')
                second_arg--;
            inst.args[1] = atoi(second_arg);
        }
        else if (starts_with(line_start, "EXIT"))
        {
            inst.code = INST_EXIT;
        }
        else if (*line_start == '\0' && finished)
        {
            *out_count = ((int)out_buf - (int)inst_storage) / sizeof(*inst_storage);
            return inst_storage;
        }
        else
        {
            log_error(logger, "Invalid line: \"%s\"", line_start);
            log_destroy(logger);
            exit(-1);
        }
        while (repeat_count > 0)
        {
            *out_buf = inst;
            out_buf++;
            repeat_count--;

            if (out_buf_end == out_buf)
            {
                log_error(logger, "File too big");
                log_destroy(logger);
                exit(-1);
            }
        }
        if (finished)
        {
            *out_count = ((int)out_buf - (int)inst_storage) / sizeof(*inst_storage);
            return inst_storage;
        }

        line_start = line_end + 1;
        line_end = line_start;
    }
}
