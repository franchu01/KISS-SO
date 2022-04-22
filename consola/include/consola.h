#ifndef CONSOLA_H
#define CONSOLA_H
#include <stdio.h>
#include <commons/log.h>
#include <commons/config.h>
#include <stdbool.h>
#include <stdlib.h>
#include <readline/readline.h>
#include <readline/history.h>
#include "shared_utils.h"
#include "tests.h"

inst_t *parse_codigo(char *b, int len, int *out_count);

#endif