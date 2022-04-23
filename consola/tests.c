#include "tests.h"
#include "consola.h"

static char *archivo_test =
    "WRITE 1 2\nCOPY 5 4 \nI/O 1000 \nREAD 5 \nNO_OP 3 \nEXIT\n";
void asserts_prueba_parseo(inst_t *insts, int count)
{
    CU_ASSERT_EQUAL(count, 8);
    CU_ASSERT_EQUAL(insts[0].code, INST_WRITE);
    CU_ASSERT_EQUAL(insts[1].code, INST_COPY);
    CU_ASSERT_EQUAL(insts[2].code, INST_IO);
    CU_ASSERT_EQUAL(insts[3].code, INST_READ);
    CU_ASSERT_EQUAL(insts[4].code, INST_NO_OP);
    CU_ASSERT_EQUAL(insts[5].code, INST_NO_OP);
    CU_ASSERT_EQUAL(insts[6].code, INST_NO_OP);
    CU_ASSERT_EQUAL(insts[7].code, INST_EXIT);

    CU_ASSERT_EQUAL(insts[0].args[0], 1);
    CU_ASSERT_EQUAL(insts[1].args[0], 5);
    CU_ASSERT_EQUAL(insts[2].args[0], 1000);
    CU_ASSERT_EQUAL(insts[3].args[0], 5);
    CU_ASSERT_EQUAL(insts[4].args[0], 0);
    CU_ASSERT_EQUAL(insts[5].args[0], 0);
    CU_ASSERT_EQUAL(insts[6].args[0], 0);
    CU_ASSERT_EQUAL(insts[7].args[0], 0);

    CU_ASSERT_EQUAL(insts[0].args[1], 2);
    CU_ASSERT_EQUAL(insts[1].args[1], 4);
    CU_ASSERT_EQUAL(insts[2].args[1], 0);
    CU_ASSERT_EQUAL(insts[3].args[1], 0);
    CU_ASSERT_EQUAL(insts[4].args[1], 0);
    CU_ASSERT_EQUAL(insts[5].args[1], 0);
    CU_ASSERT_EQUAL(insts[6].args[1], 0);
    CU_ASSERT_EQUAL(insts[7].args[1], 0);
}
void prueba_parseo()
{
    char *data = strdup(archivo_test);
    int count = 0;
    inst_t *insts = parse_codigo(data, strlen(data), &count);
    free(data);

    asserts_prueba_parseo(insts, count);

    char *without_final_newline = strdup(archivo_test);
    without_final_newline[strlen(without_final_newline) - 1] = '\0';
    insts = parse_codigo(without_final_newline, strlen(without_final_newline), &count);
    free(without_final_newline);

    asserts_prueba_parseo(insts, count);
}

int run_tests()
{
    CU_initialize_registry();
    CU_pSuite tests = CU_add_suite("Consola Suite", NULL, NULL);
    CU_add_test(tests, "Prueba basica de parseo", prueba_parseo);

    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();
    int ret = CU_get_number_of_tests_failed() > 0 ? 1 : 0;
    CU_cleanup_registry();
    return ret;
}