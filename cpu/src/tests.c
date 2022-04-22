#include "tests.h"

void suma_restaurante()
{
    CU_ASSERT_EQUAL(2 + 2, 4);
}

int run_tests()
{
    CU_initialize_registry();
    CU_pSuite tests = CU_add_suite("Restaurante Suite", NULL, NULL);
    CU_add_test(tests, "Probar Suma", suma_restaurante);

    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();
    int ret = CU_get_number_of_tests_failed() > 0 ? 1 : 0;
    CU_cleanup_registry();
    return ret;
}