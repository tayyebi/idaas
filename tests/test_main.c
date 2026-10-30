#include <stdio.h>

int test_util(void);
int test_b64(void);
int test_pkce(void);
int test_store(void);
int test_config(void);
int test_jwt(void);
int test_managed(void);
int test_accounts(void);

int main(void)
{
    int fails = 0;
    fails += test_util();
    fails += test_b64();
    fails += test_pkce();
    fails += test_store();
    fails += test_config();
    fails += test_jwt();
    fails += test_managed();
    fails += test_accounts();
    if (fails)
        printf("FAILED: %d check(s)\n", fails);
    else
        printf("all checks passed\n");
    return fails ? 1 : 0;
}
