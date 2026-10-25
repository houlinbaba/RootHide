// Host regression exercising the production envbuf.c implementation with
// deterministic allocation failures. No Apple-only APIs are involved.
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int allocCount, failAt;
static bool should_fail(void) {
    ++allocCount;
    return failAt != 0 && allocCount == failAt;
}
static void *test_malloc(size_t n) { return should_fail() ? NULL : malloc(n); }
static void *test_calloc(size_t n, size_t sz) { return should_fail() ? NULL : calloc(n, sz); }
static void *test_realloc(void *p, size_t n) { return should_fail() ? NULL : realloc(p, n); }
static char *test_strdup(const char *p) { return should_fail() ? NULL : strdup(p); }

#define malloc test_malloc
#define calloc test_calloc
#define realloc test_realloc
#define strdup test_strdup
#include "envbuf.c"
#undef malloc
#undef calloc
#undef realloc
#undef strdup

static void fail_on(int n) { allocCount = 0; failAt = n; }
static void no_fail(void) { fail_on(0); }
static const char *source[] = {"A=one", "B=two", NULL};

int main(void) {
    unsigned tests = 0;
    no_fail();
    char **copy = envbuf_mutcopy(source);
    assert(copy && copy[0] != source[0] && envbuf_len((const char**)copy) == 3);
    assert(strcmp(envbuf_getenv((const char **)copy, "A"), "one") == 0);
    envbuf_free(copy); ++tests;

    no_fail();
    assert(envbuf_mutcopy(NULL) == NULL); ++tests;
    const char *empty[] = {NULL};
    copy = envbuf_mutcopy(empty);
    assert(copy && copy[0] == NULL);
    envbuf_free(copy); ++tests;

    for (int n=1;n<=3;n++) {
        fail_on(n);
        copy = envbuf_mutcopy(source);
        assert(copy == NULL);
        ++tests;
    }

    no_fail();
    copy=envbuf_mutcopy(source);
    assert(envbuf_setenv(&copy, "A", "replaced"));
    assert(strcmp(envbuf_getenv((const char **)copy, "A"), "replaced") == 0);
    envbuf_free(copy); ++tests;

    no_fail();
    copy=envbuf_mutcopy(source);
    assert(envbuf_setenv(&copy, "C", "three"));
    assert(envbuf_len((const char **)copy)==4);
    assert(strcmp(envbuf_getenv((const char **)copy, "C"), "three")==0);
    envbuf_unsetenv(&copy,"A");
    assert(envbuf_getenv((const char **)copy,"A")==NULL);
    assert(strcmp(envbuf_getenv((const char **)copy,"B"),"two")==0);
    envbuf_free(copy); ++tests;

    for (int n=1;n<=2;n++) {
        no_fail();
        copy=envbuf_mutcopy(source);
        char **saved=copy;
        fail_on(n);
        assert(!envbuf_setenv(&copy, "C", "three"));
        assert(copy == saved);
        assert(envbuf_getenv((const char **)copy,"C")==NULL);
        assert(strcmp(envbuf_getenv((const char **)copy,"A"),"one")==0);
        no_fail(); envbuf_free(copy); ++tests;
    }

    for (int n=1;n<=3;n++) {
        copy=NULL;
        fail_on(n);
        assert(!envbuf_setenv(&copy, "A", "one"));
        assert(copy==NULL);
        ++tests;
    }

    no_fail(); copy=NULL;
    assert(envbuf_setenv(&copy,"A","one"));
    assert(copy && strcmp(copy[0],"A=one")==0 && copy[1]==NULL);
    envbuf_free(copy); ++tests;

    no_fail();
    assert(!envbuf_setenv(NULL,"A","x"));
    assert(!envbuf_setenv(&copy,NULL,"x"));
    assert(!envbuf_setenv(&copy,"A",NULL)); ++tests;

    no_fail(); copy=envbuf_mutcopy(source);
    fail_on(1); assert(!envbuf_setenv(&copy,"A","should-not-replace"));
    assert(strcmp(envbuf_getenv((const char**)copy,"A"),"one")==0);
    no_fail(); envbuf_free(copy); ++tests;

    printf("PASS %u envbuf production-source scenarios under ASan/UBSan\n",tests);
    return 0;
}
