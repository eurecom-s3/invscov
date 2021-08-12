#include <cstdlib>
#include <cstdio>
#include <cmath>
#include <mutex>
#include <cstdint>
#include <cfloat>
#include <sys/mman.h>
#include <unistd.h>
#include <inttypes.h>

#include "dump_rt.h"

using namespace std;

static mutex dump_mutex;
static size_t this_invocation_nonce;

namespace __invscov {

FILE* dtrace_out = NULL;

void destroy() {
  dump_mutex.lock();
  if (dtrace_out) {
    fclose(dtrace_out);
    dtrace_out = NULL;
  }
  dump_mutex.unlock();
}

__attribute__((constructor, no_sanitize("address", "memory"))) void init() {
  if (getenv("DAIKON_DTRACE_FILE")) {
    char* path = getenv("DAIKON_DTRACE_FILE");
    dtrace_out = fopen(path, "w");
  } else
    dtrace_out = stderr;
  atexit(destroy);
}

} // namespace __invscov

using namespace __invscov;

extern "C" void __afl_manual_init(void) {}
extern "C" int __afl_persistent_loop(unsigned int) {
  static int cnt = 0;
  if (cnt == 0) {
    cnt = 1;
    return 1;
  }
  return 0;
}

extern "C" __attribute__((no_sanitize("address", "memory"))) uint8_t __invscov_area_is_mapped(void *ptr, size_t len) {

  if ((uintptr_t)ptr < sysconf(_SC_PAGE_SIZE)) return 0; // fast path for null ptrs
  
  // check if mapped
  char *p = (char*)ptr;
  char *page = (char *)((uintptr_t)p & ~(sysconf(_SC_PAGE_SIZE) - 1));

  int r = msync(page, (p - page) + len, MS_ASYNC);
  if (r < 0) return errno != ENOMEM;
  
  return 1;

}

extern "C" __attribute__((no_sanitize("address", "memory"))) uint8_t __invscov_area_is_valid(void *ptr, size_t len) {

  // check if valid
  // return __asan_region_is_poisoned(ptr, len) == NULL;
  // return __msan_test_shadow(ptr, len) == -1;
  return 1;

}

extern "C" __attribute__((no_sanitize("address", "memory"))) size_t __invscov_dump_enter_prologue(const char* name) {
  size_t in = this_invocation_nonce++;
  if (in == 0) {
    if (dtrace_out) fprintf(dtrace_out, "input-language C/C++\ndecl-version 2.0\n"
                        "var-comparability implicit\n\n");
  }
  if (dtrace_out) {
    fprintf(dtrace_out, "%s():::ENTER\n", name);
    fprintf(dtrace_out, "this_invocation_nonce\n%lu\n", in);
  }
  return in;
}

extern "C" __attribute__((no_sanitize("address", "memory"))) size_t __invscov_dump_loop_prologue(const char* name, int pptid) {
  size_t in = this_invocation_nonce++;
  if (dtrace_out) {
    fprintf(dtrace_out, "%s():::LOOP%d\n", name, pptid);
    fprintf(dtrace_out, "this_invocation_nonce\n%lu\n", in);
  }
  return in;
}

extern "C" __attribute__((no_sanitize("address", "memory"))) void __invscov_dump_exit_prologue(const char* name, int pptid, size_t in) {
  if (dtrace_out) {
    fprintf(dtrace_out, "%s():::EXIT%d\n", name, pptid);
    fprintf(dtrace_out, "this_invocation_nonce\n%lu\n", in);
  }
}

extern "C" __attribute__((no_sanitize("address", "memory"))) void __invscov_dump_epilogue() {
  if (dtrace_out) {
    fprintf(dtrace_out, "\n");
    //fflush(dtrace_out);
  }
}

extern "C" __attribute__((no_sanitize("address", "memory"))) void __invscov_dump_lock() {
  dump_mutex.lock();
}
extern "C" __attribute__((no_sanitize("address", "memory"))) void __invscov_dump_unlock() {
  dump_mutex.unlock();
}

extern "C" __attribute__((no_sanitize("address", "memory"))) void __invscov_dump_nosense(const char* name) {
  if (dtrace_out) fprintf(dtrace_out, "%s\nnonsensical\n2\n", name);
}

extern "C" __attribute__((no_sanitize("address", "memory"))) void __invscov_dump_i8(const char* name, int8_t val) {
  if (dtrace_out) fprintf(dtrace_out, "%s\n%d\n1\n", name, (int)val);
}

extern "C" __attribute__((no_sanitize("address", "memory"))) void __invscov_dump_i16(const char* name, int16_t val) {
  if (dtrace_out) fprintf(dtrace_out, "%s\n%d\n1\n", name, (int)val);
}

extern "C" __attribute__((no_sanitize("address", "memory"))) void __invscov_dump_i32(const char* name, int32_t val) {
  if (dtrace_out) fprintf(dtrace_out, "%s\n%" PRId32 "\n1\n", name, val);
}

extern "C" __attribute__((no_sanitize("address", "memory"))) void __invscov_dump_i64(const char* name, int64_t val) {
  if (dtrace_out) fprintf(dtrace_out, "%s\n%" PRId64 "\n1\n", name, val);
}

extern "C" __attribute__((no_sanitize("address", "memory"))) void __invscov_dump_u8(const char* name, uint8_t val) {
  if (dtrace_out) fprintf(dtrace_out, "%s\n%u\n1\n", name, (unsigned)val);
}

extern "C" __attribute__((no_sanitize("address", "memory"))) void __invscov_dump_u16(const char* name, uint16_t val) {
  if (dtrace_out) fprintf(dtrace_out, "%s\n%u\n1\n", name, (unsigned)val);
}

extern "C" __attribute__((no_sanitize("address", "memory"))) void __invscov_dump_u32(const char* name, uint32_t val) {
  if (dtrace_out) fprintf(dtrace_out, "%s\n%" PRIu32 "\n1\n", name, val);
}

extern "C" __attribute__((no_sanitize("address", "memory"))) void __invscov_dump_u64(const char* name, uint64_t val) {
  if (dtrace_out) fprintf(dtrace_out, "%s\n%" PRIu64 "\n1\n", name, val);
}

extern "C" __attribute__((no_sanitize("address", "memory"))) void __invscov_dump_f(const char* name, float val) {
  if (dtrace_out) {
    if (isnan(val)) fprintf(dtrace_out, "%s\nnan\n1\n", name);
    else fprintf(dtrace_out, "%s\n%f\n1\n", name, val);
  }
}

extern "C" __attribute__((no_sanitize("address", "memory"))) void __invscov_dump_d(const char* name, double val) {
  if (dtrace_out) {
    if (isnan(val)) fprintf(dtrace_out, "%s\nnan\n1\n", name);
    else fprintf(dtrace_out, "%s\n%lf\n1\n", name, val);
  }
}

extern "C" __attribute__((no_sanitize("address", "memory"))) void __invscov_dump_ld(const char* name, long double val) {
  if (dtrace_out) {
    if (isnan(val)) fprintf(dtrace_out, "%s\nnan\n1\n", name);
    else fprintf(dtrace_out, "%s\n%Lf\n1\n", name, val);
  }
}
