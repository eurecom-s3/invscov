#ifndef __INVSCOV_DUMP_RT__
#define __INVSCOV_DUMP_RT__

#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

uint8_t __invscov_area_is_mapped(void *ptr, size_t len);
uint8_t __invscov_area_is_valid(void *ptr, size_t len);

size_t __invscov_dump_enter_prologue(const char* name);
size_t __invscov_dump_loop_prologue(const char* name, int pptid);
void __invscov_dump_exit_prologue(const char* name, int pptid, size_t in);
void __invscov_dump_lock();
void __invscov_dump_unlock();

void __invscov_dump_nosense(const char* name);

void __invscov_dump_i8(const char* name, int8_t val);
void __invscov_dump_i16(const char* name, int16_t val);
void __invscov_dump_i32(const char* name, int32_t val);
void __invscov_dump_i64(const char* name, int64_t val);
void __invscov_dump_f(const char* name, float val);
void __invscov_dump_d(const char* name, double val);
void __invscov_dump_ld(const char* name, long double val);

#ifdef __cplusplus
} // extern "C"
#endif

#endif
