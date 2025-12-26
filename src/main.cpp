#include <cstdint>
#include <cstring>
#include <sys/mman.h>
#include <cstdlib>

#include "pl/Gloss.h"
#include "pl/Signature.h"

static const char* PISTON_LIMIT_SIGNATURE = "09 9B 1F 31 00 F1 ?9 0? 00 54";
static const char* PISTON_LIMIT_REPLACE   = "09 9B 1F FD 3F B1 ?9 0? 00 54";

static bool PatchMemory(void* addr, const void* data, size_t size) {
    uintptr_t page_start = (uintptr_t)addr & ~(4095UL);
    size_t page_size = ((uintptr_t)addr + size - page_start + 4095) & ~(4095UL);
    if (mprotect((void*)page_start, page_size, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) return false;
    memcpy(addr, data, size);
    __builtin___clear_cache((char*)addr, (char*)addr + size);
    mprotect((void*)page_start, page_size, PROT_READ | PROT_EXEC);
    return true;
}

static uint8_t hexCharToNibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return 0;
}

static bool PatchPistonLimit() {
    uintptr_t addr = pl::signature::pl_resolve_signature(PISTON_LIMIT_SIGNATURE, "libminecraftpe.so");
    if (addr == 0) return false;

    int sig_len = 0;
    const char* p = PISTON_LIMIT_SIGNATURE;
    while (*p) {
        if (*p != ' ') sig_len++;
        p++;
    }
    sig_len = (sig_len + 1) / 2;

    uint8_t patch_bytes[sig_len];
    const char* src = PISTON_LIMIT_REPLACE;
    uint8_t* mem = (uint8_t*)addr;

    for (int i = 0; i < sig_len; ++i) {
        char high = src[0];
        char low  = src[1];
        uint8_t orig = mem[i];
        uint8_t val = 0;
        if (high == '?') val |= (orig & 0xF0);
        else val |= (hexCharToNibble(high) << 4);
        if (low == '?') val |= (orig & 0x0F);
        else val |= hexCharToNibble(low);
        patch_bytes[i] = val;
        src += 2;
        if (*src == ' ') src++;
    }

    return PatchMemory((void*)addr, patch_bytes, sig_len);
}

__attribute__((constructor))
void EPPL_Init() {
    GlossInit(true);
    PatchPistonLimit();
}