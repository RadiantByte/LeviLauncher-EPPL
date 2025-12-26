#include <cstdint>
#include <cstring>
#include <sys/mman.h>

#include "pl/Gloss.h"
#include "pl/Signature.h"

static bool PatchMemory(void* addr, const void* data, size_t size) {
    uintptr_t page_start = (uintptr_t)addr & ~(4095UL);
    size_t page_size = ((uintptr_t)addr + size - page_start + 4095) & ~(4095UL);

    if (mprotect((void*)page_start, page_size, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        return false;
    }

    memcpy(addr, data, size);
    __builtin___clear_cache((char*)addr, (char*)addr + size);
    mprotect((void*)page_start, page_size, PROT_READ | PROT_EXEC);

    return true;
}

static bool PatchSignatureReplace(const char* signature, const uint8_t* replace, size_t size, int repeat) {
    uintptr_t search_base = 0;

    for (int i = 0; i < repeat; i++) {
        uintptr_t addr = pl::signature::pl_resolve_signature(signature, "libminecraftpe.so", search_base);
        if (addr == 0) return false;
        if (!PatchMemory((void*)addr, replace, size)) return false;
        search_base = addr + size;
    }

    return true;
}

static bool PatchPistonLimits() {
    const char* SIG_PRIMARY_1 = "09 9B 1F 31 00 F1 ?9 0? 00 54";
    const uint8_t REP_PRIMARY_1[] = {0x09, 0x9B, 0x1F, 0xFD, 0x3F, 0xB1};

    uintptr_t addr1 = pl::signature::pl_resolve_signature(SIG_PRIMARY_1, "libminecraftpe.so");
    if (addr1 == 0) return false;
    if (!PatchMemory((void*)addr1, REP_PRIMARY_1, sizeof(REP_PRIMARY_1))) return false;

    const char* SIG_PRIMARY_2 = "09 9B 1F 35 00 F1 ?? 27 9F 1A";
    const uint8_t REP_PRIMARY_2[] = {0x09, 0x9B, 0x1F, 0xFD, 0x3F, 0xB1};

    uintptr_t search_base = 0;
    for (int i = 0; i < 2; i++) {
        uintptr_t addr2 = pl::signature::pl_resolve_signature(SIG_PRIMARY_2, "libminecraftpe.so", search_base);
        if (addr2 == 0) return false;
        if (!PatchMemory((void*)addr2, REP_PRIMARY_2, sizeof(REP_PRIMARY_2))) return false;
        search_base = addr2 + sizeof(REP_PRIMARY_2);
    }

    return true;
}

__attribute__((constructor))
void EPPL_Init() {
    GlossInit(true);
    PatchPistonLimits();
}