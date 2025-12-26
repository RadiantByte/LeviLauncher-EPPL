#include <cstdint>
#include <cstring>
#include <sys/mman.h>

#include "pl/Gloss.h"
#include "pl/Signature.h"

static const char* PISTON_SIG_1 = "09 9B 1F 31 00 F1 ?9 0? 00 54";
static const char* PISTON_SIG_2 = "09 9B 1F 35 00 F1 ?? 27 9F 1A";

constexpr uint32_t ARM64_NOP = 0xD503201F;

static bool PatchMemory(void* addr, const void* data, size_t size) {
    uintptr_t page_start = (uintptr_t)addr & ~(4095UL);
    size_t page_size = ((uintptr_t)addr + size - page_start + 4095) & ~(4095UL);
    if (mprotect((void*)page_start, page_size, PROT_READ | PROT_WRITE | PROT_EXEC) != 0)
        return false;
    memcpy(addr, data, size);
    __builtin___clear_cache((char*)addr, (char*)addr + size);
    mprotect((void*)page_start, page_size, PROT_READ | PROT_EXEC);
    return true;
}

static bool PatchPistonSignature(const char* sig) {
    uintptr_t addr = pl::signature::pl_resolve_signature(sig, "libminecraftpe.so");
    if (addr == 0) return false;

    uint8_t* base = (uint8_t*)addr;

    uint32_t* branch = (uint32_t*)(base + 8);
    uint32_t nop = ARM64_NOP;

    return PatchMemory(branch, &nop, sizeof(nop));
}

__attribute__((constructor))
void EPPL_Init() {
    GlossInit(true);
    PatchPistonSignature(PISTON_SIG_1);
    PatchPistonSignature(PISTON_SIG_1);
    PatchPistonSignature(PISTON_SIG_2);
    PatchPistonSignature(PISTON_SIG_2);
    PatchPistonSignature(PISTON_SIG_2);
}