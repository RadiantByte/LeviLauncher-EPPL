#include <cstdint>
#include <cstring>
#include <sys/mman.h>

#include "pl/Gloss.h"
#include "pl/Signature.h"

/* ============================================================
 *  COMMON MEMORY PATCH HELPER
 * ============================================================ */

static bool PatchMemory(void* addr, const void* data, size_t size) {
    uintptr_t page_start = (uintptr_t)addr & ~(4095UL);
    size_t page_size =
        ((uintptr_t)addr + size - page_start + 4095) & ~(4095UL);

    if (mprotect((void*)page_start, page_size,
                 PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        return false;
    }

    memcpy(addr, data, size);
    __builtin___clear_cache((char*)addr, (char*)addr + size);

    mprotect((void*)page_start, page_size,
             PROT_READ | PROT_EXEC);

    return true;
}

static bool PatchBytes(uintptr_t addr, const uint8_t* data, size_t size) {
    return PatchMemory(reinterpret_cast<void*>(addr), data, size);
}

/* ============================================================
 *  GFX GAMMA PATCH (AS-IS)
 * ============================================================ */

static const char* GFX_GAMMA_SIGNATURE =
    "68 E1 0D F8 48 02 80 52 A8 03 16 38 28 0C 80 52 "
    "BF E3 1A 38 69 91 09 F8 68 11 0A 78 E8 4D 82 52 "
    "01 E4 00 2F 00 10 2C 1E 68 50 A7 72 02 10 2E 1E";

constexpr uint32_t MOV_W8_10     = 0x52800148;
constexpr uint32_t SCVTF_S2_W8   = 0x1E220102;
constexpr uint32_t FMOV_S2_1_0   = 0x1E2E1002;

static bool PatchGfxGamma() {
#if !defined(__aarch64__)
    return false;
#endif

    uintptr_t addr =
        pl::signature::pl_resolve_signature(
            GFX_GAMMA_SIGNATURE,
            "libminecraftpe.so"
        );

    if (!addr)
        return false;

    uint8_t* base = (uint8_t*)addr;
    uint32_t* max_addr = (uint32_t*)(base + 44);

    if (*max_addr != FMOV_S2_1_0)
        return false;

    uint32_t* mov_addr = (uint32_t*)(base + 40);

    if (!PatchMemory(mov_addr, &MOV_W8_10, sizeof(uint32_t)))
        return false;

    if (!PatchMemory(max_addr, &SCVTF_S2_W8, sizeof(uint32_t)))
        return false;

    return true;
}

/* ============================================================
 *  PISTON LIMIT PATCH (ARM64)
 * ============================================================ */

/*
 Rust:
 09 9B 1F 31 00 F1 ?9 0? 00 54
 → 09 9B 1F FD 3F B1 ?9 0? 00 54
*/
static bool PatchPistonLimit_A() {
#if !defined(__aarch64__)
    return false;
#endif

    uintptr_t addr =
        pl::signature::pl_resolve_signature(
            "09 9B 1F 31 00 F1 ?9 0? 00 54",
            "libminecraftpe.so"
        );

    if (!addr)
        return false;

    const uint8_t patch[] = { 0xFD, 0x3F, 0xB1 };
    return PatchBytes(addr + 3, patch, sizeof(patch));
}

/*
 Rust:
 09 9B 1F 35 00 F1 ?? 27 9F 1A
 → 09 9B 1F FD 3F B1 ?? 27 9F 1A
 repeat = 2
*/
static bool PatchPistonLimit_B() {
#if !defined(__aarch64__)
    return false;
#endif

    const char* sig = "09 9B 1F 35 00 F1 ?? 27 9F 1A";
    const uint8_t patch[] = { 0xFD, 0x3F, 0xB1 };

    // === first occurrence ===
    uintptr_t first =
        pl::signature::pl_resolve_signature(sig, "libminecraftpe.so");
    if (!first)
        return false;

    if (!PatchBytes(first + 3, patch, sizeof(patch)))
        return false;

    // === manual second scan ===
    // bypass sigCache by scanning forward
    uintptr_t second = 0;
    uintptr_t scan = first + 8;

    const uint8_t* base = (const uint8_t*)scan;
    const uint8_t* end  = base + 0x200000; // safe scan window

    while (base < end) {
        uintptr_t hit =
            pl::signature::pl_resolve_signature(sig, "libminecraftpe.so");

        if (hit && hit != first) {
            second = hit;
            break;
        }
        base += 4;
    }

    if (!second)
        return false;

    return PatchBytes(second + 3, patch, sizeof(patch));
}

static bool PatchPistonLimits() {
    if (!PatchPistonLimit_A())
        return false;

    if (!PatchPistonLimit_B())
        return false;

    return true;
}

/* ============================================================
 *  INIT
 * ============================================================ */

__attribute__((constructor))
void EPPL_Init() {
    GlossInit(true);

    PatchGfxGamma();
    PatchPistonLimits();
}