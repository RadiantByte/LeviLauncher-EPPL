#include <cstdint>
#include <cstring>
#include <sys/mman.h>
#include "pl/Gloss.h"
#include "pl/Signature.h"
#include <android/log.h>

#define TAG "EPPL - NativeMOD"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

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

static bool PatchPistonLimit_A() {
#if !defined(__aarch64__)
    return false;
#endif

    uintptr_t addr = pl::signature::pl_resolve_signature(
        "09 9B 1F 31 00 F1 E9 00 00 54",
        "libminecraftpe.so"
    );

    if (!addr) {
        LOGE("Signature(A) Not found!");
        return false;
    }

    LOGI("Piston(A) addr: %p", (void*)addr);

    const uint8_t patch[] = { 0xFD, 0x3F, 0xB1 };
    return PatchBytes(addr + 3, patch, sizeof(patch));
}

static bool PatchPistonLimit_B() {
#if !defined(__aarch64__)
    return false;
#endif

    uintptr_t addr = pl::signature::pl_resolve_signature(
        "09 9B 1F 35 00 F1 E0 27 9F 1A",
        "libminecraftpe.so"
    );

    if (!addr) {
        LOGE("Signature(B) Not found!");
        return false;
    }

    LOGI("Piston(B) addr: %p", (void*)addr);

    const uint8_t patch[] = { 0xFD, 0x3F, 0xB1 };
    return PatchBytes(addr + 3, patch, sizeof(patch));
}

static bool PatchPistonLimits() {
    if (!PatchPistonLimit_A())
        return false;

    if (!PatchPistonLimit_B())
        return false;

    LOGI("Piston limits successfully patched");
    return true;
}

__attribute__((constructor))
void EPPL_Init() {
    GlossInit(true);
    PatchPistonLimits();
}