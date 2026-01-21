# CVE-2026-XXXX: Sunia SPB Peripheral Driver LPE

**Exploit Title:** Sunia SPB Peripheral Driver - Arbitrary Physical Memory Read/Write (LPE)  
**Date:** 2026-01-20  
**Exploit Author:** b3s3da  
**Vendor:** Sunia Electronics  
**Driver Version:** 1.0.7.2 (TcnPeripheral64.sys)  
**SHA256:** `fa4e294b11e613a27722559b043637bd4d0af5603ab7e8c7970caffd96cf7247`  
**Tested On:** Windows 10 x64 (21H2)  
**Vulnerability Type:** Local Privilege Escalation (LPE) / Arbitrary Memory R/W

---

## 📝 Description

The `TcnPeripheral64.sys` driver contains a critical vulnerability in its IOCTL handler that allows unprivileged user-mode applications to map arbitrary physical memory with Read/Write permissions (`PAGE_READWRITE`).

The vulnerability resides in the dispatch routine for IOCTL `0x4002848`. The driver accepts a user-supplied physical address and size, then passes them directly to `ZwMapViewOfSection` backed by `\Device\PhysicalMemory`, without proper validation or access control lists (ACLs).

This primitive allows an attacker to:
1. Read sensitive kernel memory
2. Overwrite critical kernel structures (e.g., Process Tokens) to escalate privileges to **NT AUTHORITY\SYSTEM**
3. Bypass kernel security mechanisms (e.g., Driver Signature Enforcement)

---

## 🔧 Technical Details

| Property | Value |
|----------|-------|
| **Vulnerable Driver** | `TcnPeripheral64.sys` |
| **Symbolic Link** | `\\.\SPBTESTTOOL` |
| **Vulnerable IOCTL** | `0x4002848` (Decimal: `67119176`) |
| **Vulnerable Function** | Subroutine at offset `0x2D08` |
| **Driver Hash (SHA256)** | `fa4e294b11e613a27722559b043637bd4d0af5603ab7e8c7970caffd96cf7247` |

> **Note:** The driver appears to be based on the Microsoft SpbTestTool sample, retaining the original symbolic link name.

### IOCTL Structure

```cpp
// Input Buffer (40 bytes minimum)
struct MapRequest {
    uint64_t Size;            // Mapping size
    uint64_t PhysicalAddress; // Target physical address  
    uint64_t Reserved[3];     // Padding
};

// Output Buffer (40 bytes)
struct MapResponse {
    uint64_t Unknown1;
    uint64_t Unknown2;
    uint64_t SectionHandle;
    void*    MappedAddress;   // Userspace pointer to physical memory
    uint64_t Object;
};
```

---

## ⚙️ Hardware Initialization Bypass (BYOVD Context)

The driver includes a `Hardware Init` check (`sub_1400017A0`) that verifies the presence of specific ACPI resources (GPIO/Interrupts) before enabling the IOCTL interface. On standard systems without Sunia hardware, the driver fails to initialize, returning `Error 1` (`ERROR_INVALID_FUNCTION`).

**Exploitation Technique:** To exploit this vulnerability on arbitrary targets (Bring Your Own Vulnerable Driver scenario), the driver must be manually bound to legacy system resources. This bypasses the initialization check by forcing the driver to attach to an existing system device.

---

## 🚀 Proof of Concept

### Driver Installation (Bypass Setup)

Since the target machine likely lacks the specific Sunia hardware, install the driver using the "Legacy Hardware" method:

1. Open **Device Manager** (`devmgmt.msc`)
2. Select **Action** → **Add legacy hardware**
3. Choose **"Install the hardware that I manually select from a list"**
4. Select **"System devices"** → **Next**
5. Click **"Have Disk..."** and browse to `TcnPeripheral64.inf`
6. Select **"Sunia SPB Peripheral Driver"** and complete the installation

> This binds the driver to generic system resources, satisfying the internal check.

---

## 📸 Screenshots

<p align="center">
  <img src="media/poc_output.png" alt="PoC Output" width="687">
</p>

---

## 💥 Impact

| Attack Vector | Description |
|---------------|-------------|
| **Kernel Memory Read** | Read arbitrary physical memory including kernel structures |
| **Kernel Memory Write** | Modify kernel memory to escalate privileges |
| **Token Manipulation** | Overwrite process token to gain SYSTEM privileges |
| **Security Bypass** | Disable EDR/AV by patching kernel callbacks |
| **Credential Theft** | Access LSASS memory for credential extraction |

---

## 🛡️ Remediation

- Remove or disable the vulnerable driver
- Implement proper access control checks in the IOCTL handler
- Restrict physical memory mapping to privileged callers only
- Add address range validation
- Use `IoValidateDeviceIoControlAccess` for IOCTL validation

---

## 📅 Timeline

| Date | Event |
|------|-------|
| 2026-01-20 | Vulnerability discovered |
| 2026-01-22 | Public disclosure |

---

## ⚠️ Disclaimer

This research is for **educational purposes and authorized security testing only**. The author takes no responsibility for any unauthorized use of this information. Unauthorized access to computer systems is illegal.

---