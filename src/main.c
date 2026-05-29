#include <ntifs.h>
#include <ntddk.h>
#include "../../../shared/ioctls.h"

typedef struct _Offs {
    ULONG Links, Start, End, Flags, Pid, Active, Root, Hint, Num;
} Offs;
Offs g_Offs = {0};

NTSYSAPI NTSTATUS NTAPI ZwProtectVirtualMemory(HANDLE p, PVOID* b, PSIZE_T s, ULONG n, PULONG o);
NTSYSAPI NTSTATUS NTAPI ZwFreeVirtualMemory(HANDLE p, PVOID* b, PSIZE_T s, ULONG f);

BOOLEAN Resolve() {
    RTL_OSVERSIONINFOW v = {0};
    v.dwOSVersionInfoSize = sizeof(v);
    if (!NT_SUCCESS(RtlGetVersion(&v))) return FALSE;
    ULONG build = v.dwBuildNumber;
    g_Offs.Links = 0x0; g_Offs.Start = 0x18; g_Offs.End = 0x1C; g_Offs.Flags = 0x30;
    if (build >= 26100) {
        g_Offs.Pid = 0x1D0; g_Offs.Active = 0x1D8; g_Offs.Root = 0x558; g_Offs.Hint = 0x560; g_Offs.Num = 0x568;
    } else {
        g_Offs.Pid = 0x440; g_Offs.Active = 0x448; g_Offs.Root = 0x7D8; g_Offs.Hint = 0x7E0; g_Offs.Num = 0x7E8;
    }
    return TRUE;
}

PDEVICE_OBJECT g_DevObj = NULL;
UNICODE_STRING g_Name, g_Sym;
void Unload(PDRIVER_OBJECT d);
NTSTATUS Dispatch(PDEVICE_OBJECT d, PIRP i);
NTSTATUS Control(PDEVICE_OBJECT d, PIRP i);
NTKERNELAPI NTSTATUS IoCreateDriver(PUNICODE_STRING n, PDRIVER_INITIALIZE i);
WCHAR g_BufD[64]; WCHAR g_BufV[64];

NTSTATUS Init(PDRIVER_OBJECT d, PUNICODE_STRING r) {
    UNREFERENCED_PARAMETER(r);
    if (!Resolve()) return STATUS_NOT_SUPPORTED;
    LARGE_INTEGER tick; KeQueryTickCount(&tick);
    g_BufV[0] = L'\\'; g_BufV[1] = L'D'; g_BufV[2] = L'e'; g_BufV[3] = L'v'; g_BufV[4] = L'i'; g_BufV[5] = L'c'; g_BufV[6] = L'e'; g_BufV[7] = L'\\';
    g_BufV[8] = L'r'; g_BufV[9] = L'b'; g_BufV[10] = L'x'; g_BufV[11] = L'd'; g_BufV[12] = L'r'; g_BufV[13] = L'v'; g_BufV[14] = L'_';
    ULONG val = tick.LowPart;
    for (int i = 0; i < 8; i++) {
        ULONG nibble = (val >> (28 - i * 4)) & 0xF;
        g_BufV[15 + i] = (WCHAR)(nibble < 10 ? L'0' + nibble : L'A' + (nibble - 10));
    }
    g_BufV[23] = L'\0';
    RtlInitUnicodeString(&g_Name, g_BufV); RtlInitUnicodeString(&g_Sym, L"\\DosDevices\\rbxdrv");
    IoDeleteSymbolicLink(&g_Sym);
    NTSTATUS status = IoCreateDevice(d, 0, &g_Name, RBX_DEVICE_TYPE, 0, FALSE, &g_DevObj);
    if (!NT_SUCCESS(status)) return status;
    status = IoCreateSymbolicLink(&g_Sym, &g_Name);
    if (!NT_SUCCESS(status)) { IoDeleteDevice(g_DevObj); return status; }
    d->MajorFunction[IRP_MJ_CREATE] = Dispatch;
    d->MajorFunction[IRP_MJ_CLOSE] = Dispatch;
    d->MajorFunction[IRP_MJ_DEVICE_CONTROL] = Control;
    d->DriverUnload = Unload;
    g_DevObj->Flags |= DO_BUFFERED_IO; g_DevObj->Flags &= ~DO_DEVICE_INITIALIZING;
    return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT d, PUNICODE_STRING r) {
    UNREFERENCED_PARAMETER(d); UNREFERENCED_PARAMETER(r);
    LARGE_INTEGER tick; KeQueryTickCount(&tick);
    g_BufD[0] = L'\\'; g_BufD[1] = L'D'; g_BufD[2] = L'r'; g_BufD[3] = L'i'; g_BufD[4] = L'v'; g_BufD[5] = L'e'; g_BufD[6] = L'r'; g_BufD[7] = L'\\';
    g_BufD[8] = L'r'; g_BufD[9] = L'b'; g_BufD[10] = L'x'; g_BufD[11] = L'd'; g_BufD[12] = L'r'; g_BufD[13] = L'v'; g_BufD[14] = L'_';
    ULONG val = tick.LowPart ^ 0xDEADBEEF;
    for (int i = 0; i < 8; i++) {
        ULONG nibble = (val >> (28 - i * 4)) & 0xF;
        g_BufD[15 + i] = (WCHAR)(nibble < 10 ? L'0' + nibble : L'A' + (nibble - 10));
    }
    g_BufD[23] = L'\0';
    UNICODE_STRING dn; RtlInitUnicodeString(&dn, g_BufD);
    return IoCreateDriver(&dn, &Init);
}

void Unload(PDRIVER_OBJECT d) {
    UNREFERENCED_PARAMETER(d);
    IoDeleteSymbolicLink(&g_Sym); IoDeleteDevice(g_DevObj);
}

NTSTATUS Dispatch(PDEVICE_OBJECT d, PIRP i) {
    UNREFERENCED_PARAMETER(d);
    i->IoStatus.Status = STATUS_SUCCESS; i->IoStatus.Information = 0;
    IoCompleteRequest(i, IO_NO_INCREMENT); return STATUS_SUCCESS;
}

PRTL_BALANCED_NODE FindVad(PEPROCESS p, ULONG_PTR a) {
    ULONG_PTR vpn = a >> PAGE_SHIFT;
    PRTL_BALANCED_NODE node = *(PRTL_BALANCED_NODE*)((PUCHAR)p + g_Offs.Root);
    while (node) {
        ULONG start = *(ULONG*)((PUCHAR)node + g_Offs.Start);
        ULONG end = *(ULONG*)((PUCHAR)node + g_Offs.End);
        if (vpn >= start && vpn <= end) return node;
        node = (vpn < start) ? node->Left : node->Right;
    }
    return NULL;
}

BOOLEAN UnlinkVad(PEPROCESS p, ULONG_PTR a, PULONG outStart, PULONG outEnd) {
    PRTL_BALANCED_NODE node = FindVad(p, a);
    if (!node) return FALSE;
    if (outStart) *outStart = *(ULONG*)((PUCHAR)node + g_Offs.Start);
    if (outEnd) *outEnd = *(ULONG*)((PUCHAR)node + g_Offs.End);
    *(ULONG*)((PUCHAR)node + g_Offs.Start) = 0;
    *(ULONG*)((PUCHAR)node + g_Offs.End) = 0;
    if (g_Offs.Num == 0x568) {
        if (*(PULONGLONG)((PUCHAR)p + g_Offs.Num) > 0) (*(PULONGLONG)((PUCHAR)p + g_Offs.Num))--;
    } else {
        if (*(PULONG_PTR)((PUCHAR)p + g_Offs.Num) > 0) (*(PULONG_PTR)((PUCHAR)p + g_Offs.Num))--;
    }
    return TRUE;
}

BOOLEAN RelinkVad(PEPROCESS p, ULONG_PTR a, ULONG inStart, ULONG inEnd) {
    PRTL_BALANCED_NODE node = FindVad(p, a);
    if (!node) return FALSE;
    *(ULONG*)((PUCHAR)node + g_Offs.Start) = inStart;
    *(ULONG*)((PUCHAR)node + g_Offs.End) = inEnd;
    if (g_Offs.Num == 0x568) {
        (*(PULONGLONG)((PUCHAR)p + g_Offs.Num))++;
    } else {
        (*(PULONG_PTR)((PUCHAR)p + g_Offs.Num))++;
    }
    return TRUE;
}

NTSTATUS AllocMem(PALLOCATE_MEMORY_REQ req) {
    PEPROCESS proc;
    NTSTATUS status = PsLookupProcessByProcessId(req->TargetPid, &proc);
    if (!NT_SUCCESS(status)) return status;
    KAPC_STATE apc; BOOLEAN att = FALSE;
    __try {
        KeStackAttachProcess(proc, &apc); att = TRUE;
        PVOID base = NULL; SIZE_T zero = 0; SIZE_T size = req->Size;
        status = ZwAllocateVirtualMemory(ZwCurrentProcess(), &base, zero, &size, MEM_COMMIT | MEM_RESERVE, req->Protect);
        if (NT_SUCCESS(status)) { req->RemoteBase = base; req->Size = size; }
    } __except (EXCEPTION_EXECUTE_HANDLER) { status = GetExceptionCode(); }
    if (att) KeUnstackDetachProcess(&apc);
    ObDereferenceObject(proc); return status;
}

NTSTATUS MmCopyVirtualMemory(PEPROCESS f, PVOID fa, PEPROCESS t, PVOID ta, SIZE_T s, KPROCESSOR_MODE m, PSIZE_T bs);

NTSTATUS ReadMem(PREAD_MEMORY_REQ req) {
    PEPROCESS proc;
    NTSTATUS status = PsLookupProcessByProcessId(req->TargetPid, &proc);
    if (!NT_SUCCESS(status)) return status;
    PVOID buf = ExAllocatePoolWithTag(NonPagedPoolNx, req->Size, 'rbxD');
    if (!buf) { ObDereferenceObject(proc); return STATUS_INSUFFICIENT_RESOURCES; }
    SIZE_T cop = 0;
    status = MmCopyVirtualMemory(proc, req->RemoteBase, PsGetCurrentProcess(), buf, req->Size, KernelMode, &cop);
    if (NT_SUCCESS(status)) {
        __try { ProbeForWrite(req->Buffer, req->Size, 1); RtlCopyMemory(req->Buffer, buf, req->Size); }
        __except (EXCEPTION_EXECUTE_HANDLER) { status = GetExceptionCode(); }
    }
    ExFreePoolWithTag(buf, 'rbxD'); ObDereferenceObject(proc); return status;
}

NTSTATUS WriteMem(PWRITE_MEMORY_REQ req) {
    PEPROCESS proc;
    NTSTATUS status = PsLookupProcessByProcessId(req->TargetPid, &proc);
    if (!NT_SUCCESS(status)) return status;
    PVOID buf = ExAllocatePoolWithTag(NonPagedPoolNx, req->Size, 'rbxD');
    if (!buf) { ObDereferenceObject(proc); return STATUS_INSUFFICIENT_RESOURCES; }
    __try { ProbeForRead(req->Buffer, req->Size, 1); RtlCopyMemory(buf, req->Buffer, req->Size); }
    __except (EXCEPTION_EXECUTE_HANDLER) { ExFreePoolWithTag(buf, 'rbxD'); ObDereferenceObject(proc); return GetExceptionCode(); }
    SIZE_T cop = 0;
    status = MmCopyVirtualMemory(PsGetCurrentProcess(), buf, proc, req->RemoteBase, req->Size, KernelMode, &cop);
    ExFreePoolWithTag(buf, 'rbxD'); ObDereferenceObject(proc); return status;
}

NTSTATUS ProtMem(PPROTECT_MEMORY_REQ req) {
    PEPROCESS proc;
    NTSTATUS status = PsLookupProcessByProcessId(req->TargetPid, &proc);
    if (!NT_SUCCESS(status)) return status;
    KAPC_STATE apc; BOOLEAN att = FALSE;
    __try {
        KeStackAttachProcess(proc, &apc); att = TRUE;
        PVOID base = req->RemoteBase; SIZE_T sz = req->Size; ULONG old = 0;
        status = ZwProtectVirtualMemory(ZwCurrentProcess(), &base, &sz, req->NewProtect, &old);
        if (NT_SUCCESS(status)) req->OldProtect = old;
    } __except (EXCEPTION_EXECUTE_HANDLER) { status = GetExceptionCode(); }
    if (att) KeUnstackDetachProcess(&apc);
    ObDereferenceObject(proc); return status;
}

NTSTATUS FreeMem(PFREE_MEMORY_REQ req) {
    PEPROCESS proc;
    NTSTATUS status = PsLookupProcessByProcessId(req->TargetPid, &proc);
    if (!NT_SUCCESS(status)) return status;
    KAPC_STATE apc; BOOLEAN att = FALSE;
    __try {
        KeStackAttachProcess(proc, &apc); att = TRUE;
        PVOID base = req->RemoteBase; SIZE_T sz = req->Size;
        status = ZwFreeVirtualMemory(ZwCurrentProcess(), &base, &sz, MEM_RELEASE);
    } __except (EXCEPTION_EXECUTE_HANDLER) { status = GetExceptionCode(); }
    if (att) KeUnstackDetachProcess(&apc);
    ObDereferenceObject(proc); return status;
}

NTSTATUS UnlinkReq(PUNLINK_VAD_REQ req) {
    PEPROCESS proc;
    NTSTATUS status = PsLookupProcessByProcessId(req->TargetPid, &proc);
    if (!NT_SUCCESS(status)) return status;
    __try { status = UnlinkVad(proc, (ULONG_PTR)req->RemoteBase, &req->OutStart, &req->OutEnd) ? STATUS_SUCCESS : STATUS_NOT_FOUND; }
    __except (EXCEPTION_EXECUTE_HANDLER) { status = GetExceptionCode(); }
    ObDereferenceObject(proc); return status;
}

NTSTATUS RelinkReq(PRELINK_VAD_REQ req) {
    PEPROCESS proc;
    NTSTATUS status = PsLookupProcessByProcessId(req->TargetPid, &proc);
    if (!NT_SUCCESS(status)) return status;
    __try { status = RelinkVad(proc, (ULONG_PTR)req->RemoteBase, req->InStart, req->InEnd) ? STATUS_SUCCESS : STATUS_NOT_FOUND; }
    __except (EXCEPTION_EXECUTE_HANDLER) { status = GetExceptionCode(); }
    ObDereferenceObject(proc); return status;
}

NTSTATUS Control(PDEVICE_OBJECT d, PIRP i) {
    UNREFERENCED_PARAMETER(d);
    NTSTATUS s = STATUS_INVALID_DEVICE_REQUEST;
    __try {
        if (!i) return s;
        PIO_STACK_LOCATION st = IoGetCurrentIrpStackLocation(i);
        if (!st) { i->IoStatus.Status = s; IoCompleteRequest(i, IO_NO_INCREMENT); return s; }
        ULONG code = st->Parameters.DeviceIoControl.IoControlCode;
        ULONG inLen = st->Parameters.DeviceIoControl.InputBufferLength;
        PVOID buf = i->AssociatedIrp.SystemBuffer;
        if (!buf) {
            i->IoStatus.Status = STATUS_INVALID_PARAMETER; i->IoStatus.Information = 0;
            IoCompleteRequest(i, IO_NO_INCREMENT); return STATUS_INVALID_PARAMETER;
        }
        switch (code) {
            case IOCTL_ALLOCATE_MEMORY: if (inLen >= sizeof(ALLOCATE_MEMORY_REQ)) { s = AllocMem((PALLOCATE_MEMORY_REQ)buf); if (NT_SUCCESS(s)) i->IoStatus.Information = sizeof(ALLOCATE_MEMORY_REQ); } else s = STATUS_INFO_LENGTH_MISMATCH; break;
            case IOCTL_WRITE_MEMORY: if (inLen >= sizeof(WRITE_MEMORY_REQ)) { s = WriteMem((PWRITE_MEMORY_REQ)buf); if (NT_SUCCESS(s)) i->IoStatus.Information = sizeof(WRITE_MEMORY_REQ); } else s = STATUS_INFO_LENGTH_MISMATCH; break;
            case IOCTL_READ_MEMORY: if (inLen >= sizeof(READ_MEMORY_REQ)) { s = ReadMem((PREAD_MEMORY_REQ)buf); if (NT_SUCCESS(s)) i->IoStatus.Information = sizeof(READ_MEMORY_REQ); } else s = STATUS_INFO_LENGTH_MISMATCH; break;
            case IOCTL_PROTECT_MEMORY: if (inLen >= sizeof(PROTECT_MEMORY_REQ)) { s = ProtMem((PPROTECT_MEMORY_REQ)buf); if (NT_SUCCESS(s)) i->IoStatus.Information = sizeof(PROTECT_MEMORY_REQ); } else s = STATUS_INFO_LENGTH_MISMATCH; break;
            case IOCTL_FREE_MEMORY: if (inLen >= sizeof(FREE_MEMORY_REQ)) { s = FreeMem((PFREE_MEMORY_REQ)buf); if (NT_SUCCESS(s)) i->IoStatus.Information = sizeof(FREE_MEMORY_REQ); } else s = STATUS_INFO_LENGTH_MISMATCH; break;
            case IOCTL_UNLINK_VAD: if (inLen >= sizeof(UNLINK_VAD_REQ)) { s = UnlinkReq((PUNLINK_VAD_REQ)buf); if (NT_SUCCESS(s)) i->IoStatus.Information = sizeof(UNLINK_VAD_REQ); } else s = STATUS_INFO_LENGTH_MISMATCH; break;
            case IOCTL_RELINK_VAD: if (inLen >= sizeof(RELINK_VAD_REQ)) { s = RelinkReq((PRELINK_VAD_REQ)buf); if (NT_SUCCESS(s)) i->IoStatus.Information = sizeof(RELINK_VAD_REQ); } else s = STATUS_INFO_LENGTH_MISMATCH; break;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { s = GetExceptionCode(); if (i) i->IoStatus.Information = 0; }
    if (i) { i->IoStatus.Status = s; IoCompleteRequest(i, IO_NO_INCREMENT); }
    return s;
}
