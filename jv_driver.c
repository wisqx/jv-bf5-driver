#include <ntifs.h>
#include <ntddk.h>
#include "shared/shared.h"

static const ULONG64 OFF_DTB = 0x28;

typedef struct _JV_BF5_PACKET {
    UINT32 Pid;
    UINT32 Pad;
    UINT64 Va;
    UINT64 Size;
} JV_BF5_PACKET, *PJV_BF5_PACKET;

static PVOID JvMapPhys(UINT64 phys) {
    PHYSICAL_ADDRESS pa; pa.QuadPart = phys & ~0xFFFULL;
    return MmMapIoSpaceEx(pa, PAGE_SIZE, PAGE_READWRITE);
}
static void JvUnmapPhys(PVOID p) { if (p) MmUnmapIoSpace(p, PAGE_SIZE); }

static BOOLEAN JvReadPhysU64(UINT64 phys, PUINT64 out) {
    PVOID m = JvMapPhys(phys); if (!m) return FALSE;
    *out = *(PUINT64)((PUINT8)m + (phys & 0xFFF));
    JvUnmapPhys(m); return TRUE;
}

static UINT64 JvVaToPhys(UINT64 cr3, UINT64 va) {
    UINT64 e;
    if (!JvReadPhysU64((cr3 & ~0xFFFULL) + ((va >> 39) & 0x1FF) * 8, &e) || !(e & 1)) return 0;
    if (!JvReadPhysU64((e & 0x000FFFFFFFFFF000ULL) + ((va >> 30) & 0x1FF) * 8, &e) || !(e & 1)) return 0;
    if (!JvReadPhysU64((e & 0x000FFFFFFFFFF000ULL) + ((va >> 21) & 0x1FF) * 8, &e) || !(e & 1)) return 0;
    if (e & (1ULL << 7)) return (e & 0x000FFFFFFFE00000ULL) | (va & 0x1FFFFF);
    if (!JvReadPhysU64((e & 0x000FFFFFFFFFF000ULL) + ((va >> 12) & 0x1FF) * 8, &e) || !(e & 1)) return 0;
    return (e & 0x000FFFFFFFFFF000ULL) | (va & 0xFFF);
}

static BOOLEAN JvCopyPhys(UINT64 phys, PVOID buf, SIZE_T n, BOOLEAN write) {
    PUINT8 b = buf;
    while (n) {
        UINT64 off = phys & 0xFFF; SIZE_T chunk = PAGE_SIZE - off; if (chunk > n) chunk = n;
        PVOID m = JvMapPhys(phys); if (!m) return FALSE;
        if (write) RtlCopyMemory((PUINT8)m + off, b, chunk);
        else       RtlCopyMemory(b, (PUINT8)m + off, chunk);
        JvUnmapPhys(m); b += chunk; phys += chunk; n -= chunk;
    }
    return TRUE;
}

static BOOLEAN JvReadProcessVa(UINT64 cr3, UINT64 va, PVOID dst, SIZE_T n) {
    PUINT8 b = dst;
    while (n) {
        UINT64 pa = JvVaToPhys(cr3, va); if (!pa) return FALSE;
        SIZE_T chunk = PAGE_SIZE - (va & 0xFFF); if (chunk > n) chunk = n;
        if (!JvCopyPhys(pa, b, chunk, FALSE)) return FALSE;
        b += chunk; va += chunk; n -= chunk;
    }
    return TRUE;
}

// ФУНКЦИЯ СКРЫТИЯ ДРАЙВЕРА ИЗ СИСТЕМЫ (ОТ JAVELIN)
static VOID JvHideDevice(PDEVICE_OBJECT dev) {
    PLIST_ENTRY entry = dev->DeviceObject;
    if (entry && entry->Flink && entry->Blink) {
        entry->Blink->Flink = entry->Flink;
        entry->Flink->Blink = entry->Blink;
        // Обнуляем ссылки, чтобы никто не нашел
        entry->Flink = entry->Blink = NULL;
    }
}

static NTSTATUS JvIoctl(PDEVICE_OBJECT dev, PIRP irp) {
    UNREFERENCED_PARAMETER(dev);
    PIO_STACK_LOCATION s = IoGetCurrentIrpStackLocation(irp);
    NTSTATUS st = STATUS_INVALID_PARAMETER;

    if (s->Parameters.DeviceIoControl.IoControlCode == IOCTL_JV_GET_BASE) {
        UINT32 pid = *(UINT32*)irp->AssociatedIrp.SystemBuffer;
        PEPROCESS eproc = NULL;
        if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &eproc))) {
            PPEB peb = PsGetProcessPeb(eproc);
            if (peb) {
                UINT64 cr3 = *(PUINT64)((PUINT8)eproc + OFF_DTB);
                UINT64 base = 0;
                if (JvReadProcessVa(cr3, (UINT64)peb + 0x10, &base, 8)) {
                    *(UINT64*)irp->AssociatedIrp.SystemBuffer = base;
                    st = STATUS_SUCCESS;
                }
            }
            ObDereferenceObject(eproc);
        }
        irp->IoStatus.Information = (st == STATUS_SUCCESS) ? 8 : 0;
    } 
    else {
        PJV_BF5_PACKET p = (PJV_BF5_PACKET)s->Parameters.DeviceIoControl.Type3InputBuffer;
        if (p && s->Parameters.DeviceIoControl.InputBufferLength >= sizeof(JV_BF5_PACKET)) {
            __try {
                ProbeForRead(p, sizeof(JV_BF5_PACKET), 1);
                PEPROCESS eproc = NULL;
                if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)p->Pid, &eproc))) {
                    UINT64 cr3 = *(PUINT64)((PUINT8)eproc + OFF_DTB);
                    PUINT8 ub = (PUINT8)irp->UserBuffer; SIZE_T n = (SIZE_T)p->Size;
                    ProbeForWrite(ub, n, 1);
                    if (JvReadProcessVa(cr3, p->Va, ub, n)) st = STATUS_SUCCESS;
                    ObDereferenceObject(eproc);
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) { st = GetExceptionCode(); }
        }
    }

    irp->IoStatus.Status = st;
    IoCompleteRequest(irp, IO_NO_INCREMENT); return st;
}

static NTSTATUS JvPass(PDEVICE_OBJECT d, PIRP irp) {
    UNREFERENCED_PARAMETER(d); irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0; IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT drv, PUNICODE_STRING reg) {
    UNREFERENCED_PARAMETER(reg);
    UNICODE_STRING devName, symName;
    RtlInitUnicodeString(&devName, JV_DEVICE_NAME);
    RtlInitUnicodeString(&symName, JV_SYM_NAME);
    
    PDEVICE_OBJECT dev = NULL;
    NTSTATUS st = IoCreateDevice(drv, 0, &devName, FILE_DEVICE_UNKNOWN, 0, FALSE, &dev);
    if (!NT_SUCCESS(st)) return st;
    
    // Создаем симлинк, чтобы клиент мог подключиться, но потом прячем сам девайс
    IoCreateSymbolicLink(&symName, &devName);
    
    // ПРЯЧЕМ ДЕВАЙС ОТ АНТИЧИТА
    JvHideDevice(dev);

    drv->MajorFunction[IRP_MJ_CREATE] = JvPass;
    drv->MajorFunction[IRP_MJ_CLOSE]  = JvPass;
    drv->MajorFunction[IRP_MJ_DEVICE_CONTROL] = JvIoctl;
    drv->DriverUnload = NULL;
    return STATUS_SUCCESS;
}