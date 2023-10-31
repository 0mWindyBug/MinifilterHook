
#include <fltKernel.h>
#include <dontuse.h>
#include <fltmgtr.h>
#include <ntdefs.h>
#include <restore_list.h>

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")


DWORD64 TargetDriverStart = 0;
ULONG TargetDriverSize = 0;

ULONG_PTR OperationStatusCtx = 1;

PRESTORE_NODE RestoreList = NULL;
PFLT_FILTER gFilterHandle;

#define PTDBG_TRACE_ROUTINES            0x00000001
#define PTDBG_TRACE_OPERATION_STATUS    0x00000002

ULONG gTraceFlags = 0;


#define PT_DBG_PRINT( _dbgLevel, _string )          \
    (FlagOn(gTraceFlags,(_dbgLevel)) ?              \
        DbgPrint _string :                          \
        ((int)0))

/*************************************************************************
    Prototypes
*************************************************************************/


// RESTORE LIST FUNCTIONS 


VOID SaveOrigCallback(PVOID AddrOfCallback, LONG64 Callback)
{
    PRESTORE_NODE NewNode = ExAllocatePoolWithTag(NonPagedPool, sizeof(RESTORE_NODE), 'Inst');
    if (NewNode)
    {
        NewNode->AddrOfCallback = AddrOfCallback;
        NewNode->Callback = Callback;
        NewNode->Next = NULL;
        if (RestoreList == NULL)
        {
            RestoreList = NewNode;
        }
        else
        {
            PRESTORE_NODE current = RestoreList;
            while (current->Next != NULL)
            {
                current = current->Next;
            }
            current->Next = NewNode;
        }
    }
}

VOID UnhookCallbacks()
{
    if (RestoreList)
    {
        PRESTORE_NODE current = RestoreList;
        while (current != NULL)
        {
            InterlockedExchange64(current->AddrOfCallback, current->Callback);
            current = current->Next;
        }
    }
    DbgPrint("[WdfltHook] Successfully Unhooked Callbacks!\n");
}


VOID CleanupRestoreList()
{
    if (RestoreList)
    {
        PRESTORE_NODE current = RestoreList;
        while (current != NULL)
        {
            ExFreePool(current);
            current = current->Next;
        }
    }

}











EXTERN_C_START

DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    );

NTSTATUS
WdfltHookInstanceSetup (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    );

VOID
WdfltHookInstanceTeardownStart (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    );

VOID
WdfltHookInstanceTeardownComplete (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    );

NTSTATUS
WdfltHookUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    );

NTSTATUS
WdfltHookInstanceQueryTeardown (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
WdfltHookPreOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

VOID
WdfltHookOperationStatusCallback (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
    _In_ NTSTATUS OperationStatus,
    _In_ PVOID RequesterContext
    );

FLT_POSTOP_CALLBACK_STATUS
WdfltHookPostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
WdfltHookPreOperationNoPostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

BOOLEAN
WdfltHookDoRequestOperationStatus(
    _In_ PFLT_CALLBACK_DATA Data
    );

EXTERN_C_END

//
//  Assign text sections for each routine.
//

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, WdfltHookUnload)
#pragma alloc_text(PAGE, WdfltHookInstanceQueryTeardown)
#pragma alloc_text(PAGE, WdfltHookInstanceSetup)
#pragma alloc_text(PAGE, WdfltHookInstanceTeardownStart)
#pragma alloc_text(PAGE, WdfltHookInstanceTeardownComplete)
#endif

//
//  operation registration
//

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {



    { IRP_MJ_OPERATION_END }
};



CONST FLT_REGISTRATION FilterRegistration = {

    sizeof( FLT_REGISTRATION ),         //  Size
    FLT_REGISTRATION_VERSION,           //  Version
    0,                                  //  Flags

    NULL,                               //  Context
    Callbacks,                          //  Operation callbacks

    WdfltHookUnload,                           //  MiniFilterUnload

    WdfltHookInstanceSetup,                    //  InstanceSetup
    WdfltHookInstanceQueryTeardown,            //  InstanceQueryTeardown
    WdfltHookInstanceTeardownStart,            //  InstanceTeardownStart
    WdfltHookInstanceTeardownComplete,         //  InstanceTeardownComplete

    NULL,                               //  GenerateFileName
    NULL,                               //  GenerateDestinationFileName
    NULL                                //  NormalizeNameComponent

};



NTSTATUS
WdfltHookInstanceSetup (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    )

{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );
    UNREFERENCED_PARAMETER( VolumeDeviceType );
    UNREFERENCED_PARAMETER( VolumeFilesystemType );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("WdfltHook!WdfltHookInstanceSetup: Entered\n") );

    return STATUS_SUCCESS;
}


NTSTATUS
WdfltHookInstanceQueryTeardown (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    )

{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("WdfltHook!WdfltHookInstanceQueryTeardown: Entered\n") );

    return STATUS_SUCCESS;
}


VOID
WdfltHookInstanceTeardownStart (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )

{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("WdfltHook!WdfltHookInstanceTeardownStart: Entered\n") );
}


VOID
WdfltHookInstanceTeardownComplete (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )

{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("WdfltHook!WdfltHookInstanceTeardownComplete: Entered\n") );
}


/*************************************************************************
    MiniFilter initialization and unload routines.
*************************************************************************/
PCHAR GetNameFromFullName(PCHAR FullName) {
    SIZE_T FullNameLength = strlen(FullName);

    for (SIZE_T i = FullNameLength; i > 0; i--) {
        if (*(FullName + i) == '\\') {
            return FullName + i + 1;
        }
    }

    return NULL;
}

BOOLEAN IsCallbackNode(PCALLBACK_NODE PotentialCallbackNode, PFLT_INSTANCE FltInstance, DWORD64 DriverStartAddr, DWORD64 DriverSize) {
    // take the range of the driver instead of enumerating the driver every validation
    return ((PotentialCallbackNode->Instance == FltInstance) &&
        (DWORD64)PotentialCallbackNode->PreOperation > DriverStartAddr &&
        (DWORD64)PotentialCallbackNode->PreOperation < (DriverStartAddr + DriverSize) &&
        (DWORD64)PotentialCallbackNode->PostOperation > DriverStartAddr &&
        (DWORD64)PotentialCallbackNode->PostOperation < (DriverStartAddr + DriverSize));
}

PVOID InitDriverGlobals()
{
    PVOID LocalIntBase = NULL;
    PRTL_PROCESS_MODULES ModuleInformation = NULL;
    NTSTATUS result; 
    ULONG SizeNeeded;
    SIZE_T InfoRegionSize;
    BOOL output = FALSE;
    PROTOTYPE_ZWQUERYSYSTEMINFORMATION ZwQuerySystemInformation;
    UNICODE_STRING ZQSIname;
    // Get addr of zqsi
    RtlInitUnicodeString(&ZQSIname, L"ZwQuerySystemInformation");
    ZwQuerySystemInformation = (PROTOTYPE_ZWQUERYSYSTEMINFORMATION)MmGetSystemRoutineAddress(&ZQSIname);
    // Get info size 
    result = ZwQuerySystemInformation((SYSTEM_INFORMATION_CLASS)0x0B, NULL, 0, &SizeNeeded);
    if (result != 0xC0000004)
    {
        return NULL;
    }
    InfoRegionSize = SizeNeeded;
    // Get Info 
    while (result == 0xC0000004)
    {
        InfoRegionSize += 0x1000;
        ModuleInformation = (PRTL_PROCESS_MODULES)ExAllocatePool(NonPagedPoolNx, InfoRegionSize);
        if (ModuleInformation == NULL)
        {
            return NULL;
        }
        result = ZwQuerySystemInformation((SYSTEM_INFORMATION_CLASS)0x0B, (PVOID)ModuleInformation, (ULONG)InfoRegionSize, &SizeNeeded);
        if (!NT_SUCCESS(result))
        {
            return NULL;
        }
        // Enumerate through loaded drivers
        for (DWORD i = 0; i < ModuleInformation->NumberOfModules; i++)
        {
            if (!strcmp(GetNameFromFullName((PCHAR)ModuleInformation->Modules[i].FullPathName), "WdFilter.sys"))
            {
                TargetDriverStart = (DWORD64)ModuleInformation->Modules[i].ImageBase;
                TargetDriverSize = ModuleInformation->Modules[i].ImageSize;
                DbgPrint("[WdfltHook] Init Target Driver : Start at %llx , Size is %d \n", TargetDriverStart, TargetDriverSize);
            }
        }




    }
    ExFreePool(ModuleInformation);
    return (PVOID)TargetDriverStart;
}

NTSTATUS HookTargetFilter(PCWSTR FilterName)
{
    SIZE_T NumBytesReadFromInst = 0;
    PFLT_INSTANCE* InstanceList = NULL;
    ULONG InstanceListSize = 0;
    ULONG NumberOfInstancesReturned = 0;
    NTSTATUS status = STATUS_SUCCESS;
    UNICODE_STRING filterName;
    RtlInitUnicodeString(&filterName, FilterName);
    PFLT_FILTER fltobj = NULL;
    if (NT_SUCCESS(FltGetFilterFromName(&filterName, &fltobj)))
    {
        DbgPrint("[WdfltHook] Found Target Filter Object!\n");
        status = FltEnumerateInstances(NULL, fltobj, InstanceList, InstanceListSize, &NumberOfInstancesReturned);
        if (status == STATUS_BUFFER_TOO_SMALL || status == STATUS_BUFFER_OVERFLOW)
        {
            InstanceListSize = sizeof(PFLT_INSTANCE) * NumberOfInstancesReturned;
            InstanceList = ExAllocatePoolWithTag(PagedPool, InstanceListSize, 'Inst');
            if (InstanceList)
            {
                status = FltEnumerateInstances(NULL, fltobj, InstanceList, InstanceListSize, &NumberOfInstancesReturned);
                if (NT_SUCCESS(status))
                {
                    DbgPrint("[WdfltHook] Enumerating Target Filter Object Instances!\n");
                    for (ULONG i = 0; i < NumberOfInstancesReturned; i++)
                    {
                        PFLT_INSTANCE CurrentInstance = InstanceList[i];
                        DbgPrint("[WdfltHook] Instance at : %llx!\n", (PVOID)CurrentInstance);
                        PCALLBACK_NODE TargetCallbackNode = NULL;
                        // Copy Instance Memory 
                        DbgPrint("[WdfltHook] Reading Instance %d Memory!", i+1);
                        PFLT_INSTANCE CurrentInstanceVA = ExAllocatePoolWithTag(NonPagedPool, 0x230, 'Inst');
                        MM_COPY_ADDRESS addrToRead;
                        addrToRead.VirtualAddress = CurrentInstance;
                        status = MmCopyMemory((PVOID)CurrentInstanceVA, addrToRead, 0x230, MM_COPY_MEMORY_VIRTUAL, &NumBytesReadFromInst);
                        if (!NT_SUCCESS(status))
                        {
                            DbgPrint("[WdfltHook] Failed to read instance memory!\n", i + 1);
                            ExFreePoolWithTag(CurrentInstanceVA, 'Inst');
                            break;
                        }
                        else
                        {
                            // Scan for callback node 
                            for (ULONG x = 0; x < 0x230; x++)
                            {
                                DWORD64 PotentialPointer = *(PDWORD64)((DWORD64)CurrentInstanceVA + x);
                                PCALLBACK_NODE PotentialNode = (PCALLBACK_NODE)PotentialPointer;
                                if (MmIsAddressValid((PVOID)PotentialPointer))
                                {
                                    if (IsCallbackNode(PotentialNode, CurrentInstance, TargetDriverStart, TargetDriverSize))
                                    {

                                         DbgPrint("[WdfltHook] Found CallbackNode of %ws : Node %llx Pre: %llx Post: %llx !\n", FilterName,PotentialNode, PotentialNode->PreOperation, PotentialNode->PostOperation);
                                         if (MmIsAddressValid(PotentialNode->PreOperation))
                                         {
                                             SaveOrigCallback(&PotentialNode->PreOperation, PotentialNode->PreOperation);
                                             InterlockedExchange64(&PotentialNode->PreOperation, WdfltHookPreOperation);
                                         }
                                         if (MmIsAddressValid(PotentialNode->PostOperation))
                                         {
                                             SaveOrigCallback(&PotentialNode->PostOperation, PotentialNode->PostOperation);
                                             InterlockedExchange64(&PotentialNode->PostOperation, WdfltHookPostOperation);
                                         }
                                    }
                                }
                            }
                        }
                    }
                }
                ExFreePoolWithTag(InstanceList, 'Inst');
            }
            else
            {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
        }
        FltObjectDereference(fltobj);
    }
    else
    {
        status = STATUS_UNSUCCESSFUL;
    }

    return status;
}



NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )

{
    NTSTATUS status;

    UNREFERENCED_PARAMETER( RegistryPath );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("WdfltHook!DriverEntry: Entered\n") );


    status = FltRegisterFilter( DriverObject,
                                &FilterRegistration,
                                &gFilterHandle );

    FLT_ASSERT( NT_SUCCESS( status ) );

    if (NT_SUCCESS( status )) {

        status = FltStartFiltering( gFilterHandle );

        if (!NT_SUCCESS( status )) {

            FltUnregisterFilter( gFilterHandle );
        }
    }
    InitDriverGlobals();
    HookTargetFilter(L"WdFilter");
    return status;
}

NTSTATUS
WdfltHookUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    )

{
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("WdfltHook!WdfltHookUnload: Entered\n") );
    UnhookCallbacks();
    CleanupRestoreList();
    FltUnregisterFilter( gFilterHandle );

    return STATUS_SUCCESS;
}

// Pre Operation hook 
FLT_PREOP_CALLBACK_STATUS
WdfltHookPreOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )

{
    NTSTATUS status;

    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );

    if (WdfltHookDoRequestOperationStatus( Data )) {

        status = FltRequestOperationStatusCallback( Data,
                                                    WdfltHookOperationStatusCallback,
                                                    (PVOID)(++OperationStatusCtx) );
        if (!NT_SUCCESS(status)) {

            PT_DBG_PRINT( PTDBG_TRACE_OPERATION_STATUS,
                          ("WdfltHook!WdfltHookPreOperation: FltRequestOperationStatusCallback Failed, status=%08x\n",
                           status) );
        }
    }

    DbgPrint("[WdfltHook] Hooked pre operation!\n");

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}



VOID
WdfltHookOperationStatusCallback (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
    _In_ NTSTATUS OperationStatus,
    _In_ PVOID RequesterContext
    )

{
    UNREFERENCED_PARAMETER( FltObjects );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("WdfltHook!WdfltHookOperationStatusCallback: Entered\n") );

    PT_DBG_PRINT( PTDBG_TRACE_OPERATION_STATUS,
                  ("WdfltHook!WdfltHookOperationStatusCallback: Status=%08x ctx=%p IrpMj=%02x.%02x \"%s\"\n",
                   OperationStatus,
                   RequesterContext,
                   ParameterSnapshot->MajorFunction,
                   ParameterSnapshot->MinorFunction,
                   FltGetIrpName(ParameterSnapshot->MajorFunction)) );
}


FLT_POSTOP_CALLBACK_STATUS
WdfltHookPostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    )

{
    UNREFERENCED_PARAMETER( Data );
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );
    UNREFERENCED_PARAMETER( Flags );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("WdfltHook!WdfltHookPostOperation: Entered\n") );
    DbgPrint("[WdfltHook] Hooked post operation!\n"); 
    return FLT_POSTOP_FINISHED_PROCESSING;
}


FLT_PREOP_CALLBACK_STATUS
WdfltHookPreOperationNoPostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )

{
    UNREFERENCED_PARAMETER( Data );
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("WdfltHook!WdfltHookPreOperationNoPostOperation: Entered\n") );


    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


BOOLEAN
WdfltHookDoRequestOperationStatus(
    _In_ PFLT_CALLBACK_DATA Data
    )

{
    PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;



    return (BOOLEAN)



             (((iopb->MajorFunction == IRP_MJ_FILE_SYSTEM_CONTROL) &&
               ((iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_FILTER_OPLOCK)  ||
                (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_BATCH_OPLOCK)   ||
                (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_1) ||
                (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_2)))

              ||

              ((iopb->MajorFunction == IRP_MJ_DIRECTORY_CONTROL) &&
               (iopb->MinorFunction == IRP_MN_NOTIFY_CHANGE_DIRECTORY))
             );
}
