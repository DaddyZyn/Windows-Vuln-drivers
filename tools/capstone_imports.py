SUSPICIOUS_IMPORTS = [
    # physical memory / MMIO
    "MmMapIoSpace", "MmMapIoSpaceEx", "MmUnmapIoSpace",
    "ZwMapViewOfSection", "ZwOpenSection", "MmGetPhysicalMemoryRanges",
    "MmGetPhysicalAddress", "MmCopyVirtualMemory",
    # process/token
    "PsLookupProcessByProcessId", "PsReferencePrimaryToken",
    "ZwOpenProcess", "ZwOpenThread", "PsSetCreateProcessNotifyRoutine",
    # DSE / callbacks
    "HalDispatchTable", "KeServiceDescriptorTable", "MmGetSystemRoutineAddress",
    "PsSetLoadImageNotifyRoutine", "CmRegisterCallback", "ObRegisterCallbacks",
    # memory alloc / mdl
    "ExAllocatePool", "MmProbeAndLockPages", "MmMapLockedPages",
    "MmBuildMdlForNonPagedPool", "ProbeForRead", "ProbeForWrite",
    # MSR / port IO (kernel prims)
    "HalSetBusDataByOffset", "HalGetBusDataByOffset",
    "ZwSetValueKey", "ZwDeleteKey", "ZwCreateKey",
    # primitive enablers
    "IoCreateDevice", "IoCreateSymbolicLink", "RtlCopyMemory", "KeSetSystemAffinityThread",
    "NtQuerySystemInformation", "ObReferenceObjectByHandle", "IoCreateFile",
]
