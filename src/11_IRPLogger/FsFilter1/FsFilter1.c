/*++

Module Name:

	FsFilter1.c

Abstract:

	This is the main module of the FsFilter1 miniFilter driver.

Environment:

	Kernel mode

--*/

#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>

// NOTE: Naming convention followed
//   Prefix V_M_ for global macros
//   Prefix V_   for global variables
//   Prefix M    for global function
//   Prefix Sss  for pre-operation and post-operation callbacks

// #define V_M_MAX_FILE_PATH_LENGTH 265
#define V_M_MAX_FILE_PATH_LENGTH 330

NTSTATUS MiniUnload(FLT_FILTER_UNLOAD_FLAGS);
NTSTATUS MGetFileName(PFLT_CALLBACK_DATA, PCFLT_RELATED_OBJECTS, PUNICODE_STRING);
FLT_PREOP_CALLBACK_STATUS SssPreCreate(PFLT_CALLBACK_DATA, PCFLT_RELATED_OBJECTS, PVOID*);
FLT_PREOP_CALLBACK_STATUS SssPreRead(PFLT_CALLBACK_DATA, PCFLT_RELATED_OBJECTS, PVOID*);
FLT_PREOP_CALLBACK_STATUS SssPreWrite2(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext);
FLT_PREOP_CALLBACK_STATUS SssPreWrite(PFLT_CALLBACK_DATA, PCFLT_RELATED_OBJECTS, PVOID*);
FLT_PREOP_CALLBACK_STATUS SssPreOperationCounter(PFLT_CALLBACK_DATA, PCFLT_RELATED_OBJECTS, PVOID*);
FLT_POSTOP_CALLBACK_STATUS SssPostCreate(PFLT_CALLBACK_DATA, PCFLT_RELATED_OBJECTS, PVOID*, FLT_POST_OPERATION_FLAGS);

PFLT_FILTER FilterHandle = NULL;

const FLT_OPERATION_REGISTRATION Callbacks[] = {
	// {IRP_MJ_CREATE, 0, SssPreCreate, SssPostCreate},
	{IRP_MJ_CREATE, 0, SssPreCreate, NULL},
	{IRP_MJ_READ, 0, SssPreRead, NULL},    // use NULL if we do not want to register a callback
	{IRP_MJ_WRITE, 0, SssPreWrite2, NULL},  // use NULL if we do not want to register a callback
	{IRP_MJ_OPERATION_END}  // this is always the last member so that windows knows that this is end of the structure array
};

const FLT_REGISTRATION FilterRegistration = {
	sizeof(FLT_REGISTRATION),  // Size of this structure
	FLT_REGISTRATION_VERSION,  // Filter registration version
	0,           // Flag
	NULL,        // Context registration number
	Callbacks,   // Register operation callbacks
	MiniUnload,  // Register filter unload function
	NULL,        // InstanceSetup
	NULL,        // InstanceQueryTeardown
	NULL,        // InstanceTeardownStart
	NULL,        // InstanceTeardownComplete
	NULL,        // GenerateFileName
	NULL,        // GenerateDestinationFileName
	NULL,        // NormalizeNameComponent
	NULL         // KTM notification callback
};

// ---------------------------------------------------------------------------------------------------------------------------
// ---------------------------------------------------------------------------------------------------------------------------
// ---------------------------------------------------------------------------------------------------------------------------



// Entry function
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	// We do not need to register the unload function in this DriverObject
	NTSTATUS status;

	KdPrint(("Registering the driver...\r\n"));

	// Register ourselves to the filter manager
	status = FltRegisterFilter(DriverObject, &FilterRegistration, &FilterHandle);
	if (!NT_SUCCESS(status)) {
		// Filter registration FAILED
		KdPrint(("Filter registration failed\r\n"));
		return status;
	}

	// Filter registration SUCCESSFUL
	KdPrint(("Filter registration successful\r\n"));

	// Start Filtering
	status = FltStartFiltering(FilterHandle);

	if (!NT_SUCCESS(status)) {
		// FAILED to start filtering
		// Unregister the filter
		KdPrint(("Failed to start filtering\r\n"));
		FltUnregisterFilter(FilterHandle);
		return status;
	}

	KdPrint(("Successfully started filtering\r\n"));
	KdPrint(("Filter Driver successfully registered and started filtering :)\r\n"));
	return status;
}



NTSTATUS MiniUnload(FLT_FILTER_UNLOAD_FLAGS Flags) {
	KdPrint(("Driver unloading...\r\n"));
	FltUnregisterFilter(FilterHandle);
	return STATUS_SUCCESS;
}



NTSTATUS MGetFileName(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PUNICODE_STRING FinalFilePath) {
	static INT16 recordTracker = 0;
	INT16 currRecord = recordTracker++;
	NTSTATUS status;
	UNICODE_STRING DriveLetter;
	PFLT_FILE_NAME_INFORMATION FileNameInfo;
	PWCHAR ProperFileNameStart;
	INT16 ProperFileNameLenBytes;

	FinalFilePath->Length = 0;

	// NOTE: FltObjects->FileObject->FileName can only be used in "IRP_MJ_CREATE"

	// REFER: https://github.com/microsoft/Windows-driver-samples/blob/master/filesys/miniFilter/minispy/filter/minispy.c#L667
	if (FltObjects->FileObject == NULL) {
		//  Can't get a name when there's no file object
		return STATUS_UNSUCCESSFUL;
	}

	// Step 1: Retrieve the Drive Letter

	// Get Drive letter from Device Name
	// REFER: https://comp.os.ms-windows.programmer.nt.kernel-mode.narkive.com/vvQtO73m/device-name-to-dos-name
	// 	   subsection link: https://narkive.com/vvQtO73m:7.539.23
	// REFER: https://stackoverflow.com/questions/15459501/full-file-path-with-drive-letter
	status = IoVolumeDeviceToDosName(FltObjects->FileObject->DeviceObject, &DriveLetter);
	if (NT_SUCCESS(status)) {
		// REFER: https://en.cppreference.com/w/c/string/wide/wcsncpy
		// REFER: https://docs.microsoft.com/en-us/windows/win32/api/subauth/ns-subauth-unicode_string
		FinalFilePath->Length = DriveLetter.Length;
		if (DriveLetter.Buffer != NULL) {
			wcsncpy(FinalFilePath->Buffer, DriveLetter.Buffer, DriveLetter.Length / sizeof(WCHAR));
		} else {
			FinalFilePath->Buffer[0] = L'\0';
			// REFER: https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-iovolumedevicetodosname
			//   The docs say that DriveLetter.Buffer is only set if the call was successful
			// RtlFreeUnicodeString(&DriveLetter);
			return status;
		}
		// KdPrint(("[%d] GetFileN  [%d] : drive letter = '%ws' %d\r\n", __LINE__, currRecord, DriveLetter.Buffer, DriveLetter.Length));
		RtlFreeUnicodeString(&DriveLetter);
	} else if (status == STATUS_INVALID_DEVICE_REQUEST) {
		// KdPrint(("[%d] GetFileN  [%d] : drive letter = STATUS_INVALID_DEVICE_REQUEST\r\n", __LINE__, currRecord));
		return status;
	} else {
		// KdPrint(("[%d] GetFileN  [%d] : drive letter = error (%x) (%ld)\r\n", __LINE__, currRecord, status, status));
		return status;
	}

	// Step 2: Retrieve the File Name
	// REFER: https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/flt-file-name-options

	// REFER: https://github.com/microsoft/Windows-driver-samples/blob/master/filesys/miniFilter/minispy/filter/minispy.c#L664
	//        Tells why use "FLT_FILE_NAME_QUERY_DEFAULT" options
	//   NOTE: By default, we use the query method
	//   FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP
	//   because MiniSpy would like to get the name as much as possible, but
	//   can cope if we can't retrieve a name.  For a debugging type filter,
	//   like Minispy, this is reasonable, but for most production filters
	//   who need names reliably, they should query the name at times when it
	//   is known to be safe and use the query method
	//   FLT_FILE_NAME_QUERY_DEFAULT.
	status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &FileNameInfo);
	if (NT_SUCCESS(status)) {
		// REFER: https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltparsefilenameinformation
		// status = FltParseFileNameInformation(FileNameInfo);
		if (!NT_SUCCESS(status)) {
			KdPrint(("GetFileN  : [%d]: [%d]: ERROR (%x) (%ld) PARSING file name information\r\n", __LINE__, currRecord, status, status));
			// return status;  // TODO: check if we always release FileInfo or not. If NOT, then remove "goto" and uncomment this statement
			// REFER: https://github.com/microsoft/Windows-driver-samples/blob/master/filesys/miniFilter/minispy/filter/minispy.c#L813
			//   We always release nameInfo, so ignore return value.
			goto l_clean_file_info;
		}
		// For -> FileNameInfo->Name.Buffer = "\Device\HarddiskVolume2\Windows\System32\drivers\FsFilter1.sys"
		//        FileNameInfo->Name.MaximumLength = 126  <---  2*63  <---  sizeof(WCHAR)*63
		if (FileNameInfo->Name.Buffer == NULL) {
			KdPrint(("GetFileN  : [%d]: [%d]: CRITICAL FileNameInfo->Name.Buffer is NULL, FileNameInfo->Name.Length = %d\r\n", __LINE__, currRecord, FileNameInfo->Name.Length));
			FinalFilePath->Length = 0;
			goto l_clean_file_info;
		}
		ProperFileNameStart = wcschr(FileNameInfo->Name.Buffer + 1, L'\\');
		if (ProperFileNameStart == NULL) {
			KdPrint(("GetFileN  : [%d]: [%d]: CRITICAL ProperFileNameStart is NULL on 1st search for \"\\\", FileNameInfo->Name.Buffer = \"%ws\"\r\n", __LINE__, currRecord, FileNameInfo->Name.Buffer));
			FinalFilePath->Length = 0;
			goto l_clean_file_info;
		}
		ProperFileNameStart = wcschr(ProperFileNameStart + 1, L'\\');
		if (ProperFileNameStart == NULL) {
			KdPrint(("GetFileN  : [%d]: [%d]: CRITICAL ProperFileNameStart is NULL on 2nd search for \"\\\", FileNameInfo->Name.Buffer = \"%ws\"\r\n", __LINE__, currRecord, FileNameInfo->Name.Buffer));
			goto l_SetFinalFilePathLenght;
			// FinalFilePath->Length = 0;
			// goto l_clean_file_info;
		}
		ProperFileNameLenBytes = FileNameInfo->Name.MaximumLength - sizeof(WCHAR) * (ProperFileNameStart - FileNameInfo->Name.Buffer);
		if ((FinalFilePath->Length + ProperFileNameLenBytes + 1) > FinalFilePath->MaximumLength) {
			KdPrint(("GetFileN  : [%d]: [%d]: WARNING Trimming File Path due to VERY HIGH FileNameInfo->Name.MaximumLength = %d\r\n", __LINE__, currRecord, FileNameInfo->Name.MaximumLength));
			ProperFileNameLenBytes = FinalFilePath->MaximumLength - FinalFilePath->Length - 1;
		}

		// REFER: https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlcopymemory
		RtlCopyMemory(FinalFilePath->Buffer + (FinalFilePath->Length / sizeof(WCHAR)), ProperFileNameStart, ProperFileNameLenBytes);
		FinalFilePath->Length += ProperFileNameLenBytes;

		l_SetFinalFilePathLenght:
			{
				FinalFilePath->Buffer[FinalFilePath->Length / sizeof(WCHAR)] = L'\0';
			}

		l_clean_file_info:
			{
				if (FileNameInfo != NULL)
					FltReleaseFileNameInformation(FileNameInfo);
			}
	} else {
		// KdPrint(("GetFileN  : [%d]: [%d]: error (%x) (%ld) GETTING file name information", __LINE__, currRecord, status, status));
		return status;
	}

	return STATUS_SUCCESS;
}



// REFER: https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-create
FLT_PREOP_CALLBACK_STATUS SssPreCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext) {
	static INT16 recordTrackerKernal = 0;
	static INT16 recordTracker = 0;
	INT16 currRecord = ++recordTracker;
	NTSTATUS status;
	WCHAR Name[V_M_MAX_FILE_PATH_LENGTH] = { 0 };
	UNICODE_STRING FinalFilePath;

	if (Data->RequestorMode == KernelMode) {
		// KdPrint(("Pre-CREATE: [%d]: [%d]: Request from Kernal Mode = %d\r\n", __LINE__, currRecord, ++recordTrackerKernal));
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	FinalFilePath.Buffer = Name;
	FinalFilePath.MaximumLength = V_M_MAX_FILE_PATH_LENGTH;

	/*
		0x1000000
		MEM_RESET_UNDO
		FO_REMOTE_ORIGIN
		ACCESS_SYSTEM_SECURITY

		0x200000
		FILE_OPEN_REPARSE_POINT
		FO_FILE_OPEN_CANCELLED
	*/

	// Retrieve the file name
	status = MGetFileName(Data, FltObjects, &FinalFilePath);
	if (NT_SUCCESS(status) && FinalFilePath.Length != 0) {
		// TODO: enforce the filter rules over here
		// if (MApplyFilterRules(&FinalFilePath)) {}
		// if (wcsstr(Name, L"dbgview_fm_") == NULL)
		//	KdPrint(("[%d] PreRead   [%d] file: %ws\r\n", __LINE__, currRecord, Name));

		// REFER: https://community.osr.com/discussion/254750/minifilter-how-to-identify-it-is-a-file-or-directory-in-pre-create
		// REFER: https://github.com/microsoft/Windows-driver-samples/blob/master/filesys/miniFilter/avscan/filter/avscan.c#L2010
		if (FlagOn(Data->Iopb->Parameters.Create.Options, FILE_DIRECTORY_FILE)) {
			KdPrint(("Pre-Create: [%d]: [%d]: open/create directory: %ws\r\n", __LINE__, currRecord, FinalFilePath.Buffer));
		} else {
			KdPrint(("Pre-Create: [%d]: [%d]: open/create file     : %ws\r\n", __LINE__, currRecord, FinalFilePath.Buffer));
			if (wcsstr(FinalFilePath.Buffer, L"32\\catroot") != NULL) {
				KdPrint(("Pre-Create: [%d]: [%d]: open/create file FLAG: %ld\r\n", __LINE__, currRecord, Data->Iopb->Parameters.Create.Options));
			}
		}
		if (wcsstr(FinalFilePath.Buffer, L"openme.txt") != NULL) {
			// Block the IO request
			KdPrint(("Pre-Create: [%d]: [%d]: (BLOCKED) file: %ws\r\n", __LINE__, currRecord, FinalFilePath.Buffer));
			Data->IoStatus.Status = STATUS_ACCESS_DENIED;
			// TODO: verify if below thing is to be executed or not
			// Since we blocked the IRP write operation, the real transferring size is 0
			// Data->IoStatus.Information = 0;
			return FLT_PREOP_COMPLETE;  // on seeing this return value, the filter manager will never pass this IRP down to the driver below us
		}
	}

	// This means that we have a post-operation callback to be called
	// return FLT_PREOP_SUCCESS_WITH_CALLBACK;

	// Post-Operation callback will NOT be called because "we do not want to call it" or "it does NOT exist"
	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}



// NOTE: IRP_MJ_MDL_READ_COMPLETE is for fast IO
// NOTE: automatically all drives of a Device are monitored
FLT_PREOP_CALLBACK_STATUS SssPreRead(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext) {
	static INT16 recordTrackerKernal = 0;
	static INT16 recordTracker = 0;
	INT16 currRecord = ++recordTracker;
	NTSTATUS status;
	WCHAR Name[V_M_MAX_FILE_PATH_LENGTH] = { 0 };
	UNICODE_STRING FinalFilePath;

	if (Data->RequestorMode == KernelMode) {
		// KdPrint(("Pre-READ  : [%d]: [%d]: Request from Kernal Mode = %d\r\n", __LINE__, currRecord, ++recordTrackerKernal));
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	FinalFilePath.Buffer = Name;
	FinalFilePath.MaximumLength = V_M_MAX_FILE_PATH_LENGTH;

	status = MGetFileName(Data, FltObjects, &FinalFilePath);
	if (NT_SUCCESS(status) && FinalFilePath.Length != 0) {
		// REFER: https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/strupr-strupr-l-mbsupr-mbsupr-l-wcsupr-l-wcsupr?view=msvc-160
		// _wcsupr(Name);  // if we have uppercase and lowercase character, then we always change this file name to uppercase
		// REFER: https://en.cppreference.com/w/c/string/wide/wcsstr
		// KdPrint(("[%d] PreRead   [%d] FinalFilePath->Buffer = %ws\r\n", __LINE__, currRecord, FinalFilePath.Buffer));
		// TODO: enforce the filter rules over here
		// if (MApplyFilterRules(&FinalFilePath)) {}
		// if (wcsstr(Name, L"dbgview_fm_") == NULL)
			KdPrint(("Pre-READ  : [%d]: [%d]: file = \"%ws\"\r\n", __LINE__, currRecord, Name));
		if (wcsstr(FinalFilePath.Buffer, L"openme.txt") != NULL) {
			// Block the IO request
			KdPrint(("Pre-READ  : [%d]: [%d]: (BLOCKED) file = \"%ws\"\r\n", __LINE__, currRecord, Name));
			Data->IoStatus.Status = STATUS_ACCESS_DENIED;
			// since we blocked the IRP write operation, the real transferring size is 0
			Data->IoStatus.Information = 0;
			return FLT_PREOP_COMPLETE;  // on seeing this return value, the filter manager will never pass this IRP down to the driver below us
		}
	}

	// Post-Operation callback will NOT be called because "we do not want to call it" or "it does NOT exist"
	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


FLT_PREOP_CALLBACK_STATUS SssPreWrite2(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext) {
	static INT16 recordTrackerKernal = 0;
	static INT16 recordTracker = 0;
	INT16 currRecord = ++recordTracker;
	NTSTATUS status;
	WCHAR Name[V_M_MAX_FILE_PATH_LENGTH] = { 0 };
	UNICODE_STRING FinalFilePath;

	if (Data->RequestorMode == KernelMode) {
		// KdPrint(("Pre-WRITE : [%d]: [%d]: Request from Kernal Mode = %d\r\n", __LINE__, currRecord, ++recordTrackerKernal));
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	FinalFilePath.Buffer = Name;
	FinalFilePath.MaximumLength = V_M_MAX_FILE_PATH_LENGTH;

	status = MGetFileName(Data, FltObjects, &FinalFilePath);
	if (NT_SUCCESS(status) && FinalFilePath.Length != 0) {
		// REFER: https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/strupr-strupr-l-mbsupr-mbsupr-l-wcsupr-l-wcsupr?view=msvc-160
		// _wcsupr(Name);  // if we have uppercase and lowercase character, then we always change this file name to uppercase
		// REFER: https://en.cppreference.com/w/c/string/wide/wcsstr
		// KdPrint(("[%d] PreRead   [%d] FinalFilePath->Buffer = %ws\r\n", __LINE__, currRecord, FinalFilePath.Buffer));
		// TODO: enforce the filter rules over here
		// if (MApplyFilterRules(&FinalFilePath)) {}
		// if (wcsstr(Name, L"dbgview_fm_") == NULL)
			KdPrint(("Pre-WRITE : [%d]: [%d]: file = \"%ws\"\r\n", __LINE__, currRecord, Name));
		if (wcsstr(FinalFilePath.Buffer, L"openme.txt") != NULL) {
			// Block the IO request
			KdPrint(("Pre-WRITE : [%d]: [%d]: (BLOCKED) file = \"%ws\"\r\n", __LINE__, currRecord, Name));
			Data->IoStatus.Status = STATUS_ACCESS_DENIED;
			// since we blocked the IRP write operation, the real transferring size is 0
			Data->IoStatus.Information = 0;
			return FLT_PREOP_COMPLETE;  // on seeing this return value, the filter manager will never pass this IRP down to the driver below us
		}
	}

	// Post-Operation callback will NOT be called because "we do not want to call it" or "it does NOT exist"
	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


// NOTE: automatically all drives of a Device are monitored
FLT_PREOP_CALLBACK_STATUS SssPreWrite(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext) {
	static INT16 recordTracker = 0;
	static INT16 recordTrackerKernal = 0;
	INT16 currRecord = recordTracker++;
	NTSTATUS status;
	WCHAR Name[260] = { 0 };
	UNICODE_STRING DriveLetter;
	PFLT_FILE_NAME_INFORMATION FileNameInfo;
	int ErrorDriveLetterAndNameInfo = 0;

	if (Data->RequestorMode == KernelMode) {
		// KdPrint(("Pre-WRITE : [%d]: [%d]: Request from Kernal Mode = %d\r\n", __LINE__, currRecord, ++recordTrackerKernal));
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	// TODO: load rules from CSV file
	// REFER: https://stackoverflow.com/questions/1976007/what-characters-are-forbidden-in-windows-and-linux-directory-names
		// Forward slash is the best separator "/"
	// REFER: https://docs.microsoft.com/en-us/windows/win32/fileio/naming-a-file#file-and-directory-names
		// In editions of Windows before Windows 10 version 1607, the maximum length for a path is MAX_PATH, which is defined as 260 characters

	// TODO: get PID and Process Name
	// REFER: https://titanwolf.org/Network/Articles/Article?AID=6b92cc8a-84ef-4025-80fa-90fb3ddfb988#gsc.tab=0
	// REFER: https://community.osr.com/discussion/173162/how-to-identify-process-that-is-opening-a-file-from-within-a-mini-filter
		// IoGetRequestorProcessId()
	// REFER: https://community.osr.com/discussion/141561/getting-parents-parent-process-information-in-minifilter-driver
		// To get parent of any process
	// REFER: https://stackoverflow.com/questions/24701561/current-process-handle-strange-macros
		// NtCurrentProcess();
		// GetCurrentProcessId();

	// TODO: handle deletion
	// REFER: https://community.osr.com/discussion/184259/how-does-a-directory-folder-get-removed-by-minifilter

	// TODO: get Drive letter from Device Name
	// REFER: https://comp.os.ms-windows.programmer.nt.kernel-mode.narkive.com/vvQtO73m/device-name-to-dos-name
	// 	   subsection link: https://narkive.com/vvQtO73m:7.539.23
	// REFER: https://stackoverflow.com/questions/15459501/full-file-path-with-drive-letter

	status = IoVolumeDeviceToDosName(FltObjects->FileObject->DeviceObject, &DriveLetter);
	if (NT_SUCCESS(status)) {
		KdPrint(("Pre-WRITE : [%d]: [%d]: drive letter = \"%ws\"\r\n", __LINE__, currRecord, DriveLetter.Buffer));
		RtlFreeUnicodeString(&DriveLetter);
	} else if (status == STATUS_INVALID_DEVICE_REQUEST) {
		KdPrint(("Pre-WRITE : [%d]: [%d]: drive letter = STATUS_INVALID_DEVICE_REQUEST\r\n", __LINE__, currRecord));
	} else {
		KdPrint(("Pre-WRITE : [%d]: [%d]: drive letter = error status = %x , %ld\r\n", __LINE__, currRecord, status, status));
		ErrorDriveLetterAndNameInfo |= 1;
	}
	// Retrieve the file name
	status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &FileNameInfo);
	if (NT_SUCCESS(status)) {
		status = FltParseFileNameInformation(FileNameInfo);
		if (NT_SUCCESS(status)) {
			if (FileNameInfo->Name.MaximumLength < 260) {
				RtlCopyMemory(Name, FileNameInfo->Name.Buffer, FileNameInfo->Name.MaximumLength);
				// REFER: https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/strupr-strupr-l-mbsupr-mbsupr-l-wcsupr-l-wcsupr?view=msvc-160
				// _wcsupr(Name);  // if we have uppercase and lowercase character, then we always change this file name to uppercase
				// REFER: https://en.cppreference.com/w/c/string/wide/wcsstr
				if (wcsstr(Name, L"openme.txt") != NULL) {
					// Block the IO request
					KdPrint(("Pre-WRITE : [%d]: [%d]: (BLOCKED) file: \"%ws\"\r\n", __LINE__, currRecord, Name));
					Data->IoStatus.Status = STATUS_ACCESS_DENIED;
					// since we blocked the IRP write operation, the real transferring size is 0
					Data->IoStatus.Information = 0;
					FltReleaseFileNameInformation(FileNameInfo);
					return FLT_PREOP_COMPLETE;  // on seeing this return value, the filter manager will never pass this IRP down to the driver below us
				}
				if (wcsstr(Name, L"dbgview_fm_") == NULL)
					KdPrint(("Pre-WRITE : [%d]: [%d]: file: \"%ws\"\r\n", __LINE__, currRecord, Name));
			}
		} else {
			KdPrint(("Pre-WRITE : [%d]: [%d]: error status = %x , %ld , error PARSING file name information", __LINE__, currRecord, status, status));
		}
		FltReleaseFileNameInformation(FileNameInfo);
	} else {
		KdPrint(("Pre-WRITE : [%d]: [%d]: error %x , %ld , error GETTING file name information\r\n", __LINE__, currRecord, status, status));
		ErrorDriveLetterAndNameInfo |= 2;
	}
	if (ErrorDriveLetterAndNameInfo == 1) {
		KdPrint(("Pre-WRITE : [%d]: [%d]: WARNING only single ERROR %d\r\n", __LINE__, currRecord, ErrorDriveLetterAndNameInfo));
	}

	// Post-Operation callback will NOT be called because "we do not want to call it" or "it does NOT exist"
	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}



// NOTE: IRP_MJ_MDL_READ_COMPLETE is for fast IO
// NOTE: automatically all drives of a Device are monitored
FLT_PREOP_CALLBACK_STATUS SssPreOperationCounter(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext) {
	static INT16 recordTrackerKernal = 0;
	static INT16 recordTracker = 0;
	INT16 currRecord = recordTracker++;

	if (Data->RequestorMode == KernelMode) {
		++recordTrackerKernal;
		KdPrint(("currRecord = %d, Kernal Mode Calls = %d, Diff = %d\r\n", currRecord, recordTrackerKernal, currRecord - recordTrackerKernal));
	} else {
		KdPrint(("currRecord = %d\r\n", currRecord));
	}

	// TODO: get PID
	// REFER: https://community.osr.com/discussion/137962
	// procid = PsGetCurrentProcessId();
	// peproc = PsGetCurrentProcess();
	// pImageName = PsGetProcessImageFileName(peproc);

	// This means that we have a post-operation callback to be called
	// return FLT_PREOP_SUCCESS_WITH_CALLBACK;

	// Post-Operation callback will NOT be called because "we do not want to call it" or "it does NOT exist"
	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}



// NOTE: this is never executed :)
FLT_POSTOP_CALLBACK_STATUS SssPostCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext, FLT_POST_OPERATION_FLAGS Flags) {
	KdPrint(("Post-CREATE: [%d]: post OPEN/CREATE is running\r\n", __LINE__));
	return FLT_POSTOP_FINISHED_PROCESSING;
}
