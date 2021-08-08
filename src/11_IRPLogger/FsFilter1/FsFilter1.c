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


NTSTATUS MiniUnload(FLT_FILTER_UNLOAD_FLAGS);
FLT_PREOP_CALLBACK_STATUS SssPreCreate(PFLT_CALLBACK_DATA, PCFLT_RELATED_OBJECTS, PVOID*);
FLT_PREOP_CALLBACK_STATUS SssPreRead(PFLT_CALLBACK_DATA, PCFLT_RELATED_OBJECTS, PVOID*);
FLT_PREOP_CALLBACK_STATUS SssPreWrite(PFLT_CALLBACK_DATA, PCFLT_RELATED_OBJECTS, PVOID*);
FLT_POSTOP_CALLBACK_STATUS SssPostCreate(PFLT_CALLBACK_DATA, PCFLT_RELATED_OBJECTS, PVOID*, FLT_POST_OPERATION_FLAGS);

PFLT_FILTER FilterHandle = NULL;

const FLT_OPERATION_REGISTRATION Callbacks[] = {
	// {IRP_MJ_CREATE, 0, SssPreCreate, SssPostCreate},
	{IRP_MJ_READ, 0, SssPreRead, NULL},  // use NULL if we do not want to register a callback
	{IRP_MJ_WRITE, 0, SssPreWrite, NULL},  // use NULL if we do not want to register a callback
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

/*NTSTATUS MGetFileName(PFLT_CALLBACK_DATA Data) {
	NTSTATUS status;
	PFLT_FILE_NAME_INFORMATION FileNameInfo;

	// Retrieve the file name
	// REFER: https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/flt-file-name-options
	status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP, &FileNameInfo);
	if (!NT_SUCCESS(status)) return status;
	
}*/

// REFER: https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-create
FLT_PREOP_CALLBACK_STATUS SssPreCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext) {
	NTSTATUS status;
	WCHAR Name[260] = { 0 };
	PFLT_FILE_NAME_INFORMATION FileNameInfo;

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
	status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &FileNameInfo);
	if (NT_SUCCESS(status)) {
		status = FltParseFileNameInformation(FileNameInfo);
		if (NT_SUCCESS(status)) {
			if (FileNameInfo->Name.MaximumLength < 260) {
				RtlCopyMemory(Name, FileNameInfo->Name.Buffer, FileNameInfo->Name.MaximumLength);
				// REFER: https://community.osr.com/discussion/254750/minifilter-how-to-identify-it-is-a-file-or-directory-in-pre-create
				// REFER: https://github.com/microsoft/Windows-driver-samples/blob/master/filesys/miniFilter/avscan/filter/avscan.c#L2010
				if (FlagOn(Data->Iopb->Parameters.Create.Options, FILE_DIRECTORY_FILE)) {
					KdPrint(("Pre OPEN/CREATE directory: %ws\r\n", Name));
				} else {
					KdPrint(("Pre OPEN/CREATE file     : %ws\r\n", Name));
					if (wcsstr(Name, L"32\\catroot") != NULL) {
						KdPrint(("Pre OPEN/CREATE file FLAG: %ld\r\n", Data->Iopb->Parameters.Create.Options));
					}
				}
			}
		}
		FltReleaseFileNameInformation(FileNameInfo);
	}

	// This means that we have a post-operation
	// callback to be called
	// return FLT_PREOP_SUCCESS_WITH_CALLBACK;
	return FLT_PREOP_SUCCESS_NO_CALLBACK;  // ---> No post - operation callback will never be called
}

// NOTE: IRP_MJ_MDL_READ_COMPLETE is for fast IO
// NOTE: automatically all drives of a Device are monitored
FLT_PREOP_CALLBACK_STATUS SssPreRead(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext) {
	static int recordTracker = 0;
	int currRecord = recordTracker++;
	NTSTATUS status;
	PWCHAR ProperFileNameStart;
	WCHAR Name[260+5] = { 0 };
	UNICODE_STRING FinalFilePath;
	UNICODE_STRING DriveLetter;
	PFLT_FILE_NAME_INFORMATION FileNameInfo;
	int ErrorDriveLetterAndNameInfo = 0;
	if (currRecord % 1000) return FLT_PREOP_SUCCESS_NO_CALLBACK;

	// TODO: get Drive letter from Device Name
	// REFER: https://comp.os.ms-windows.programmer.nt.kernel-mode.narkive.com/vvQtO73m/device-name-to-dos-name
	// 	   subsection link: https://narkive.com/vvQtO73m:7.539.23
	// REFER: https://stackoverflow.com/questions/15459501/full-file-path-with-drive-letter
	FinalFilePath.Buffer = Name;
	FinalFilePath.Length = 0;
	FinalFilePath.MaximumLength = 260+5;
	
	status = IoVolumeDeviceToDosName(FltObjects->FileObject->DeviceObject, &DriveLetter);
	if (NT_SUCCESS(status)) {
		// REFER: https://en.cppreference.com/w/c/string/wide/wcsncpy
		// REFER: https://docs.microsoft.com/en-us/windows/win32/api/subauth/ns-subauth-unicode_string
		FinalFilePath.Length = DriveLetter.Length;
		if (DriveLetter.Buffer != NULL)
			wcsncpy(FinalFilePath.Buffer, DriveLetter.Buffer, DriveLetter.Length / sizeof(WCHAR));
		KdPrint(("Pre READ  [%d] : drive letter = '%ws' %d\r\n", currRecord, DriveLetter.Buffer, DriveLetter.Length));
		RtlFreeUnicodeString(&DriveLetter);
	} else if (status == STATUS_INVALID_DEVICE_REQUEST) {
		KdPrint(("Pre READ  [%d] : drive letter = STATUS_INVALID_DEVICE_REQUEST\r\n", currRecord));
	} else {
		KdPrint(("Pre READ  [%d] : drive letter = error %x %ld\r\n", currRecord, status, status));
		ErrorDriveLetterAndNameInfo |= 1;
	}
	// Retrieve the file name
	// REFER: https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/flt-file-name-options
	status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP, &FileNameInfo);
	if (NT_SUCCESS(status)) {
		status = FltParseFileNameInformation(FileNameInfo);
		if (NT_SUCCESS(status)) {
			if (FileNameInfo->Name.MaximumLength < 260) {
				// For FileNameInfo->Name.Buffer = "\Device\HarddiskVolume2\Windows\System32\drivers\FsFilter1.sys"
				// FileNameInfo->Name.MaximumLength = 126  <---  2*63  <---  sizeof(WCHAR)*63
				ProperFileNameStart = wcschr(wcschr(FileNameInfo->Name.Buffer + 1, L'\\') + 1, L'\\');
				FinalFilePath.MaximumLength = FileNameInfo->Name.MaximumLength - sizeof(WCHAR) * (ProperFileNameStart - FileNameInfo->Name.Buffer);
				// REFER: https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlcopymemory
				RtlCopyMemory(FinalFilePath.Buffer + (FinalFilePath.Length / sizeof(WCHAR)), ProperFileNameStart, FinalFilePath.MaximumLength);
				FinalFilePath.Length += FinalFilePath.MaximumLength;
				FinalFilePath.MaximumLength = 265;
				FinalFilePath.Buffer[FinalFilePath.Length / sizeof(WCHAR)] = L'\0';
				// REFER: https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/strupr-strupr-l-mbsupr-mbsupr-l-wcsupr-l-wcsupr?view=msvc-160
				// _wcsupr(Name);  // if we have uppercase and lowercase character, then we always change this file name to uppercase
				// REFER: https://en.cppreference.com/w/c/string/wide/wcsstr
				KdPrint(("Pre READ  [%d] FinalFilePath.Buffer = %ws\r\n", currRecord, FinalFilePath.Buffer));
				KdPrint(("Pre READ  [%d] FileNameInfo->Name.MaximumLength = %d\r\n", currRecord, FileNameInfo->Name.MaximumLength));
				if (wcsstr(FinalFilePath.Buffer, L"openme.txt") != NULL) {
					// Block the IO request
					KdPrint(("Pre READ  [%d] (BLOCKED) file: %ws\r\n", currRecord, Name));
					Data->IoStatus.Status = STATUS_ACCESS_DENIED;
					// since we blocked the IRP write operation, the real transferring size is 0
					Data->IoStatus.Information = 0;
					FltReleaseFileNameInformation(FileNameInfo);
					return FLT_PREOP_COMPLETE;  // on seeing this return value, the filter manager will never pass this IRP down to the driver below us
				}
				if (wcsstr(Name, L"dbgview_fm_") == NULL)
					KdPrint(("Pre READ  [%d] file: %ws\r\n", currRecord, Name));
			}
		} else {
			KdPrint(("Pre READ  [%d]: error %x %ld PARSING file name information", currRecord, status, status));
		}
		FltReleaseFileNameInformation(FileNameInfo);
	} else {
		KdPrint(("Pre READ  [%d]: error %x %ld GETTING file name information", currRecord, status, status));
		ErrorDriveLetterAndNameInfo |= 2;
	}
	if (ErrorDriveLetterAndNameInfo == 1) {
		KdPrint(("Pre READ  [%d]: WARNING only single ERROR %d", currRecord, ErrorDriveLetterAndNameInfo));
	}

	// This means that we have NO post-operation
	// callback to be called
	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


// NOTE: automatically all drives of a Device are monitored
FLT_PREOP_CALLBACK_STATUS SssPreWrite(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext) {
	static int recordTracker = 0;
	int currRecord = recordTracker++;
	NTSTATUS status;
	WCHAR Name[260] = { 0 };
	UNICODE_STRING DriveLetter;
	PFLT_FILE_NAME_INFORMATION FileNameInfo;
	int ErrorDriveLetterAndNameInfo = 0;
	if (currRecord % 1000) return FLT_PREOP_SUCCESS_NO_CALLBACK;

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
		KdPrint(("Pre WRITE [%d] : drive letter = '%ws'\r\n", currRecord, DriveLetter.Buffer));
		RtlFreeUnicodeString(&DriveLetter);
	} else if (status == STATUS_INVALID_DEVICE_REQUEST) {
		KdPrint(("Pre WRITE [%d] : drive letter = STATUS_INVALID_DEVICE_REQUEST\r\n", currRecord));
	} else {
		KdPrint(("Pre WRITE [%d] : drive letter = error %x %ld", currRecord, status, status));
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
					KdPrint(("Pre WRITE [%d] (BLOCKED) file: %ws\r\n", currRecord, Name));
					Data->IoStatus.Status = STATUS_ACCESS_DENIED;
					// since we blocked the IRP write operation, the real transferring size is 0
					Data->IoStatus.Information = 0;
					FltReleaseFileNameInformation(FileNameInfo);
					return FLT_PREOP_COMPLETE;  // on seeing this return value, the filter manager will never pass this IRP down to the driver below us
				}
				if (wcsstr(Name, L"dbgview_fm_") == NULL)
					KdPrint(("Pre WRITE [%d] file: %ws\r\n", currRecord, Name));
			}
		} else {
			KdPrint(("Pre WRITE [%d]: error %x %ld PARSING file name information", currRecord, status, status));
		}
		FltReleaseFileNameInformation(FileNameInfo);
	} else {
		KdPrint(("Pre WRITE [%d]: error %x %ld GETTING file name information", currRecord, status, status));
		ErrorDriveLetterAndNameInfo |= 2;
	}
	if (ErrorDriveLetterAndNameInfo == 1) {
		KdPrint(("Pre WRITE [%d]: WARNING only single ERROR %d", currRecord, ErrorDriveLetterAndNameInfo));
	}

	// This means that we have NO post-operation
	// callback to be called
	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

// NOTE: this is never executed :)
FLT_POSTOP_CALLBACK_STATUS SssPostCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext, FLT_POST_OPERATION_FLAGS Flags) {
	KdPrint(("Post OPEN/CREATE is running\r\n"));
	return FLT_POSTOP_FINISHED_PROCESSING;
}
