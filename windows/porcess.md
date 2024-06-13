# 1.依赖
## 1.1. OpenProcess
``` c++
HANDLE WINAPI OpenProcess (
  DWORD   dwDesiredAccess,  // 指定所得句柄具有的访问权限
  BOOL    bInheritHandle,    // 是否可被继承
  DWORD   dwProcessId    // 指定要打开的进程ID
);

OpenProcess(PROCESS_ALL_ACCESS, FALSE, ulTargetProcessID);
```

## 1.2. VirtualAllocEx
``` c++
LPVOID WINAPI VirtualAllocEx (
  HANDLE   hProcess,          // 目标进程句柄
  LPVOID  lpAddress,          // 期望的起始地址，通常置为NULL
  SIZE_T  dwSize,            // 需分配的内存大小
  DWORD    flAllocationType,       // 分配内存空间的类型，取 MEM_COMMIT
  DWORD   flProtect    // 内存访问权限，指定PAGE_READWRITE/PAGE_EXECUTE_READWRITE
);
``` 

## 1.3. WriteProcessMemory
``` c++
BOOL WINAPI WriteProcessMemory (
  HANDLE    hProcess,             // 目标进程句柄
  LPVOID    lpBaseAddress,           // 目标进程内存空间地址，也就是待写入字符串的地址(目的地址)
  LPCVOID   lpBuffer,             // 原存放字符串的地址(源地址)
  SIZE_T    nSize,       // 需写入数据字节数
  SIZE_T    *lpNumberOfBytesWritten   // 实际写入的字节数，设置为 NULL
);
```

# 2. 远程线程注入
## 2.1.CreateRemoteThread
``` c++
HANDLE WINAPI CreateRemoteThread (
  HANDLE                  hProcess,          // 远程进程句柄
  LPSECURITY_ATTRIBUTES    lpThreadAttributes,  // 线程的安全属性，通常为NULL
  SIZE_T                  dwStackSize,    // 线程栈的大小，通常为0
  LPTHREAD_START_ROUTINE  lpStartAddress,         // 线程入口函数的起始地址
  LPVOID                  lpParameter,     // 传递给线程函数的参数
  DWORD                   dwCreationFlags,  // 线程是否立即启动，通常为0
  LPDWORD                 lpThreadId    // 用于保存内核分配给线程的ID，，通常为NULL
);

WaitForSingleObject(ThreadHandle, INFINITE);    
```

## 2.2. NtCreateThreadEx
``` c++
NTSYSAPI 
NTSTATUS
NTAPI

NtCreateThread(
  OUT PHANDLE             ThreadHandle,
  IN ACCESS_MASK          DesiredAccess,
  IN POBJECT_ATTRIBUTES   ObjectAttributes OPTIONAL,
  IN HANDLE               ProcessHandle,
  OUT PCLIENT_ID          ClientId,
  IN PCONTEXT             ThreadContext,
  IN PINITIAL_TEB         InitialTeb,
  IN BOOLEAN              CreateSuspended );
```

## 2.3. RtlCreateUserThread
``` c++
NTSYSAPI 
NTSTATUS
NTAPI

RtlCreateUserThread(
  IN HANDLE               ProcessHandle,
  IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
  IN BOOLEAN              CreateSuspended,
  IN ULONG                StackZeroBits,
  IN OUT PULONG           StackReserved,
  IN OUT PULONG           StackCommit,
  IN PVOID                StartAddress,
  IN PVOID                StartParameter OPTIONAL,
  OUT PHANDLE             ThreadHandle,
  OUT PCLIENT_ID          ClientID );
```

# 3. 已有线程劫持
## 3.1. 从进程快照中获取已存在线程列表
``` c++
HANDLE CreateToolhelp32Snapshot(
  [in] DWORD dwFlags, //TH32CS_SNAPTHREAD
  [in] DWORD th32ProcessID
);

typedef struct tagTHREADENTRY32 {
　　DWORD dwSize; //指定结构的长度，以字节为单位。在调用Thread32First时，设置这个成员为SIZEOF（THREADENTRY32）。如果不初始化的dwSize，Thread32First将调用失败。
　　DWORD cntUsage; //这个成员已经不再被使用，总是设置为零。
　　DWORD th32ThreadID; //通过CreateProcess函数返回的兼容线程标示符
　　DWORD th32OwnerProcessID; /此线程所属进程的进程ID
　　LONG tpBasePri; //线程在内核中分配的优先级，tpBasePri值为0到31, 0为最低优先级
　　LONG tpDeltaPri; //这个成员已经不再被使用，总是设置为零。
　　DWORD dwFlags; //这个成员已经不再被使用，总是设置为零。
} THREADENTRY32, *PTHREADENTRY32;

BOOL Thread32First(
  [in]      HANDLE          hSnapshot,
  [in, out] LPTHREADENTRY32 lpte
);

BOOL Thread32Next(
  [in]  HANDLE          hSnapshot,
  [out] LPTHREADENTRY32 lpte
);
```

## 3.2. 选定线程打开
``` c++
HANDLE OpenThread(
  [in] DWORD dwDesiredAccess,
  [in] BOOL  bInheritHandle,
  [in] DWORD dwThreadId
);
```

## 3.3. 选定线程挂起
``` c++
DWORD SuspendThread(
  [in] HANDLE hThread
);
```

## 3.4. 获取选定线程上下文
``` c++
BOOL GetThreadContext(
  [in]      HANDLE    hThread,
  [in, out] LPCONTEXT lpContext
);
```

## 3.5. 设置选定线程上下文
``` c++
BOOL SetThreadContext(
  [in] HANDLE        hThread,
  [in] const CONTEXT *lpContext
);
```

## 3.6. 恢复选定线程运行
``` c++
DWORD ResumeThread(
  [in] HANDLE hThread
);
```

## 3.7. 线程上下文需要修改内容
``` c++
void __declspec(naked) InjectedFunction() {
    __asm {
        pushad //将所有寄存器的值保存下来
        push        11111111h; the DLL path argument
        mov         eax, 22222222h; the LoadLibraryA function address
        call        eax
        popad //恢复所有寄存器的值到之前的状态
        push        33333333h; the code to return to
        ret
    }
}
int main() {
    InjectedFunction();
    return 0;
}
```
"11111111h"、“22222222h”和“33333333h”用于占位

# 4. 创建进程挂起注入
## 4.1. 在已有进程安全上下文中创建新进程
``` c++
// ASCII 版本
BOOL CreateProcessA(
  LPCSTR                lpApplicationName, //指定可执行文件名和包含文件的完整目录，当省略掉目录的时候默认是用进程的工作目录来补全，而不会使用 PATH 变量搜索文件名。可执行文件必带有后缀名，不能省略
  LPSTR                 lpCommandLine, //该参数是包含最多32768个字符（结尾的空字符也算在内了）的命令行参数
  LPSECURITY_ATTRIBUTES lpProcessAttributes, //这个参数是指向SECURITY_ATTRIBUTES 结构体的指针，用来决定 CreateProcess 得到的进程句柄能否被子进程所继承，参数为 NULL 表示不允许继承。
  LPSECURITY_ATTRIBUTES lpThreadAttributes, //也是 SECURITY_ATTRIBUTES 结构的指针，和上一个参数类似，用于描述线程
  BOOL                  bInheritHandles, //子进程是否继承父进程中的可继承句柄，如果为TRUE则继承，为FALSE则不继承
  DWORD                 dwCreationFlags, //进程创建标志
  LPVOID                lpEnvironment, //进程环境块指针，如果该参数为 NULL 则子进程使用父进程的环境块
  LPCSTR                lpCurrentDirectory, //进程工作目录，该参数应该是进程当前目录的完整路径
  LPSTARTUPINFOA        lpStartupInfo, //指向 STARTUPINFO 或者 STARTUPINFOEX 结构体的指针
  LPPROCESS_INFORMATION lpProcessInformation //一个输出参数（由CreateProcess 函数负责填充），它是指向 PROCESS_INFORMATION 结构体的指针，该结构体包含子进程的身份信息
);
// UNICODE 版本
BOOL CreateProcessW(
  LPCWSTR               lpApplicationName,
  LPWSTR                lpCommandLine,
  LPSECURITY_ATTRIBUTES lpProcessAttributes,
  LPSECURITY_ATTRIBUTES lpThreadAttributes,
  BOOL                  bInheritHandles,
  DWORD                 dwCreationFlags,
  LPVOID                lpEnvironment,
  LPCWSTR               lpCurrentDirectory,
  LPSTARTUPINFOW        lpStartupInfo,
  LPPROCESS_INFORMATION lpProcessInformation
);

typedef struct _PROCESS_INFORMATION {
  HANDLE hProcess; //进程句柄
  HANDLE hThread; //线程句柄
  DWORD  dwProcessId; //进程ID
  DWORD  dwThreadId; //线程ID
} PROCESS_INFORMATION, *PPROCESS_INFORMATION, *LPPROCESS_INFORMATION;
```

# 5. APC注入
``` c++
DWORD QueueUserAPC(
  PAPCFUNC  pfnAPC, //指向一个用户提供的APC函数的指针,当线程处于alertable状态时回调
  HANDLE    hThread, //线程句柄，必须有THREAD_SET_CONTEXT 权限
  ULONG_PTR dwData //传递给回调函数的参数值
);
```


## 6. 参考
1、https://mp.weixin.qq.com/s/7lHqfWrewgiVtTXGhVXfQA
