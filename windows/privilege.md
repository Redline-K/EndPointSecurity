# 1. OLA提权
## 1.1. OpenProcessToken(O)
``` c++
BOOL OpenProcessToken(
  HANDLE  ProcessHandle, //要修改访问权限的进程句柄
  DWORD   DesiredAccess, //指定你要进行的操作类型，如要修改令牌我们要指定第二个参数为TOKEN_ADJUST_PRIVILEGES
  PHANDLE TokenHandle    //返回的访问令牌指针
);
```

## 1.2. LookupPrivilegeValueA(L)
``` c++
BOOL LookupPrivilegeValueA(
  LPCSTR lpSystemName,  //系统的名称，如果是本地系统只要指明为NULL就可以了
  LPCSTR lpName,        //指明了权限的名称，如“SeDebugPrivilege”
  PLUID  lpLuid         //返回LUID的指针
);
```

## 1.3. AdjustTokenPrivileges(A)
``` c++
BOOL AdjustTokenPrivileges(
  HANDLE            TokenHandle,           //访问令牌的句柄
  BOOL              DisableAllPrivileges,  //决定是进行权限修改还是除能（Disable）所有权限
  PTOKEN_PRIVILEGES NewState,              //指明要修改的权限，是一个指向TOKEN_PRIVILEGES结构的指针，该结构包含一个数组，数据组的每个项指明了权限的类型和要进行的操作
  DWORD             BufferLength,          //结构PreviousState的长度，如果PreviousState为空，该参数应为NULL
  PTOKEN_PRIVILEGES PreviousState,         //也是一个指向TOKEN_PRIVILEGES结构的指针，存放修改前的访问权限的信息，可空
  PDWORD            ReturnLength           //为实际PreviousState结构返回的大小
);

typedef struct _TOKEN_PRIVILEGES {
  DWORD               PrivilegeCount;              //指的数组原素的个数
  LUID_AND_ATTRIBUTES Privileges[ANYSIZE_ARRAY];   //一个LUID_AND_ATTRIBUTES类型的数组
} TOKEN_PRIVILEGES, *PTOKEN_PRIVILEGES;



typedef struct _LUID_AND_ATTRIBUTES {
  LUID  Luid;              //权限的类型，是一个LUID的值
  DWORD Attributes;        //指明了要进行的操作类型，有三个可选项：SE_PRIVILEGE_ENABLED、SE_PRIVILEGE_ENABLED_BY_DEFAULT、SE_PRIVILEGE_USED_FOR_ACCESS
} LUID_AND_ATTRIBUTES, *PLUID_AND_ATTRIBUTES;
```

# 2. RtlAdjustPrivilege
``` c++
NTSTATUS RtlAdjustPrivilege
(
    ULONG Privilege,   // 所需要的权限名称，可以到MSDN查找关于Process Token & Privilege内容可以查到
    BOOLEAN Enable,    // 如果为True 就是打开相应权限，如果为False 则是关闭相应权限
    BOOLEAN CurrentThread,  // 如果为True 则仅提升当前线程权限，否则提升整个进程的权限
    PBOOLEAN Enabled   // 输出原来相应权限的状态（打开 | 关闭）
)

int __stdcall RtlAdjustPrivilege(int Privilege, bool Enable, char CurrentThread, int *Enabled)
{
  int result; // eax
  int v5; // esi
  int isEnabled; // [esp+8h] [ebp-2Ch] BYREF
  HANDLE TokenHandle; // [esp+Ch] [ebp-28h] BYREF
  int OldState[3]; // [esp+10h] [ebp-24h] BYREF
  int v9; // [esp+1Ch] [ebp-18h]
  int NewState; // [esp+20h] [ebp-14h] BYREF
  int dwPrivilege; // [esp+24h] [ebp-10h]
  int v12; // [esp+28h] [ebp-Ch]
  int v13; // [esp+2Ch] [ebp-8h]

  if ( CurrentThread == 1 )
    result = NtOpenThreadToken(-2, 40, 0, &TokenHandle);
  else
    result = ZwOpenProcessToken(-1, 40, &TokenHandle);
  if ( result >= 0 )
  {
    dwPrivilege = Privilege;
    NewState = 1;
    v12 = 0;
    v13 = Enable ? 2 : 0;
    v5 = ZwAdjustPrivilegesToken((int)TokenHandle, 0, (int)&NewState, 16, (int)OldState, (int)&isEnabled);
    NtClose(TokenHandle);
    if ( v5 == 0x106 )
      v5 = 0xC0000061;
    if ( v5 >= 0 )
    {
      if ( OldState[0] )
        *(_BYTE *)Enabled = (v9 & 2) != 0;      // 其实就是(OldState.Privileges[0].Attributes & SE_PRIVILEGE_ENABLED)
      else
        *(_BYTE *)Enabled = Enable;
    }
    result = v5;
  }
  return result;
}
```

# 3. 参考文献
1.https://mp.weixin.qq.com/s/NkJOfiRIBnqyzVh3_fE22Q