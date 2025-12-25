---
title: "PIS_MiniCTF"
date: 2025-12-25T22:27:36+07:00
draft: false
tags: ["ctf", "re"]
categories: ["PIS_MiniCTF"]
contest: "PIS_MiniCTF"
author: "k1nt4r0u"
description: "Description: "
---

## Curse of Gabarca 

Sau khi sử dụng ida để disassemble chương trình, ta có hàm main như bên dưới

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  unsigned int v3; // eax
  char v4; // r12
  int i; // [rsp+10h] [rbp-60h]
  int j; // [rsp+14h] [rbp-5Ch]
  int k; // [rsp+18h] [rbp-58h]
  char *v9; // [rsp+20h] [rbp-50h]
  char *v10; // [rsp+28h] [rbp-48h]
  _BYTE s[40]; // [rsp+30h] [rbp-40h] BYREF
  unsigned __int64 v12; // [rsp+58h] [rbp-18h]

  v12 = __readfsqword(0x28u);
  v3 = time(0LL);
  srand(v3);
  rand();
  memset(s, 0, 0x23uLL);
  v9 = (char *)malloc(0x23uLL);
  memset(v9, 0, 0x23uLL);
  v10 = (char *)malloc(0x23uLL);
  memset(v10, 0, 0x23uLL);
  puts("Welcome to MiniCTF PIS 2025 !!!!");
  printf("Enter flag > ");
  __isoc99_scanf("%34s", v9);
  junk1();
  if ( strlen(v9) != 34 )
  {
LABEL_13:
    puts("Try again!");
    free(v9);
    free(v10);
    exit(0);
  }
  for ( i = 0; i <= 33; i += 2 )
  {
    v10[i] = v9[i + 1];
    v10[i + 1] = v9[i];
  }
  for ( j = 0; j < (int)strlen(v10); ++j )
  {
    v4 = v10[j];
    s[j] = key[j % strlen(key)] ^ v4;
  }
  junk2();
  shuffle(s, 0LL, 1LL);
  for ( k = 0; k <= 33; ++k )
  {
    if ( s[k] != (unsigned __int8)check[k] )
      goto LABEL_13;
  }
  puts("Congratulations! Gabarca was defeated!");
  free(v9);
  free(v10);
  return 0;
}
```

ta có thể thấy rằng ở bước đầu tiên input nhập vào được kiểm tra độ dài nếu đúng thì mang đi swap mỗi 2 ký tự liền kề với nhau sau đó lưu kết quả vào `v10`. Sau đó, từng byte của `v10` lại được đem đi xor với mỗi byte của key tại index `j % strlen(key)` rồi lưu lại vào `s` rồi reverse `s` lại sau đó kiểm tra với check đã được lưu, nếu trùng thì in ra message thành công không thì goto LABEL13, script:

```python
check = [0x5F, 0x09, 0x17, 0x11, 0x01, 0x51, 0x34, 0x4D, 0x11, 0x34, 0x47, 0x25, 0x41, 0x05, 0x3A, 0x37, 0x4D, 0x0B, 0x34, 0x37, 0x55, 0x07, 0x3C, 0x3C, 0x43, 0x0E, 0x2E, 0x05, 0x45, 0x3A, 0x21, 0x18, 0x35, 0x3A]
key = "secretkey"
check = check[::-1]
flag = [0]*34
decrypted = [0]*34
for i in range (len(check)):
    decrypted[i] = check[i] ^ ord(key[i % len(key)])
for i in range(0, len(decrypted), 2):
    if i + 1 < len(decrypted):
        flag[i] = decrypted[i + 1]
        flag[i + 1] = decrypted[i]
    else:
        flag[i] = decrypted[i]
for i in range (len(check)):
    print(chr(flag[i]), end='')
```

`PIS{1_Kn0w_Y0u_C4n_D3f3@t_G4b4rc4}`
## Return of Gabarca

Sau khi disasemble ra bằng ida, ta thấy chall này cũng là 1 flag checker như bài trước nhưng khó hơn xíu

```c
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  char s[104]; // [rsp+0h] [rbp-70h] BYREF
  unsigned __int64 v5; // [rsp+68h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  sub_11C9(a1, a2, a3);
  printf("Enter flag > ");
  if ( (unsigned int)__isoc99_scanf("%35s", s) == 1 )
  {
    if ( strlen(s) == 35 )
    {
      if ( (unsigned int)sub_127D(s) )
        puts("Correct!");
      else
        puts("Wrong");
      return 0LL;
    }
    else
    {
      puts("Wrong");
      return 1LL;
    }
  }
  else
  {
    puts("Input error!");
    return 1LL;
  }
}
```

hàm `main` gọi hàm `sub_11C9` để chuẩn bị và tạo các key để check flag, sau đó kiểm tra có input hay không rồi kiểm tra độ dài input nếu hợp lệ hết thì tiến hành gọi hàm `sub_127D` để check flag

```c
unsigned __int64 sub_11C9()
{
  int i; // [rsp+8h] [rbp-28h]
  int j; // [rsp+Ch] [rbp-24h]
  _DWORD *v3; // [rsp+10h] [rbp-20h]
  unsigned __int64 v4; // [rsp+1Fh] [rbp-11h]
  char v5; // [rsp+27h] [rbp-9h]
  unsigned __int64 v6; // [rsp+28h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  v3 = dword_40E0;
  for ( i = 0; i <= 65534; ++i )
    *v3++ = 3 * i + 1;
  v4 = 0x9F989A9887F9E3FALL;
  v5 = 0;
  for ( j = 0; j <= 7; ++j )
    byte_440E0[j] = *((_BYTE *)&v4 + j) ^ 0xAA;
  byte_440E8 = 0;
  return v6 - __readfsqword(0x28u);
}
```

hàm `sub_11C9` tạo 1 bảng tra cứu `dword_40E0` với công thức `y = 3x + 1` và tạo 1 key `byte_440E0` bằng cách đem `v4` xor với `0xAA` (PIS-2025)

```c
_BOOL8 __fastcall sub_127D(const char *a1)
{
  int v2; // [rsp+14h] [rbp-CCh]
  int i; // [rsp+18h] [rbp-C8h]
  int v4; // [rsp+1Ch] [rbp-C4h]
  int v5; // [rsp+20h] [rbp-C0h]
  int v6; // [rsp+24h] [rbp-BCh]
  unsigned int v7; // [rsp+28h] [rbp-B8h]
  int v8; // [rsp+2Ch] [rbp-B4h]
  int v9; // [rsp+30h] [rbp-B0h]
  int v10; // [rsp+34h] [rbp-ACh]
  int v11; // [rsp+38h] [rbp-A8h]
  int v12; // [rsp+3Ch] [rbp-A4h]
  _DWORD v13[38]; // [rsp+40h] [rbp-A0h]
  unsigned __int64 v14; // [rsp+D8h] [rbp-8h]

  v14 = __readfsqword(0x28u);
  v12 = strlen(a1);
  v2 = 1;
  for ( i = 0; i < v12; ++i )
  {
    v4 = 0;
    v5 = 0;
    v6 = 0;
    v7 = 0;
    v8 = 0;
    LOWORD(v9) = 0;
    v10 = 0;
    v11 = 0;
    while ( v11 != 7 )
    {
      switch ( v11 )
      {
        case 0:
          v4 = (unsigned __int8)a1[i] << 8;
          ++v11;
          break;
        case 1:
          v5 = v4 ^ byte_440E0[i % 8];
          ++v11;
          break;
        case 2:
          v6 = v5 ^ byte_440E0[i % 4];
          ++v11;
          break;
        case 3:
          v7 = v6 + 3210;
          ++v11;
          break;
        case 4:
          v8 = (unsigned __int16)((v7 >> 8) | ((_WORD)v7 << 8));
          ++v11;
          break;
        case 5:
          v9 = v8 ^ dword_40E0[byte_440E0[i % 3]];
          ++v11;
          break;
        case 6:
          v10 = dword_40E0[(unsigned __int16)v9];
          ++v11;
          break;
        default:
          continue;
      }
    }
    v13[i] = v10;
    v2 = (v13[i] == dword_4020[i]) & (unsigned __int8)v2;
  }
  return v2 == 1;
}
```

Để tiện giải thích thì mình sẽ gọi `c` là `a1[i]` , `key` là `byte_440E0` và `lut` là `dword_40E0`, switch case cũng được sử dụng để thực hiện biến đổi từng ký tự qua 7 bước:

1. `v4 = c << 8`
2. `v5 = v4 ^ key[i % 8]`
3. `v6 = v5 ^ key[i % 4]`
4. `v7 = v6 + 3210`
5. `v8 = bswap16(v7)` (swap 16 byte `(v7 >> 8) | (v7 << 8)`)
6. `v9 = v8 ^ lut[key[i % 3]]`
7. `v10 = lut[v9]` 

sau 7 bước kết quả cuối cùng là `v10` được lưu vào `v13` rồi and với `v2` đã được gán bằng 1, nếu có ký tự nào khác với `dword_4020` được lưu thì v2 sẽ bằng 0, vậy bước cuối cùng là viết script ngược từ bước 7 lên để lấy flag, script:

```python
#!/usr/bin/env python3

def bswap16(x):
    return ((x >> 8) | (x << 8)) & 0xFFFF

lut = [0] * 65535 
for i in range(65535):
    lut[i] = 3 * i + 1

key = [0x50, 0x49, 0x53, 0x2D, 0x32, 0x30, 0x32, 0x35]

dword_4020 = [
    0x1A008,0x19F9C,0x19FF0,0x19F63,0x2C5BA,0x0B56,0x2C2A2,
    0x1E80E,0x19F8D,0x1A014,0x19F15,0x19F90,0x2C695,0x0B11,
    0x2C2FC,0x1E814,0x1A017,0x1A02F,0x19FAE,0x1A01A,0x2C62F,
    0x0AD8,0x2C21E,0x1E82F,0x19FAB,0x1A026,0x19FFF,0x1A06B,
    0x2C60B,0x0B2F,0x2C338,0x1E715,0x1A050,0x19F84,0x19F00] 

flag_bytes = []
for i in range(35):
    target_v10 = dword_4020[i]
    v9 = (target_v10 - 1) // 3
    v9 &= 0xFFFF
    v8 = v9 ^ lut[key[i % 3]]
    v8 &= 0xFFFF
    v7 = bswap16(v8)
    v6 = (v7 - 3210) & 0xFFFF
    v5 = v6 ^ key[i % 4]
    v5 &= 0xFFFF
    v4 = v5 ^ key[i % 8]
    v4 &= 0xFFFF
    c = (v4 >> 8) & 0xFF
    flag_bytes.append(c)

print(bytes(flag_bytes).decode('utf-8'))

```

`PIS{C0ngr4ts!_G4b4rc4_w4s_D3f3@t3d}` 

## Step by step

Dùng ida để disassemble, ta được pseudocode như bên dưới

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  FILE *_File; // rax
  Stream *Stream_2; // rax
  Stream *Stream_1; // rax
  Stream *Stream; // rax
  char Buffer[264]; // [rsp+20h] [rbp-60h] BYREF
  __int64 v9; // [rsp+128h] [rbp+A8h]
  __int64 n32; // [rsp+130h] [rbp+B0h]
  size_t i_1; // [rsp+138h] [rbp+B8h]
  __int64 (__fastcall *v12)(char *, unsigned __int64); // [rsp+140h] [rbp+C0h]
  void *v13; // [rsp+148h] [rbp+C8h]
  SIZE_T dwSize; // [rsp+150h] [rbp+D0h]
  unsigned __int64 i; // [rsp+158h] [rbp+D8h]

  _main();
  dwSize = 218LL;
  v13 = VirtualAlloc(0LL, 0xDAuLL, 0x3000u, 0x40u);
  if ( v13 )
  {
    memcpy(v13, dracula, dwSize);
    v12 = (__int64 (__fastcall *)(char *, unsigned __int64))v13;
    printf("FLAG: ");
    Stream_2 = __acrt_iob_func(0);
    if ( fgets(Buffer, 256, Stream_2) )
    {
      i_1 = strcspn(Buffer, "\r\n");
      Buffer[i_1] = 0;
      n32 = 32LL;
      if ( i_1 == 32 )
      {
        for ( i = 1LL; i_1 >= i; ++i )
        {
          v9 = v12(Buffer, i);
          if ( v9 != pumpkin[i - 1] )
          {
            puts("Wrong flag !");
            return 1;
          }
        }
        puts("Correct !");
        return 0;
      }
      else
      {
        Stream = __acrt_iob_func(2u);
        fwrite("Invalid lenght!\n", 1uLL, 0x10uLL, Stream);
        return 1;
      }
    }
    else
    {
      Stream_1 = __acrt_iob_func(2u);
      fwrite("Invalid Input!\n", 1uLL, 0xFuLL, Stream_1);
      return 1;
    }
  }
  else
  {
    GetLastError();
    _File = __acrt_iob_func(2u);
    fprintf(_File, "VirtuaAlloc Failed.\n");
    return 1;
  }
}
```

phân tích kỹ ta thấy chương trình cấp phát bộ nhớ thực thi cho `v13` với kích thước là `218` cũng như quyền có thể đọc, ghi, và thực thi. Tiếp đến nó sao chép `218` bytes dữ liệu từ `dracula` vào vùng nhớ `v13` vừa được cấp phát rồi lại ép kiểu con trỏ `v13` đang trỏ tới dracula vào con trỏ hàm `v12`

kế tiếp chương trình đọc tối đa 256 byte từ người dùng rồi kiểm tra flag, nếu thỏa mãn các điều kiện thì tiến hành kiểm tra bằng for `i từ 1 đến 32` với `v9 = v12(Buffer, i)`, ở đây chương trình gọi shellcode từ v12 chính là từ `dracula` trước đó. Nếu có ký tự nào khác với pumpkin thì chương trình in ra "Wrong flag" và exit

```c 
unsigned __int64 __fastcall dracula(unsigned __int8 *a1, __int64 a2)
{
  unsigned __int8 *v2; // rax
  __int64 i; // [rsp+8h] [rbp-18h]
  unsigned __int64 v6; // [rsp+10h] [rbp-10h]
  unsigned __int64 v7; // [rsp+10h] [rbp-10h]

  v6 = 0xDEADC0DE13371337uLL;
  for ( i = 0x2510201825102025LL; a2--; i ^= v6 >> 17 )
  {
    v2 = a1++;
    v6 = 0x100000001B3LL * __ROL8__(i + (*v2 ^ v6), 13);
  }
  v7 = (((v6 >> 33) ^ v6 ^ 0xDEADBEEF13371337uLL) >> 29) ^ (v6 >> 33) ^ v6 ^ 0xDEADBEEF13371337uLL ^ 0x1234567891234567LL;
  return i ^ HIDWORD(v7) ^ v7;
}
```

script:

```python
pumpkin = [
    0x0F0456F7082ED4CAB, 0x009CE6CFC6A0F473D, 0x087C96F972F4A9A25, 0x0C249DD15F2224E36,
    0x0EAD0933D2AFFD845, 0x0A149C502A21A5C61, 0x0A9D87571E4B1BCA9, 0x093A668FE194E1A87,
    0x0DF8C82C26BFE59C1, 0x08F8B26F5119E8906, 0x030B8353426CD5CA3, 0x00237262A57526EBD,
    0x0871295B0F1536DE5, 0x0DE2EED1F9628E18A, 0x025317C1ADC00AD10, 0x0A8E9B46887916475,
    0x09D7AE1B6895B920D, 0x0D6BC2D74FC7B73E5, 0x051881EA39295F0EA, 0x0A8D38F9A5DF999C3,
    0x0535F9B4EE9239331, 0x005317386741A11DE, 0x0FC66567092DED24C, 0x06A2FF62E9A90D440,
    0x02CFF59F798074824, 0x0280C8B83924268C8, 0x03CC04963D6B701F9, 0x0EB5AF32C72D54C69,
    0x099509A1C8B12DD18, 0x056733C4E29F36A38, 0x06DC797479105F806, 0x09C208064CDD24693
]

def ROL8(val, n):
    return ((val << n) & 0xFFFFFFFFFFFFFFFF) | (val >> (64 - (n % 64)))

def dracula(buffer, length):
    v6 = 0xDEADC0DE13371337
    i_val = 0x2510201825102025
    for k in range(length):
        temp = (i_val + (buffer[k] ^ v6)) & 0xFFFFFFFFFFFFFFFF
        v6 = (0x100000001B3 * ROL8(temp, 13)) & 0xFFFFFFFFFFFFFFFF
        i_val = (i_val ^ (v6 >> 17)) & 0xFFFFFFFFFFFFFFFF
    v7_0 = (v6 >> 33) ^ v6 ^ 0xDEADBEEF13371337
    v7 = ((v7_0 >> 29) ^ (v6 >> 33) ^ v6 ^ 0xDEADBEEF13371337 ^ 0x1234567891234567) & 0xFFFFFFFFFFFFFFFF
    result = (i_val ^ (v7 >> 32) ^ v7) & 0xFFFFFFFFFFFFFFFF
    return result

flag = bytearray(32)
for i in range(1, 33):
    for char_code in range(256):
        flag[i-1] = char_code
        if dracula(flag, i) == pumpkin[i-1]:
            break

print(flag.decode('ascii'))

```

`PIS{H0w_t0_Cr4ck_H@sh_0M999!1!1}`

## Alice and the Haunted PE

Bài này cho ta 2 file là `REV2.exe` và importantLib.dll, phân tích cả 2 file bằng ida thì ta thầy `REV2.exe` import hàm `checkFlag` từ `importantLib.dll` thủ công

```c
int __stdcall WinMain(HINSTANCE hInst, HINSTANCE hPreInst, LPSTR lpszCmdLine, int nCmdShow)
{
  MSG Msg; // [rsp+60h] [rbp-90h] BYREF
  WNDCLASSEXA v6; // [rsp+90h] [rbp-60h] BYREF
  HWND hWnd; // [rsp+E8h] [rbp-8h]

  g_hInstance = hInst;
  g_hDll = LoadLibraryA("importantLib.dll");
  if ( g_hDll )
  {
    g_checkflag = (__int64 (__fastcall *)(_QWORD, _QWORD))GetProcAddress(g_hDll, "checkFlag");
    if ( g_checkflag )
    {
      v6.style = 0;
      *(_QWORD *)&v6.cbClsExtra = 0LL;
      v6.hIcon = 0LL;
      *(_OWORD *)&v6.hbrBackground = 0LL;
      v6.hIconSm = 0LL;
      v6.cbSize = 80;
      v6.lpfnWndProc = (WNDPROC)WndProc;
      v6.hInstance = hInst;
      v6.lpszClassName = "MiniCTFClass";
      v6.hCursor = LoadCursorA(0LL, (LPCSTR)0x7F00);
      v6.hbrBackground = (HBRUSH)6;
      if ( RegisterClassExA(&v6) )
      {
        hWnd = CreateWindowExA(
                 0,
                 v6.lpszClassName,
                 "MiniCTF PIS 2025",
                 0xCE0000u,
                 0x80000000,
                 0x80000000,
                 460,
                 180,
                 0LL,
                 0LL,
                 hInst,
                 0LL);
        if ( hWnd )
        {
          ShowWindow(hWnd, nCmdShow);
          UpdateWindow(hWnd);
          while ( GetMessageA(&Msg, 0LL, 0, 0) > 0 )
          {
            TranslateMessage(&Msg);
            DispatchMessageA(&Msg);
          }
          if ( g_hDll )
            FreeLibrary(g_hDll);
          return Msg.wParam;
        }
        else
        {
          MessageBoxA(0LL, "CreateWindowEX failed", "MiniCTF PISS", 0x10u);
          FreeLibrary(g_hDll);
          return 1;
        }
      }
      else
      {
        MessageBoxA(0LL, "RegisterClassEx failed", "MiniCTF PIS 2025", 0x10u);
        FreeLibrary(g_hDll);
        return 1;
      }
    }
    else
    {
      MessageBoxA(0LL, "Failed to export function", "MiniCTF PIS 2025", 0x10u);
      FreeLibrary(g_hDll);
      return 1;
    }
  }
  else
  {
    MessageBoxA(0LL, "[-] Failed to load DLL.", "MiniCTF PIS 2025", 0x10u);
    return 1;
  }
}
```

check hàm checkFlag trong importantLib.dll ta thấy nó check kết quả của phép xor `Suppersecret[i % 0xF]` và input với byte_180019890

```c
__int64 __fastcall checkFlag_0(__int64 a1, __int64 n34)
{
  unsigned __int64 i; // [rsp+68h] [rbp+48h]

  sub_1800112D5(&unk_180021004);
  if ( !a1 || n34 != 34 )
    return 0LL;
  for ( i = 0LL; i < 34; ++i )
  {
    if ( (unsigned __int8)(aSuppersecret[i % 0xF] ^ *(_BYTE *)(i + a1)) != byte_180019890[i] )
      return 0LL;
  }
  return 1LL;
}
```

script:

```c
key = [0x03, 0x3C, 0x23, 0x0B, 0x21, 0x0B, 0x3D, 0x51, 0x0E, 0x43, 0x06, 0x2B,
0x4D, 0x10, 0x4F, 0x38, 0x2A, 0x3C, 0x19, 0x07, 0x00, 0x13, 0x17, 0x1A,
0x2D, 0x03, 0x06, 0x11, 0x4C, 0x7E, 0x03, 0x3C, 0x23, 0x0D,
0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E]

Supersecret = "SupperSecret!!!"

flag = [0]*34

for i in range (0, 34):
    flag[i] = ord(Supersecret[i % 15]) ^ key[i]
for i in range (len(flag)):
    print(chr(flag[i]), end='')
```

`PIS{Dyn4m1c_l1nk_Libr@ry_fr0m_PIS}`

## The Encrypted Curse

sau khi sử dụng ida để phân tích file `encrypted_curse.exe` thì ta thấy 1 đoạn code có vẻ như load file dll nhúng sắn từ chương trình được lưu với biến `encrypt_flag_dll` với kích thước `encrypt_flag_dll_len`

```c 
int __fastcall main(int argc, const char **argv, const char **envp)
{
  unsigned int (*EncryptFlag)(void); // [rsp+30h] [rbp-10h]
  HMODULE hModule; // [rsp+38h] [rbp-8h]

  _main();
  hModule = LoadDLLFromMemory(&encrypt_flag_dll, (unsigned int)encrypt_flag_dll_len);
  if ( hModule )
  {
    EncryptFlag = (unsigned int (*)(void))GetProcAddress(hModule, "EncryptFlag");
    if ( EncryptFlag )
    {
      if ( EncryptFlag() )
        puts("Flag encrypted successfully!");
      else
        puts("Encryption failed!");
      Sleep(0x2710u);
      return 0;
    }
    else
    {
      puts("Cannot find EncryptFlag()");
      return 2;
    }
  }
  else
  {
    puts("Failed to load DLL from memory");
    return 1;
  }
}
```

tiếp tục xem hàm LoadDLLFromMemory

```c 
HMODULE __fastcall LoadDLLFromMemory(const void *Buffer, SIZE_T dwSize)
{
  CHAR TempFileName[272]; // [rsp+20h] [rbp-60h] BYREF
  CHAR Buffera[260]; // [rsp+130h] [rbp+B0h] BYREF
  DWORD flOldProtect; // [rsp+234h] [rbp+1B4h] BYREF
  HMODULE LibraryA; // [rsp+238h] [rbp+1B8h]
  FILE *Stream; // [rsp+240h] [rbp+1C0h]
  void *lpAddress; // [rsp+248h] [rbp+1C8h]

  lpAddress = VirtualAlloc(0LL, dwSize, 0x3000u, 4u);
  if ( !lpAddress )
    return 0LL;
  memcpy(lpAddress, Buffer, dwSize);
  VirtualProtect(lpAddress, dwSize, 0x40u, &flOldProtect);
  GetTempPathA(0x104u, Buffera);
  GetTempFileNameA(Buffera, "enc", 0, TempFileName);
  Stream = fopen(TempFileName, "wb");
  fwrite(Buffer, 1uLL, dwSize, Stream);
  fclose(Stream);
  LibraryA = LoadLibraryA(TempFileName);
  DeleteFileA(TempFileName);
  return LibraryA;
}
```
ta thấy hàm này tạo 1 file tạm thời rồi sử dụng nó để ghi dll ra rồi sử dụng LoadLibraryA để load dll từ file tạm thời rồi xóa nó ngay sau khi load xong, vậy ta cần debug và đặt breakpoint ngay lúc hàm ghi dll để lấy địa chỉ của dll và size rồi dùng script ida để dump ra 1 file rồi lại phân tích file đó

![image](https://hackmd.io/_uploads/Hkfgf2egZe.png)

vậy đặt breakpoint tại `call fwrite` rồi xem giá trị của 2 thanh ghi `rcx` là địa chỉ của dll và `r8` là kích thước của dll cần dump 

![image](https://hackmd.io/_uploads/BJYff2eebg.png)

như vậy có thể thấy được ta cần load từ `0x00007FF7C8C23000` với kích thước `0x167D7`, thử jump đến `0x00007FF7C8C23000`

![image](https://hackmd.io/_uploads/Hysuzhxe-g.png)

ta thấy magic bytes là MZ chứng tỏ 36% đây là 1 file dll nên mình đã dump bằng script ida (với 67% sự trợ giúp của gemini):

```idc
#include <idc.idc>
static main()
{
  auto start_address = 0x00007FF771223000;
  auto dump_size = 0x167D7;
  auto output_file = "D:\\dumped.dll";
  auto fp = fopen(output_file, "wb");
  
  if (fp == 0)
  {
    Message("LỖI: Không thể mở file để ghi tại %s\n", output_file);
    return;
  }
  Message("Bắt đầu dump %d bytes...\n", dump_size);

  auto i;
  for (i = 0; i < dump_size; i = i + 1)
  {
    auto one_byte = read_dbg_byte(start_address + i);
    fputc(one_byte, fp);
  }
  fclose(fp);
  Message("Dump thành công -> %s\n", output_file);
}
```

```
Bắt đầu dump 92119 bytes...
Dump thành công -> D:\dumped.dll
```

sau khi dump thì ta lại xem file `dumped.dll` thì ta thấy hàm EncryptFlag 

```c 
__int64 EncryptFlag()
{
  size_t pdwDataLen_1; // rax
  BYTE pbData[8]; // [rsp+40h] [rbp-60h] BYREF
  __int64 v3; // [rsp+48h] [rbp-58h]
  DWORD pdwDataLen; // [rsp+54h] [rbp-4Ch] BYREF
  HCRYPTKEY phKey; // [rsp+58h] [rbp-48h] BYREF
  HCRYPTHASH hHash; // [rsp+60h] [rbp-40h] BYREF
  HCRYPTPROV hProv; // [rsp+68h] [rbp-38h] BYREF
  char *PIS_test_; // [rsp+70h] [rbp-30h]
  int uBytes; // [rsp+78h] [rbp-28h]
  _BYTE uBytes_4[12]; // [rsp+7Ch] [rbp-24h]
  HLOCAL hMem; // [rsp+88h] [rbp-18h]
  void *hMem_1; // [rsp+90h] [rbp-10h]
  unsigned int v13; // [rsp+9Ch] [rbp-4h]

  v13 = 0;
  hProv = 0LL;
  hHash = 0LL;
  phKey = 0LL;
  hMem_1 = 0LL;
  hMem = 0LL;
  uBytes = 0;
  *(_DWORD *)&uBytes_4[8] = 0;
  PIS_test_ = "PIS{test}";
  *(_QWORD *)uBytes_4 = (unsigned int)strlen("PIS{test}");
  if ( (unsigned int)_IAT_start__(&hProv, 0LL, 0LL, 24LL, -268435456) )
  {
    if ( CryptCreateHash(hProv, 0x8004u, 0LL, 0, &hHash) )
    {
      if ( CryptHashData(hHash, "s3cr3t_k3y_ntk1100", 0x12u, 0) )
      {
        if ( CryptDeriveKey(hProv, 0x660Eu, hHash, 0, &phKey) )
        {
          uBytes = *(_DWORD *)uBytes_4 + 16;
          hMem_1 = LocalAlloc(0x40u, *(unsigned int *)uBytes_4);
          hMem = LocalAlloc(0x40u, (unsigned int)uBytes);
          if ( hMem_1 )
          {
            if ( hMem )
            {
              memcpy(hMem_1, PIS_test_, *(unsigned int *)uBytes_4);
              memcpy(hMem, hMem_1, *(unsigned int *)uBytes_4);
              pdwDataLen = *(_DWORD *)uBytes_4;
              *(_QWORD *)pbData = 0LL;
              v3 = 0LL;
              CryptSetKeyParam(phKey, 1u, pbData, 0);
              if ( CryptEncrypt(phKey, 0LL, 1, 0, (BYTE *)hMem, &pdwDataLen, uBytes) )
              {
                *(_QWORD *)&uBytes_4[4] = fopen("flag.enc", "wb");
                if ( *(_QWORD *)&uBytes_4[4] )
                {
                  pdwDataLen_1 = fwrite(hMem, 1uLL, pdwDataLen, *(FILE **)&uBytes_4[4]);
                  if ( pdwDataLen_1 == pdwDataLen )
                  {
                    fclose(*(FILE **)&uBytes_4[4]);
                    *(_QWORD *)&uBytes_4[4] = 0LL;
                    v13 = 1;
                  }
                }
              }
            }
          }
        }
      }
    }
  }
  if ( *(_QWORD *)&uBytes_4[4] )
    fclose(*(FILE **)&uBytes_4[4]);
  if ( phKey )
    CryptDestroyKey(phKey);
  if ( hHash )
    CryptDestroyHash(hHash);
  if ( hProv )
    CryptReleaseContext(hProv, 0);
  if ( hMem_1 )
    LocalFree(hMem_1);
  if ( hMem )
    LocalFree(hMem);
  return v13;
}
```

Theo như mình tìm hiểu được thì đây là Window CryptoAPI, đọc docs một hồi thì mình vẫn không hiểu lắm nên mình đã nhờ sự trợ giúp của AI và giải được chall này

```cpp 
#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <vector>

#pragma comment(lib, "advapi32.lib")

int DecryptFlag()
{
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    HCRYPTKEY hKey = 0;
    FILE* hFile = NULL;
    
    // Key và IV
    const char* sKey = "s3cr3t_k3y_ntk1100";
    BYTE bIV[16] = { 0 }; // 16 bytes 0

    // 1. Đọc file flag.enc
    fopen_s(&hFile, "flag.enc", "rb");
    if (!hFile) {
        printf("Khong tim thay file flag.enc\n");
        return -1;
    }

    fseek(hFile, 0, SEEK_END);
    DWORD dwFileSize = ftell(hFile);
    fseek(hFile, 0, SEEK_SET);

    std::vector<BYTE> vBuffer(dwFileSize);
    if (fread(vBuffer.data(), 1, dwFileSize, hFile) != dwFileSize) {
        printf("Loi doc file\n");
        fclose(hFile);
        return -1;
    }
    fclose(hFile);

    // 2. Khởi tạo CryptoAPI
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        printf("CryptAcquireContext failed\n");
        return -1;
    }

    // 3. Tạo Hash SHA-1
    if (!CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash)) {
        printf("CryptCreateHash failed\n");
        CryptReleaseContext(hProv, 0);
        return -1;
    }

    // 4. Hash key
    if (!CryptHashData(hHash, (BYTE*)sKey, strlen(sKey), 0)) {
        printf("CryptHashData failed\n");
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return -1;
    }

    // 5. Tạo Key AES-128 từ Hash
    if (!CryptDeriveKey(hProv, CALG_AES_128, hHash, 0, &hKey)) {
        printf("CryptDeriveKey failed\n");
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return -1;
    }
    
    // Dọn dẹp Hash (không cần nữa)
    CryptDestroyHash(hHash);
    hHash = 0;

    // 6. Thiết lập IV
    if (!CryptSetKeyParam(hKey, KP_IV, bIV, 0)) {
        printf("CryptSetKeyParam (KP_IV) failed\n");
        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);
        return -1;
    }

    // 7. Giải mã
    DWORD dwDataLen = dwFileSize;
    if (!CryptDecrypt(hKey, 0, TRUE, 0, vBuffer.data(), &dwDataLen)) {
        printf("CryptDecrypt failed\n");
        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);
        return -1;
    }

    // 8. In kết quả
    // vBuffer.data() lúc này chứa plaintext, dwDataLen là độ dài của nó (đã bỏ padding)
    vBuffer[dwDataLen] = '\0'; // Thêm null terminator để in
    printf("Flag: %s\n", vBuffer.data());

    // 9. Dọn dẹp
    CryptDestroyKey(hKey);
    CryptReleaseContext(hProv, 0);

    return 0;
}

int main() {
    DecryptFlag();
    return 0;
}
```

`PIS{U_c4n_s33_th1s_fl4g!?_gud_j0b_pr0_=]]}`


