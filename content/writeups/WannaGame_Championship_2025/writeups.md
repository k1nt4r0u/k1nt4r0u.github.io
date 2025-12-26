---
title: "WannaGame Championship 2025 - Reversing Writeup"
date: 2025-12-25T21:37:47+07:00
draft: false
categories: ["WannaGame Championship 2025"]
contest: "WannaGame Championship 2025"
author: "k1nt4r0u"
---

## Buzzing

Bài này lúc đầu mình tưởng phải scp file về giải mà ko được nên mình dùng base64 copy về xem thì thực sự chỉ đọc file flag nên mình launch lại instance thử các lệnh linux. Mò một hồi vẫn không được, tìm hiểu thì mình thấy eBPF có thể chặn không cho chạy bất cứ lệnh nào chứa `/readflag` -> sử dụng lệnh `ln` với option `-s` để tạo symlink file `/readflag` với `/tmp/solve` rồi chạy `/tmp/solve` để đọc file `/flag` là xong

## Checker

chall này cho 1 file exe, xem qua bằng lệnh file thì mình có được các thông tin của chall

```
checker.exe: PE32+ executable for MS Windows 6.00 (console), x86-64, 6 sections
```

decompile bằng ida thì mình được hàm main khá dài, nhìn qua thì thấy chương trình hỏi người dùng checker option 1 hay 2 rồi gán cho từng lựa chọn 1 Resource ID tương ứng là 101 và 102:

```C
  printf("Choose your flag checker !\n");
  printf("1 or 2 ?\n");
  if ( (unsigned int)sub_7FF76C46C830("%d", (unsigned int)&n2) != 1 )
  {
    printf("Invalid input!\n");
    return 1;
  }
  if ( n2 == 1 )
  {
    n101 = 101;
  }
  else
  {
    if ( n2 != 2 )
    {
      printf("Invalid choice!\n");
      return 1;
    }
    n101 = 102;
  }
```

xem qua thì có vẻ chương trình gọi các hàm Windows API để load 1 trong 2 file exe nhúng trong `Resource` ra file có tên `flag_checker.exe` dựa trên lựa chọn của người dùng, trước hết thì nó dùng hàm `FindResourceA` để tìm `Resource` trong file `PE` 

```C
hResInfo = FindResourceA(0LL, (LPCSTR)(unsigned __int16)n101, (LPCSTR)0xA);
```

sau khi tìm thấy resource rồi thì chương trình tiến hành lấy các thông tin của resource cần load với các hàm như `LoadResource` để handle resource với `hResInfo` đã tìm được ở trên  `SizeofResource` để lấy kích thước file cần load cũng như `LockResource` lấy src để trỏ tới vị trí lưu raw bytes của file `flag_checker.exe`

```C
hResData = LoadResource(0LL, hResInfo);
Size_1 = SizeofResource(0LL, hResInfo);
Src = LockResource(hResData);
```

khúc này chương trình tạo buffer `v25` với kích thước của file cần load rồi copy file từ `Resource` sang `v25`

```c
v8 = unknown_libname_69((__int64)v12);
sub_7FF76C464430(v25, Size_1, v8); 
Size = Size_1;
v9 = (void *)unknown_libname_(v25); 
memcpy(v9, Src, Size);
```

sau đó chương trình gọi hàm để ghi file `flag_checker.exe` ra 

```c
lpCommandLine = "flag_checker.exe";
sub_7FF76C463D10((unsigned int)v28, (unsigned int)"flag_checker.exe", 32, 64, 1);

...

__int64 __fastcall sub_7FF76C463D10(__int64 a1, __int64 flag_checker.exe, int n32, unsigned int n64, int a5)
{
  __int64 v5; // rax

  if ( a5 )
  {
    *(_QWORD *)a1 = &unk_7FF76C497940;
    std::ios::ios(a1 + 168);
  }
  v5 = unknown_libname_69(a1 + 8);
  sub_7FF76C463E30(a1, v5, 0LL, 0LL);
  *(_QWORD *)(a1 + *(int *)(*(_QWORD *)a1 + 4LL)) = &std::ofstream::`vftable';
  *(_DWORD *)(a1 + *(int *)(*(_QWORD *)a1 + 4LL) - 4) = *(_DWORD *)(*(_QWORD *)a1 + 4LL) - 168;
  sub_7FF76C463C80(a1 + 8);
  if ( !sub_7FF76C46AB80(a1 + 8, flag_checker.exe, n32 | 2u, n64) )
    sub_7FF76C46B790(*(int *)(*(_QWORD *)a1 + 4LL) + a1, 2LL, 0LL);
  return a1;
}
```

sau khi mở và ghi ra file `flag_checker.exe` cũng như check flag theo lựa chọn của người dùng và in ra output thì chương trình đóng handle và xóa file `flag_checker.exe`  bằng các hàm `CloseHandle` và `DeleteFileA`

```c
if ( CreateProcessA(0LL, lpCommandLine, 0LL, 0LL, 0, 0, 0LL, 0LL, &StartupInfo, &ProcessInformation) )
        {
          WaitForSingleObject(ProcessInformation.hProcess, 0xFFFFFFFF);
          CloseHandle(ProcessInformation.hProcess);
          CloseHandle(ProcessInformation.hThread);
          DeleteFileA(lpCommandLine);
          v18 = 0;
          sub_7FF76C465D80(v28);
          sub_7FF76C4652E0(v25);
          return v18;
        }
```

vậy nên việc mình cần làm là chạy debug và đặt breakpoint ngay sau khi chương trình load ra file `flag_checker.exe` hoặc ngay trước khi nó xóa file, ở đây thì mình break ngay hàm `DeleteFileA` thì mình có được 1 file `flag_checker.exe` trong cùng thư mục chứa chall, chạy debug 2 lần với 2 option khác nhau thì mình có được 2 file `flag_checker.exe`, đặt lại tên cho 2 file rồi mình mở ida xem 2 file này làm gì

```c 
int __fastcall main(int argc, const char **argv, const char **envp)
{
  __int64 v3; // r8
  _QWORD *v4; // rax
  __int64 v5; // r8
  char v7; // [rsp+30h] [rbp-128h] BYREF
  _BYTE v8[3]; // [rsp+31h] [rbp-127h] BYREF
  unsigned int v9; // [rsp+34h] [rbp-124h]
  int v10; // [rsp+38h] [rbp-120h]
  __int64 v11; // [rsp+40h] [rbp-118h]
  _QWORD *v12; // [rsp+48h] [rbp-110h]
  __int64 v13; // [rsp+50h] [rbp-108h]
  _BYTE v14[8]; // [rsp+58h] [rbp-100h] BYREF
  _BYTE v15[16]; // [rsp+60h] [rbp-F8h] BYREF
  _BYTE dst[16]; // [rsp+70h] [rbp-E8h] BYREF
  _BYTE v17[24]; // [rsp+80h] [rbp-D8h] BYREF
  _BYTE v18[24]; // [rsp+98h] [rbp-C0h] BYREF
  _BYTE v19[24]; // [rsp+B0h] [rbp-A8h] BYREF
  _BYTE v20[24]; // [rsp+C8h] [rbp-90h] BYREF
  _BYTE v21[24]; // [rsp+E0h] [rbp-78h] BYREF
  _BYTE v22[24]; // [rsp+F8h] [rbp-60h] BYREF
  _BYTE v23[16]; // [rsp+110h] [rbp-48h] BYREF
  _BYTE v24[15]; // [rsp+120h] [rbp-38h] BYREF
  char v25; // [rsp+12Fh] [rbp-29h] BYREF

  if ( (word_140042018[2] & 1) != 0 )
    sub_1400043D0(&qword_140043620, "Flag checker 1 !!!!!!!!!!!\n", envp);
  else
    sub_1400043D0(&qword_140043620, "Flag checker 1 !!!!!!!!!!\n", envp);
  sub_1400043D0(&qword_140043620, "Your flag: ", v3);
  sub_1400040C0(&qword_140043580, &unk_1400432E8);
  v11 = unknown_libname_59(&v7);
  v12 = (_QWORD *)sub_1400099D0(&unk_1400432E8, v14);
  v4 = (_QWORD *)sub_140009480(&unk_1400432E8, v15);
  sub_140003F40(v22, *v4, *v12, v11);
  sub_140001460(v21, v22, &unk_1400432A0);
  sub_140001570(v20, v21, &unk_1400432B8);
  v9 = sub_140002370(1337LL);
  sub_1400039F0(v19, v20, v9);
  sub_140001C50((unsigned int)v18, (unsigned int)v19, (unsigned int)&unk_1400432D0, (unsigned int)&unk_140043288, 0);
  v24[0] = -4;
  v24[1] = 118;
  v24[2] = -44;
  v24[3] = 9;
  v24[4] = -93;
  v24[5] = -40;
  v24[6] = 80;
  v24[7] = 47;
  v24[8] = -71;
  v24[9] = -41;
  v24[10] = -70;
  v24[11] = -32;
  v24[12] = -80;
  v24[13] = 52;
  v24[14] = -78;
  v13 = unknown_libname_59(v8);
  qmemcpy(dst, (const void *)unknown_libname_63(v23, v24, &v25), sizeof(dst));
  sub_140006820(v17, dst, v13);
  if ( (unsigned __int8)unknown_libname_1(v18, v17) )
    sub_1400043D0(&qword_140043620, "Correct!\n", v5);
  else
    sub_1400043D0(&qword_140043620, "Incorrect!\n", v5);
  v10 = 0;
  sub_1400074D0(v17);
  sub_1400074D0(v18);
  sub_1400074D0(v19);
  sub_1400074D0(v20);
  sub_1400074D0(v21);
  sub_1400074D0(v22);
  return v10;
}
```

xem qua file flag_checker.exe lấy được từ option 1 thì mình vẫn không hiểu lắm vì có nhiều thuật toán lạ nên mình nhờ AI thì biết được chương trình sử dụng các thuật toán encrypt như `ChaCha20`, `RC4`, `lcg` và `xor` để check flag nên mình dùng `xref` để tìm nơi tạo key và tìm được các key, còn seed cho `lcg` thì mình chạy debug rồi break ngay sau khi chương trình gọi hàm `sub_140002370` rồi xem giá trị `rax` chính là seed cho decrypt `lcg`, thứ tự giải sẽ là `chacha` -> `lcg` -> `rc4` -> `xor skibidi`

![image](/images/WGC2025/WGC2025_1.png)

![image](/images/WGC2025/WGC2025_2.png)

```python 
from Crypto.Cipher import ChaCha20, ARC4

target_signed = [-4, 118, -44, 9, -93, -40, 80, 47, -71, -41, -70, -32, -80, 52, -78]
ciphertext = bytes([(x + 256) % 256 for x in target_signed])
key_xor = b"skibidi"                
key_rc4 = bytes(range(1, 17))         
key_chacha = b'\xAA' * 32          
nonce_chacha = b'\x45' * 12           

def chacha(data, key, nonce):
    cipher = ChaCha20.new(key=key, nonce=nonce)
    return cipher.decrypt(data)

def lcg(data, seed):
    out = bytearray()
    a = seed & 0xFFFFFFFFFFFFFFFF
    for b in data:
        mask = 0
        tmp = a
        for _ in range(8):
            mask ^= (tmp & 0xFF)
            tmp >>= 8
        out.append(b ^ (mask & 0xFF))
        a = (a * 0x5851F42D4C957F2D + 0x14057B7EF767814F) & 0xFFFFFFFFFFFFFFFF
    return bytes(out)

def rc4(data, key):
    cipher = ARC4.new(key)
    return cipher.decrypt(data)

def xor(data, key):
    return bytes([d ^ key[i % len(key)] for i, d in enumerate(data)])

def solve(seed):
    return xor(rc4(lcg(chacha(ciphertext, key_chacha, nonce_chacha), seed), key_rc4), key_xor)

print(solve(0xAD66AA22))
#W1{Ch4ng1ng_d4t
```

sau đó mình thử ngồi nghĩ cách tìm part 2 và 3 nhưng mãi không được

```c 
int __fastcall main(int argc, const char **argv, const char **envp)
{
  __int64 v3; // r8
  _QWORD *v4; // rax
  __int64 v5; // r8
  _BYTE v7[4]; // [rsp+30h] [rbp-B8h] BYREF
  unsigned int v8; // [rsp+34h] [rbp-B4h]
  int v9; // [rsp+38h] [rbp-B0h]
  __int64 v10; // [rsp+40h] [rbp-A8h]
  _QWORD *v11; // [rsp+48h] [rbp-A0h]
  _BYTE v12[8]; // [rsp+50h] [rbp-98h] BYREF
  _BYTE v13[8]; // [rsp+58h] [rbp-90h] BYREF
  _BYTE v14[24]; // [rsp+60h] [rbp-88h] BYREF
  _BYTE v15[24]; // [rsp+78h] [rbp-70h] BYREF
  _BYTE v16[24]; // [rsp+90h] [rbp-58h] BYREF
  _BYTE v17[24]; // [rsp+A8h] [rbp-40h] BYREF
  _BYTE v18[40]; // [rsp+C0h] [rbp-28h] BYREF

  if ( *((unsigned __int16 *)&unk_140043330 + 2) % 3 )
    sub_1400048D0(&qword_1400449D0, "Flag checker 2+3 !!!!!!!!!!!!!!!!!!!\n", envp);
  else
    sub_1400048D0(&qword_1400449D0, "Flag checker 2+3 !!!!!!!!!!\n", envp);
  sub_1400048D0(&qword_1400449D0, "Your flag: ", v3);
  sub_1400045C0(&qword_140044930, &unk_140044680);
  v10 = unknown_libname_60(v7);
  v11 = (_QWORD *)sub_14000A620(&unk_140044680, v12);
  v4 = (_QWORD *)sub_14000A050(&unk_140044680, v13);
  sub_140004440(v18, *v4, *v11, v10);
  sub_140001950(v17, v18, &unk_1400445A0);
  sub_140001A60(v16, v17, &unk_1400445B8);
  v8 = sub_140002970(1337LL);
  sub_140004000(v15, v16, v8);
  sub_140002140((unsigned int)v14, (unsigned int)v15, (unsigned int)&unk_140044600, (unsigned int)&unk_140044588, 0);
  if ( (unsigned __int8)unknown_libname_1(v14, &unk_1400446A0) )
    sub_1400048D0(&qword_1400449D0, "Correct!\n", v5);
  else
    sub_1400048D0(&qword_1400449D0, "Incorrect!\n", v5);
  v9 = 0;
  sub_140007F10(v14);
  sub_140007F10(v15);
  sub_140007F10(v16);
  sub_140007F10(v17);
  sub_140007F10(v18);
  return v9;
}
```

## Dutchman_app

Bài này giải nén ra cho mình 1 file apk, mở ra xem thử bằng jadx-gui thì mình có file MainActivity như sau

```java
package com.example.check_new_detection;

import android.content.SharedPreferences;
import com.example.check_new_detection.databinding.ActivityMainBinding;
import defpackage.l2;
import defpackage.mi;

/* loaded from: classes.dex */
public final class MainActivity extends l2 {
    public static final /* synthetic */ int A = 0;
    public ActivityMainBinding v;
    public final String w = "8a5e07ef748a4dbb3b35a63e55e2a405a3bac57bb3387eac71e4d573bc168f6e";
    public final String x = "SecurityPrefs";
    public final String y = "UnlockTime";
    public final long z = 180000;

    static {
        System.loadLibrary("check_new_detection");
    }

    public final native String fa(String str);

    public final native boolean fia();

    /* JADX WARN: Removed duplicated region for block: B:37:0x00f1  */
    @Override // defpackage.l2, androidx.activity.a, defpackage.b9, android.app.Activity
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public final void onCreate(android.os.Bundle r13) {
        /*
            Method dump skipped, instruction units count: 547
            To view this dump change 'Code comments level' option to 'DEBUG'
        */
        throw new UnsupportedOperationException("Method not decompiled: com.example.check_new_detection.MainActivity.onCreate(android.os.Bundle):void");
    }

    public final void t() {
        SharedPreferences sharedPreferences = getSharedPreferences(this.x, 0);
        mi.l(sharedPreferences, "getSharedPreferences(...)");
        sharedPreferences.edit().putLong(this.y, System.currentTimeMillis() + this.z).apply();
    }
}
```

![image](/images/WGC2025/WGC2025_3.png)

có vẻ như app này lấy device id từ đâu đó rồi nếu unauthorized thì terminate luôn và lấy từ thời điểm hiện tại + 180000 mili giây nữa mới cho mở lại app

```java
public final void t() {
        SharedPreferences sharedPreferences = getSharedPreferences(this.x, 0);
        mi.l(sharedPreferences, "getSharedPreferences(...)");
        sharedPreferences.edit().putLong(this.y, System.currentTimeMillis() + this.z).apply();
    }
```

chương trình này trước đó cũng tạo các strings `w`, `x`, `y` và `z` = 180000 rồi sau đó load thư viện có tên `check_new_detection` nên mình sử dụng apktool để decompile file apk này 

```$ apktool d dutchman_app.apk -o dutchman_app
I: Using Apktool 2.12.1 on dutchman_app.apk with 8 threads
I: Baksmaling classes.dex...
I: Loading resource table...
I: Decoding file-resources...
I: Loading resource table from file: /home/kintarou/.local/share/apktool/framework/1.apk
I: Decoding values */* XMLs...
I: Decoding AndroidManifest.xml with resources...
I: Copying original files...
I: Copying assets...
I: Copying lib...
I: Copying unknown files...
```

decompile xong thì mình mở file `MainActivity.smali` xem lý do tại sao mình không thể mở app, đây cũng là lần đầu mình làm dạng bài này nên không rành lắm, với sự trợ giúp của gpt thì mình biết được các dòng code này check device id nên mình patch bằng cách thêm dòng `goto :cond_c` ngay dưới dòng `const/16 v5, 0x8` để bỏ qua check

```smali
.line 375
.line 376
if-nez p1, :cond_11

.line 377
.line 378
if-nez v1, :cond_11

.line 379
.line 380
if-nez v3, :cond_11

.line 381
.line 382
if-nez v4, :cond_c

```

!image](/images/WGC2025/WGC2025_4.png)

sau đó mình build lại file apk sau khi đã patch rồi chạy lại xem nhưng lại không chạy được 

check trong directory lib thì mình thấy có các file .so nên mình ném vô ida xem thử nó có gì

```
├──arm64-v8a
│   └──libcheck_new_detection.so
├──armeabi-v7a
│   └──libcheck_new_detection.so
├──x86
│   └──libcheck_new_detection.so
└──x86_64
    └──libcheck_new_detection.so
```

trong giải mình ngồi mãi vẫn không có thêm ý tưởng gì nên sau giải mình giải tiếp

sau giải mình ngồi thử build lại rồi thử chạy app thì màn hình giờ đã hiện chỗ nhập security key




