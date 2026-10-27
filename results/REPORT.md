# parity report

generated: 2026-10-27T03:07:14Z
host: Linux 5.10.0-ish_aok x86_64

## selftest
```
selftest: OK (3 frame shapes, mixed headers, 24-byte invariant held)
[FOUND] sendsize (0x28af4) -> 1 hit(s)
          +24 as u32 big
[FOUND] checksum (0x5d20) -> 1 hit(s)
          +28 as u16 little
[FOUND] flags (0x8) -> 5 hit(s)
          +8 as u8 big
          +33 as u8 big
          +8 as u8 little
          +33 as u8 little
          +32 as u16 big

unambiguous: False
  +8 width 1 matches ['flags', 'flags']
  +33 width 1 matches ['flags', 'flags']
selftest: OK (3/3 located, zero false positives)
[FOUND] sendsize (0x28af4) -> 1 hit(s)
          +24 as u32 big
[FOUND] checksum (0x5d20) -> 1 hit(s)
          +28 as u16 little
[FOUND] flags (0x8) -> 5 hit(s)
          +8 as u8 big
          +33 as u8 big
          +8 as u8 little
          +33 as u8 little
          +32 as u16 big

unambiguous: False
  +8 width 1 matches ['flags', 'flags']
  +33 width 1 matches ['flags', 'flags']
selftest: OK (3/3 located, zero false positives)
```

## run_all
```
capture                               transport    port  frames  directions            status
------------------------------------------------------------------------------------------------
forward_level3_tcp_port_1163.pcap     tcp          1163       0  -                     EMPTY
forward_level4_tcp_port_1167.pcap     tcp          1167       0  -                     EMPTY
reverse_level3_http_port_80.pcap      http           80       0  -                     EMPTY
reverse_level3_http_port_443.pcap     http          443       0  -                     EMPTY
reverse_level3_tcp_port_53.pcap       tcp            53       0  -                     EMPTY

FAIL: 5/5 unusable: ['forward_level3_tcp_port_1163.pcap', 'forward_level4_tcp_port_1167.pcap', 'reverse_level3_http_port_80.pcap', 'reverse_level3_http_port_443.pcap', 'reverse_level3_tcp_port_53.pcap']
```

## dllflags
```
===== bins/PCConfig.exe =====
== bins/PCConfig.exe  (150,040 bytes)
   machine=i386  pe=PE32  base=0x400000  sections=4
   exports: none / ordinal-only
   vocabulary hits: 0 ascii, 9 wide
     [wide] 0x01b1a0  va=0x41c3a0  PCHEAP_CONFIG_FLAG_DONT_CREATE_SECTION
     [wide] 0x01b1f0  va=0x41c3f0  PCHEAP_CONFIG_FLAG_DONT_CREATE_WINDOW
     [wide] 0x01b240  va=0x41c440  PCHEAP_CONFIG_FLAG_IGNORE_WIN_FIREWALL
     [wide] 0x01b290  va=0x41c490  PCHEAP_CONFIG_LOADED_WITH_UTILITY_BURST
     [wide] 0x01b2e0  va=0x41c4e0  PCHEAP_CONFIG_FLAG_LEVEL4
     [wide] 0x01b314  va=0x41c514  PCHEAP_CONFIG_FLAG_LEVEL3
     [wide] 0x01b348  va=0x41c548  PCHEAP_CONFIG_FLAG_QUICK_DELETE_SELF
     [wide] 0x01b398  va=0x41c598  PCHEAP_CONFIG_FLAG_CALLBACK_NOW
     [wide] 0x01b3d8  va=0x41c5d8  PCHEAP_CONFIG_FLAG_24_HOUR
----- xref -----
== bins/PCConfig.exe  (150,040 bytes)
   machine=i386  pe=PE32  base=0x400000  sections=4
   exports: none / ordinal-only
   vocabulary hits: 0 ascii, 9 wide
     [wide] 0x01b1a0  va=0x41c3a0  PCHEAP_CONFIG_FLAG_DONT_CREATE_SECTION
     [wide] 0x01b1f0  va=0x41c3f0  PCHEAP_CONFIG_FLAG_DONT_CREATE_WINDOW
     [wide] 0x01b240  va=0x41c440  PCHEAP_CONFIG_FLAG_IGNORE_WIN_FIREWALL
     [wide] 0x01b290  va=0x41c490  PCHEAP_CONFIG_LOADED_WITH_UTILITY_BURST
     [wide] 0x01b2e0  va=0x41c4e0  PCHEAP_CONFIG_FLAG_LEVEL4
     [wide] 0x01b314  va=0x41c514  PCHEAP_CONFIG_FLAG_LEVEL3
     [wide] 0x01b348  va=0x41c548  PCHEAP_CONFIG_FLAG_QUICK_DELETE_SELF
     [wide] 0x01b398  va=0x41c598  PCHEAP_CONFIG_FLAG_CALLBACK_NOW
     [wide] 0x01b3d8  va=0x41c5d8  PCHEAP_CONFIG_FLAG_24_HOUR

-- xref / single-bit immediate scan --
  [xref] PCHEAP_CONFIG_FLAG_DONT_CREATE_SECTION         va=0x41c3a0     no code reference
  [xref] PCHEAP_CONFIG_FLAG_DONT_CREATE_WINDOW          va=0x41c3f0     no code reference
  [xref] PCHEAP_CONFIG_FLAG_IGNORE_WIN_FIREWALL         va=0x41c440     no code reference
  [xref] PCHEAP_CONFIG_LOADED_WITH_UTILITY_BURST        va=0x41c490     no code reference
  [xref] PCHEAP_CONFIG_FLAG_LEVEL4                      va=0x41c4e0     no code reference
  [xref] PCHEAP_CONFIG_FLAG_LEVEL3                      va=0x41c514     no code reference
  [xref] PCHEAP_CONFIG_FLAG_QUICK_DELETE_SELF           va=0x41c548     no code reference
  [xref] PCHEAP_CONFIG_FLAG_CALLBACK_NOW                va=0x41c598     no code reference
  [xref] PCHEAP_CONFIG_FLAG_24_HOUR                     va=0x41c5d8     no code reference

===== caps/PeddleCheap_Lp.dll =====
== caps/PeddleCheap_Lp.dll  (271,872 bytes)
   machine=i386  pe=PE32  base=0x10000000  sections=5
   exports: none / ordinal-only
   vocabulary hits: 5 ascii, 15 wide
     0x034310  va=0x10035910  EggPayloadInfo
     0x0346c0  va=0x10035cc0  export
     0x0346d8  va=0x10035cd8  RunLibrary
     0x0346e4  va=0x10035ce4  Failed to get export
     0x034e58  va=0x10036458  PayloadInfo
     [wide] 0x034320  va=0x10035920  Export name
     [wide] 0x0345b8  va=0x10035bb8  Error sending fileInfo struct.
     [wide] 0x034970  va=0x10035f70  Invalid export choice (%ls)
     [wide] 0x0349a8  va=0x10035fa8  Failed to get an export choice
     [wide] 0x0349e8  va=0x10035fe8  Export Choice
     [wide] 0x034a38  va=0x10036038  Load the library without calling an export
     [wide] 0x034a90  va=0x10036090  Run an export with no parameters
     [wide] 0x034ad8  va=0x100360d8  Run an export with the default parameters
     [wide] 0x034b70  va=0x10036170  FAILED to determine payload (%ls) export name
     [wide] 0x0350b8  va=0x100366b8  Unable to determine export args for dependency: %s
     [wide] 0x03576c  va=0x10036d6c  RunType
     [wide] 0x0358b8  va=0x10036eb8  Export
     [wide] 0x0365ac  va=0x10037bac  \\.\pipe\pcheap_reuse
----- xref -----
== caps/PeddleCheap_Lp.dll  (271,872 bytes)
   machine=i386  pe=PE32  base=0x10000000  sections=5
   exports: none / ordinal-only
   vocabulary hits: 5 ascii, 15 wide
     0x034310  va=0x10035910  EggPayloadInfo
     0x0346c0  va=0x10035cc0  export
     0x0346d8  va=0x10035cd8  RunLibrary
     0x0346e4  va=0x10035ce4  Failed to get export
     0x034e58  va=0x10036458  PayloadInfo
     [wide] 0x034320  va=0x10035920  Export name
     [wide] 0x0345b8  va=0x10035bb8  Error sending fileInfo struct.
     [wide] 0x034970  va=0x10035f70  Invalid export choice (%ls)
     [wide] 0x0349a8  va=0x10035fa8  Failed to get an export choice
     [wide] 0x0349e8  va=0x10035fe8  Export Choice
     [wide] 0x034a38  va=0x10036038  Load the library without calling an export
     [wide] 0x034a90  va=0x10036090  Run an export with no parameters
     [wide] 0x034ad8  va=0x100360d8  Run an export with the default parameters
     [wide] 0x034b70  va=0x10036170  FAILED to determine payload (%ls) export name
     [wide] 0x0350b8  va=0x100366b8  Unable to determine export args for dependency: %s
     [wide] 0x03576c  va=0x10036d6c  RunType
     [wide] 0x0358b8  va=0x10036eb8  Export
     [wide] 0x0365ac  va=0x10037bac  \\.\pipe\pcheap_reuse

-- xref / single-bit immediate scan --
  [xref] EggPayloadInfo                                 va=0x10035910   nearest single-bit immediates: ['0x1', '0x8', '0x10', '0x4', '0x4', '0x10']
         d=1   0x1     1000c0bb:	push   $0x1
         d=4   0x8     1000c0d5:	cmpl   $0x8,0x18(%edi)
         d=7   0x10    1000c09c:	add    $0x10,%esp
         d=7   0x4     1000c0de:	add    $0x4,%edi
         ref: 1000c0bd:	push   $0x10035910
  [xref] export                                         va=0x10035cc0   nearest single-bit immediates: ['0x10', '0x10', '0x2', '0x1', '0x1']
         d=6   0x10    1000c86c:	add    $0x10,%esp
         d=15  0x10    1000c848:	add    $0x10,%esp
         d=26  0x2     1000c8e0:	push   $0x2
         d=27  0x1     1000c811:	push   $0x1
         ref: 1000c885:	push   $0x10035cc0
  [xref] RunLibrary                                     va=0x10035cd8   nearest single-bit immediates: ['0x1', '0x1', '0x10', '0x10', '0x10']
         d=1   0x1     1000c811:	push   $0x1
         d=2   0x1     1000c80b:	orw    $0x1,0x1a(%esp)
         d=7   0x10    1000c7f6:	add    $0x10,%esp
         d=11  0x10    1000c848:	add    $0x10,%esp
         ref: 1000c813:	push   $0x10035cd8
  [xref] Failed to get export                           va=0x10035ce4   nearest single-bit immediates: ['0x8', '0x1', '0x8', '0x1', '0x8', '0x2']
         d=3   0x8     1000c67e:	add    $0x8,%esp
         d=4   0x1     1000c681:	movb   $0x1,0x344(%esp)
         d=13  0x8     1000c650:	add    $0x8,%esp
         d=24  0x1     1000c62b:	orw    $0x1,0x2a(%esp)
         ref: 1000c673:	push   $0x10035ce4
  [xref] PayloadInfo                                    va=0x10036458   nearest single-bit immediates: ['0x8', '0x8', '0x10']
         d=5   0x8     1000e8c9:	movb   $0x8,0x1dc(%esp)
         d=17  0x8     1000e888:	add    $0x8,%esp
         d=25  0x10    1000e870:	add    $0x10,%esp
         ref: 1000e8e6:	push   $0x10036458
  [xref] Export name                                    va=0x10035920   nearest single-bit immediates: ['0x10', '0x1', '0x10', '0x8', '0x4', '0x4']
         d=3   0x10    1000c09c:	add    $0x10,%esp
         d=9   0x1     1000c0bb:	push   $0x1
         d=12  0x10    1000c065:	add    $0x10,%esp
         d=14  0x8     1000c0d5:	cmpl   $0x8,0x18(%edi)
         ref: 1000c091:	push   $0x10035920
  [xref] Error sending fileInfo struct.                 va=0x10035bb8   nearest single-bit immediates: ['0x10', '0x10']
         d=13  0x10    1000ca83:	add    $0x10,%esp
         d=29  0x10    1000cabb:	add    $0x10,%esp
         ref: 1000ca4a:	push   $0x10035bb8
  [xref] Invalid export choice (%ls)                    va=0x10035f70   nearest single-bit immediates: ['0x8', '0x1', '0x4']
         d=8   0x8     1000e0bc:	cmpl   $0x8,0x24(%esp)
         d=17  0x1     1000e0a5:	mov    $0x1,%al
         d=24  0x4     1000e084:	add    $0x4,%edx
         ref: 1000e0d4:	push   $0x10035f70
  [xref] Failed to get an export choice                 va=0x10035fa8   nearest single-bit immediates: ['0x8', '0x1', '0x8', '0x1', '0x1', '0x4']
         d=3   0x8     1000dfe1:	add    $0x8,%esp
         d=7   0x1     1000dfbd:	movb   $0x1,0x188(%esp)
         d=17  0x8     1000e020:	add    $0x8,%esp
         d=21  0x1     1000e02a:	movb   $0x1,(%eax)
         ref: 1000dfd6:	push   $0x10035fa8
  [xref] Export Choice                                  va=0x10035fe8   nearest single-bit immediates: ['0x1', '0x8', '0x1', '0x4', '0x1', '0x8']
         d=2   0x1     1000dfbd:	movb   $0x1,0x188(%esp)
         d=12  0x8     1000dfe1:	add    $0x8,%esp
         d=13  0x1     1000df82:	movb   $0x1,0x164(%esp)
         d=18  0x4     1000df6c:	movb   $0x4,0x164(%esp)
         ref: 1000dfb7:	push   $0x10035fe8
  [xref] Load the library without calling an export     va=0x10036038   nearest single-bit immediates: ['0x10', '0x8', '0x8', '0x8']
         d=6   0x10    1000ddfb:	mov    $0x10,%ecx
         d=8   0x8     1000de3a:	cmpl   $0x8,0x18(%edi)
         d=17  0x8     1000de55:	add    $0x8,%esp
         d=25  0x8     1000de73:	cmpl   $0x8,0x18(%edi)
         ref: 1000de12:	mov    $0x10036038,%esi
  [xref] Run an export with no parameters               va=0x10036090   nearest single-bit immediates: ['0x10', '0x8', '0x8']
         d=1   0x10    1000ddfb:	mov    $0x10,%ecx
         d=13  0x8     1000de3a:	cmpl   $0x8,0x18(%edi)
         d=22  0x8     1000de55:	add    $0x8,%esp
         ref: 1000de00:	mov    $0x10036090,%esi
  [xref] Run an export with the default parameters      va=0x100360d8   nearest single-bit immediates: ['0x10', '0x8', '0x8', '0x8']
         d=3   0x10    1000ddfb:	mov    $0x10,%ecx
         d=17  0x8     1000de3a:	cmpl   $0x8,0x18(%edi)
         d=26  0x8     1000de55:	add    $0x8,%esp
         d=27  0x8     1000ddb2:	add    $0x8,%esp
         ref: 1000dded:	mov    $0x100360d8,%esi
  [xref] FAILED to determine payload (%ls) export name  va=0x10036170   nearest single-bit immediates: ['0x8', '0x8', '0x4', '0x8']
         d=5   0x8     1000e4dc:	cmpl   $0x8,0x3c(%ebp)
         d=20  0x8     1000e526:	cmpl   $0x8,0x18(%edi)
         d=24  0x4     1000e531:	add    $0x4,%edi
         d=30  0x8     1000e496:	cmpl   $0x8,0x3c(%ebp)
         ref: 1000e4e9:	push   $0x10036170
  [xref] Unable to determine export args for dependency: %s va=0x100366b8   nearest single-bit immediates: ['0x2', '0x8', '0x1', '0x4', '0x1', '0x8']
         d=4   0x2     1000f971:	movb   $0x2,0x1ac(%esp)
         d=7   0x8     1000f94b:	cmpl   $0x8,0x8c(%esp)
         d=7   0x1     1000f985:	movb   $0x1,0x1ac(%esp)
         d=9   0x4     1000f946:	add    $0x4,%edi
         ref: 1000f963:	push   $0x100366b8
  [xref] RunType                                        va=0x10036d6c   nearest single-bit immediates: ['0x1', '0x10']
         d=22  0x1     100120a8:	cmp    $0x1,%eax
         d=30  0x10    10012028:	add    $0x10,%esp
         ref: 1001205a:	push   $0x10036d6c
  [xref] Export                                         va=0x10036eb8   nearest single-bit immediates: ['0x8', '0x1']
         d=8   0x8     1001e6d1:	add    $0x8,%esp
         d=15  0x1     1001e6ba:	cmp    $0x1,%ax
         ref: 1001e6e2:	push   $0x10036eb8
  [xref] \\.\pipe\pcheap_reuse                          va=0x10037bac   nearest single-bit immediates: ['0x1', '0x800', '0x1', '0x1', '0x1']
         d=3   0x1     10029a2a:	push   $0x1
         d=6   0x800   10029a23:	mov    $0x800,%eax
         d=8   0x1     10029a4e:	mov    $0x1,%al
         d=24  0x1     10029a68:	cmp    $0x1,%ebx
         ref: 10029a33:	push   $0x10037bac

```

## log_parse
```
3 records from caps/00041-pc_listen_2017_10_16_09h37m12s.966.xml

Command      lptimestamp=2017-10-16T09:37:12 name=pc_listen
PayloadInfo  checksum=5d20 fileName=C:\johnb\fuzzbunch-master-new\Resources\Pc\/../Dsz/Payloads/Files/x64-winnt-vc9s/release/Dsz_Implant_Pc.dll lptimestamp=2017-10-16T09:41:13 origSize=338944 sendSize=166644 sendingPayload=true
RunLibrary   export=#1 flags=0x00000008 lptimestamp=2017-10-16T09:41:13 name= path=

ground-truth values for verify.py:
  checksum=5d20
  export=#1
  flags=0x00000008
  origSize=338944
  sendSize=166644
```

