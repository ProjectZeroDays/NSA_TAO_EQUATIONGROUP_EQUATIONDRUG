# fileinfo_blob.hex

36-byte fileInfo struct reconstructed from the logged `PayloadInfo` record in
`00041-pc_listen_2017_10_16_09h37m12s.966.xml`.

| off | field        | value      | source                          |
|-----|--------------|------------|---------------------------------|
| +0  | unknown      | 00 x16     | not pinned by log               |
| +16 | library type | 00000003   | candidate (runType filelib=3)   |
| +20 | unknown      | dcce0000   | open, per dp_decrypt.py         |
| +24 | sendSize     | 00028af4   | log `sendSize=166644`           |
| +28 | checksum     | 205d       | log `checksum=5d20` (u16 LE)    |
| +30 | runType      | 0100       | log `export=#1`                 |
| +32 | RunLibrary   | 0008       | log `flags=0x00000008` (u16 BE) |
| +34 | tail         | 0000       | not pinned by log               |

This is a log-derived fixture, not a byte-exact capture blob. Offsets +16, +20 and
+30 are expected to be reported `candidate`/`open` by verify.py, never `confirmed`.