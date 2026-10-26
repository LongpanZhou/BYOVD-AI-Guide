
void FUN_1801674a0(longlong param_1,longlong param_2,uint param_3,undefined8 param_4,ushort *param_5
                  )

{
  byte bVar1;
  ushort uVar2;
  int iVar3;
  
  if (0xe < param_3) {
    uVar2 = *(ushort *)(param_2 + 0xc) >> 8 | *(ushort *)(param_2 + 0xc) << 8;
    if (uVar2 == 0x800) {
      FUN_180167610(param_1,param_2 + 0xe);
      return;
    }
    if (uVar2 == 0x806) {
      if ((((0x1b < param_3 - 0xe) && (*(char *)(param_2 + 0x12) == '\x06')) &&
          (*(char *)(param_2 + 0x13) == '\x04')) &&
         (((*(short *)(param_2 + 0xe) == 0x100 && (*(short *)(param_2 + 0x10) == 8)) &&
          (uVar2 = *(ushort *)(param_2 + 0x14) >> 8 | *(ushort *)(param_2 + 0x14) << 8,
          (ushort)(uVar2 - 1) < 2)))) {
        *param_5 = *param_5 | 8;
        if (((uVar2 == 2) && ((*(byte *)(param_2 + 0x20) & 1) == 0)) &&
           ((*(short *)(param_2 + 0x20) != 0 ||
            ((*(short *)(param_2 + 0x22) != 0 || (*(short *)(param_2 + 0x24) != 0)))))) {
          if ((*(int *)(param_2 + 0x26) != -1) &&
             (((bVar1 = (byte)*(int *)(param_2 + 0x26), bVar1 != 0 && (bVar1 != 0x7f)) &&
              ((bVar1 & 0xf0) != 0xe0)))) {
            FUN_180166fd0(param_1,param_1 + 0x78,param_2 + 0x26,4,"if/arp");
          }
        }
        iVar3 = nocrt_memcmp(param_2 + 0x16,param_1,6);
        if (iVar3 == 0) {
          if (((*(int *)(param_2 + 0x1c) != -1) &&
              (bVar1 = (byte)*(int *)(param_2 + 0x1c), bVar1 != 0)) &&
             ((bVar1 != 0x7f && ((bVar1 & 0xf0) != 0xe0)))) {
            FUN_180166d50(param_1,1,param_2 + 0x1c,"if/arp");
          }
        }
      }
    }
    else if (uVar2 == 0x86dd) {
      FUN_1801677d0(param_1,param_2 + 0xe);
      return;
    }
  }
  return;
}

