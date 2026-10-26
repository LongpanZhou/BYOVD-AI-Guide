
void FUN_18016c1b0(longlong param_1,undefined8 param_2,longlong param_3,uint param_4)

{
  byte bVar1;
  ushort uVar2;
  int iVar3;
  uint uVar4;
  ulonglong uVar5;
  uint uVar6;
  byte *pbVar7;
  ulonglong uVar8;
  ushort *puVar9;
  byte bVar10;
  
  if ((((0xd < param_4) && (0x27 < param_4 - 0xe)) && (*(char *)(param_3 + 0x14) == ':')) &&
     (*(char *)(param_3 + 0x15) == -1)) {
    param_4 = param_4 - 0x36;
    puVar9 = (ushort *)(param_3 + 0x36);
    if (3 < param_4) {
      bVar1 = *(byte *)puVar9;
      bVar10 = 1;
      if (bVar1 == 0x85) {
        uVar4 = 8;
      }
      else if (bVar1 == 0x86) {
        uVar4 = 0x10;
      }
      else if (bVar1 == 0x87) {
        uVar4 = 0x18;
      }
      else {
        if (bVar1 != 0x88) {
          return;
        }
        uVar4 = 0x18;
        bVar10 = 2;
      }
      if ((uVar4 <= param_4) && (*(char *)(param_3 + 0x37) == '\0')) {
        param_4 = param_4 - uVar4;
        pbVar7 = (byte *)((ulonglong)uVar4 + (longlong)puVar9);
        if (7 < param_4) {
          while( true ) {
            uVar4 = (uint)((ulonglong)pbVar7[1] * 8);
            if (param_4 < uVar4) break;
            if (*pbVar7 == bVar10) {
              if (uVar4 != 8) {
                return;
              }
              iVar3 = nocrt_memcmp(pbVar7 + 2,param_2,6);
              if (iVar3 != 0) {
                return;
              }
              *(undefined4 *)(pbVar7 + 2) = *(undefined4 *)(param_1 + 0x78);
              *(undefined2 *)(pbVar7 + 6) = *(undefined2 *)(param_1 + 0x7c);
              *(undefined2 *)(param_3 + 0x38) = 0;
              uVar2 = *(ushort *)(param_3 + 0x12) >> 8 | *(ushort *)(param_3 + 0x12) << 8;
              uVar4 = (uint)uVar2;
              uVar5 = RTNetIPv6PseudoChecksum(param_3 + 0xe);
              if (1 < uVar2) {
                uVar6 = (uVar2 - 2 >> 1) + 1;
                uVar8 = (ulonglong)uVar6;
                uVar4 = uVar4 + uVar6 * -2;
                do {
                  uVar2 = *puVar9;
                  puVar9 = puVar9 + 1;
                  uVar5 = (ulonglong)((int)uVar5 + (uint)uVar2);
                  uVar8 = uVar8 - 1;
                } while (uVar8 != 0);
              }
              if (0 < (int)uVar4) {
                uVar5 = (ulonglong)((int)uVar5 + (uint)(byte)*puVar9);
              }
              uVar8 = uVar5 >> 0x10 & 0xffff;
              uVar4 = (uint)uVar8;
              while (uVar4 != 0) {
                uVar4 = ((uint)uVar5 & 0xffff) + (int)uVar8;
                uVar5 = (ulonglong)uVar4;
                uVar4 = uVar4 >> 0x10;
                uVar8 = (ulonglong)uVar4;
              }
              *(ushort *)(param_3 + 0x38) = ~(ushort)uVar5;
              return;
            }
            param_4 = param_4 - uVar4;
            pbVar7 = pbVar7 + (ulonglong)pbVar7[1] * 8;
            if (param_4 < 8) {
              return;
            }
          }
        }
      }
    }
  }
  return;
}

