
int FUN_1801661f0(undefined1 *param_1,void *param_2,ulonglong param_3,int param_4,int param_5,
                 void *param_6,uint *param_7,int *param_8)

{
  undefined2 uVar1;
  uint uVar2;
  undefined4 uVar3;
  longlong lVar4;
  byte bVar5;
  byte bVar6;
  ushort uVar7;
  ushort uVar8;
  int iVar9;
  byte bVar10;
  ushort uVar11;
  ulonglong uVar12;
  longlong lVar13;
  short sVar14;
  
  if (param_4 == 0) {
    bVar10 = param_1[1];
    bVar6 = bVar10;
  }
  else {
    bVar10 = param_1[6];
    bVar6 = param_1[1];
  }
  uVar2 = (uint)*(ushort *)(param_1 + 2) * param_4;
  lVar13 = (longlong)param_2 + (ulonglong)bVar10 + (ulonglong)uVar2;
  iVar9 = 0;
  if (param_4 + 1 == param_5) {
    bVar5 = bVar6;
    if (param_4 != 0) {
      bVar5 = param_1[6];
    }
    iVar9 = ((int)param_3 - (uint)bVar5) - uVar2;
  }
  else {
    if (param_4 == 0) {
      iVar9 = (uint)bVar6 - (uint)(byte)param_1[6];
    }
    iVar9 = (uint)*(ushort *)(param_1 + 2) - iVar9;
  }
  memcpy(param_6,param_2,(ulonglong)bVar6);
  sVar14 = (short)iVar9;
  switch(*param_1) {
  case 1:
    uVar7 = *(ushort *)(param_1 + 2);
    bVar6 = param_1[5];
    uVar3 = FUN_18016c4b0(param_6,param_1[4],iVar9,param_4,bVar10);
    lVar4 = (ulonglong)bVar6 + (longlong)param_6;
    uVar2 = *(uint *)(lVar4 + 4);
    uVar2 = (uVar2 >> 0x18 | (uVar2 & 0xff0000) >> 8 | (uVar2 & 0xff00) << 8 | uVar2 << 0x18) +
            (uint)uVar7 * param_4;
    *(uint *)(lVar4 + 4) =
         uVar2 >> 0x18 | (uVar2 & 0xff0000) >> 8 | (uVar2 & 0xff00) << 8 | uVar2 * 0x1000000;
    if (param_4 + 1 != param_5) {
      *(byte *)(lVar4 + 0xd) = (byte)((uint)*(undefined4 *)(lVar4 + 0xc) >> 8) & 0xf6;
    }
    uVar1 = RTNetTCPChecksum(uVar3,lVar4,lVar13,iVar9);
    *(undefined2 *)(lVar4 + 0x10) = uVar1;
    break;
  case 2:
    bVar6 = param_1[5];
    uVar7 = *(ushort *)(param_1 + 2);
    uVar11 = (sVar14 - (ushort)(byte)param_1[4]) + -0x28 + (ushort)bVar10;
    uVar8 = uVar11 * 0x100;
    lVar4 = (longlong)param_6 + (ulonglong)(byte)param_1[4];
    *(ushort *)(lVar4 + 4) = uVar11 >> 8 | uVar8;
    uVar3 = RTNetIPv6PseudoChecksumEx
                      (lVar4,CONCAT71((uint7)(byte)(uVar8 >> 8),6),
                       (sVar14 - (ushort)bVar6) + (ushort)bVar10);
    lVar4 = (ulonglong)bVar6 + (longlong)param_6;
    uVar2 = *(uint *)(lVar4 + 4);
    uVar2 = (uVar2 >> 0x18 | (uVar2 & 0xff0000) >> 8 | (uVar2 & 0xff00) << 8 | uVar2 << 0x18) +
            (uint)uVar7 * param_4;
    *(uint *)(lVar4 + 4) =
         uVar2 >> 0x18 | (uVar2 & 0xff0000) >> 8 | (uVar2 & 0xff00) << 8 | uVar2 * 0x1000000;
    if (param_4 + 1 != param_5) {
      *(byte *)(lVar4 + 0xd) = (byte)((uint)*(undefined4 *)(lVar4 + 0xc) >> 8) & 0xf6;
    }
    uVar1 = RTNetTCPChecksum(uVar3,lVar4,lVar13,iVar9);
    *(undefined2 *)(lVar4 + 0x10) = uVar1;
    break;
  case 3:
    if (param_4 == 0) {
      uVar12 = (ulonglong)(byte)param_1[5];
      uVar7 = *(ushort *)(uVar12 + 4 + (longlong)param_2);
      if (param_3 < (ushort)(uVar7 >> 8 | uVar7 << 8) + uVar12) {
        uVar7 = 0xffff;
        if (param_3 - uVar12 < 0xffff) {
          uVar7 = (ushort)(param_3 - uVar12);
          uVar7 = uVar7 >> 8 | uVar7 << 8;
          *(ushort *)(uVar12 + 4 + (longlong)param_2) = uVar7;
        }
        else {
          *(undefined2 *)(uVar12 + 4 + (longlong)param_2) = 0xffff;
        }
      }
      if ((ushort)(uVar7 >> 8 | uVar7 << 8) < 8) {
        *(undefined2 *)(uVar12 + 4 + (longlong)param_2) = 0x800;
      }
      bVar6 = param_1[5];
      uVar3 = RTNetIPv4PseudoChecksum((ulonglong)(byte)param_1[4] + (longlong)param_2);
      uVar1 = RTNetUDPChecksum(uVar3,(ulonglong)bVar6 + (longlong)param_2);
      *(undefined2 *)((ulonglong)bVar6 + 6 + (longlong)param_6) = uVar1;
    }
    uVar7 = *(ushort *)(param_1 + 2);
    lVar13 = (longlong)param_6 + (ulonglong)(byte)param_1[4];
    uVar11 = ((ushort)bVar10 - (ushort)(byte)param_1[4]) + sVar14;
    uVar8 = 0x2000;
    *(ushort *)(lVar13 + 2) = uVar11 >> 8 | uVar11 * 0x100;
    if (param_4 + 1 == param_5) {
      uVar8 = 0;
    }
    uVar7 = (ushort)((uint)uVar7 * param_4 >> 3);
    *(ushort *)(lVar13 + 6) = (uVar8 | uVar7) >> 8 | uVar7 << 8;
    uVar1 = RTNetIPv4HdrChecksum(lVar13);
    *(undefined2 *)(lVar13 + 10) = uVar1;
    break;
  case 4:
    bVar6 = param_1[4];
    goto LAB_1801665b2;
  case 5:
    uVar7 = (sVar14 - (ushort)(byte)param_1[4]) + (ushort)bVar10;
    lVar4 = (longlong)param_6 + (ulonglong)(byte)param_1[4];
    *(ushort *)(lVar4 + 2) = uVar7 >> 8 | uVar7 * 0x100;
    uVar7 = (*(ushort *)(lVar4 + 4) >> 8 | *(ushort *)(lVar4 + 4) << 8) + (short)param_4;
    *(ushort *)(lVar4 + 4) = uVar7 >> 8 | uVar7 * 0x100;
    uVar1 = RTNetIPv4HdrChecksum(lVar4);
    *(undefined2 *)(lVar4 + 10) = uVar1;
    RTNetIPv4PseudoChecksum(lVar4);
    bVar6 = param_1[5];
    uVar7 = *(ushort *)(param_1 + 2);
    bVar5 = (*(byte *)((ulonglong)(byte)param_1[4] + (longlong)param_6) & 0xf) * '\x04' + param_1[4]
    ;
    lVar4 = (ulonglong)bVar5 + (longlong)param_6;
    uVar11 = (sVar14 - (ushort)bVar5) + -0x28 + (ushort)bVar10;
    uVar8 = uVar11 * 0x100;
    *(ushort *)(lVar4 + 4) = uVar11 >> 8 | uVar8;
    uVar3 = RTNetIPv6PseudoChecksumEx
                      (lVar4,CONCAT71((uint7)(byte)(uVar8 >> 8),6),
                       (sVar14 - (ushort)bVar6) + (ushort)bVar10);
    lVar4 = (ulonglong)bVar6 + (longlong)param_6;
    uVar2 = *(uint *)(lVar4 + 4);
    uVar2 = (uVar2 >> 0x18 | (uVar2 & 0xff0000) >> 8 | (uVar2 & 0xff00) << 8 | uVar2 << 0x18) +
            (uint)uVar7 * param_4;
    *(uint *)(lVar4 + 4) =
         uVar2 >> 0x18 | (uVar2 & 0xff0000) >> 8 | (uVar2 & 0xff00) << 8 | uVar2 * 0x1000000;
    if (param_4 + 1 != param_5) {
      *(byte *)(lVar4 + 0xd) = (byte)((uint)*(undefined4 *)(lVar4 + 0xc) >> 8) & 0xf6;
    }
    uVar1 = RTNetTCPChecksum(uVar3,lVar4,lVar13,iVar9);
    *(undefined2 *)(lVar4 + 0x10) = uVar1;
    break;
  case 6:
    FUN_18016c4b0(param_6,param_1[4],iVar9,param_4,bVar10);
    bVar6 = (*(byte *)((ulonglong)(byte)param_1[4] + (longlong)param_6) & 0xf) * '\x04' + param_1[4]
    ;
LAB_1801665b2:
    bVar5 = param_1[5];
    uVar8 = (sVar14 - (ushort)bVar6) + -0x28 + (ushort)bVar10;
    uVar7 = uVar8 * 0x100;
    uVar11 = (sVar14 - (ushort)bVar5) + (ushort)bVar10;
    *(ushort *)((ulonglong)bVar6 + (longlong)param_6 + 4) = uVar8 >> 8 | uVar7;
    uVar3 = RTNetIPv6PseudoChecksumEx
                      ((ulonglong)bVar6 + (longlong)param_6,CONCAT71((uint7)(byte)(uVar7 >> 8),0x11)
                       ,uVar11);
    lVar13 = (ulonglong)bVar5 + (longlong)param_6;
    *(ushort *)(lVar13 + 4) = uVar11 >> 8 | uVar11 * 0x100;
    uVar1 = RTNetUDPChecksum(uVar3,lVar13);
    *(undefined2 *)(lVar13 + 6) = uVar1;
  }
  *param_7 = (uint)bVar10;
  *param_8 = iVar9;
  return (uint)*(ushort *)(param_1 + 2) * param_4 + (uint)bVar10;
}

