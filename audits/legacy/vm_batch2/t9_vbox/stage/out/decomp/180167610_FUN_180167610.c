
void FUN_180167610(longlong param_1,uint *param_2,uint param_3,byte param_4)

{
  uint uVar1;
  bool bVar2;
  byte bVar3;
  char cVar4;
  ushort uVar5;
  uint *puVar6;
  uint uVar7;
  ushort *puVar8;
  uint uVar9;
  uint uVar10;
  uint local_28 [4];
  
  if (param_3 < 0x14) {
    return;
  }
  uVar1 = *param_2;
  uVar7 = (uVar1 & 0xf) * 4;
  if (uVar7 < 0x14) {
    return;
  }
  if (param_3 < uVar7) {
    return;
  }
  local_28[0] = param_2[3];
  bVar2 = false;
  if (((((local_28[0] == 0xffffffff) || (bVar3 = (byte)local_28[0], bVar3 == 0)) || (bVar3 == 0x7f))
      || ((bVar3 & 0xf0) == 0xe0)) ||
     ((uVar10 = (uint)*(byte *)(param_1 + 0x80), *(byte *)(param_1 + 0x80) != 0 &&
      (**(uint **)(param_1 + 0x78) == local_28[0])))) goto LAB_180167736;
  if (1 < uVar10) {
    bVar3 = *(byte *)(param_1 + 0x83);
    uVar9 = uVar10 - 1;
    if (*(uint *)((ulonglong)(bVar3 * uVar9) + *(longlong *)(param_1 + 0x78)) != local_28[0]) {
      if (uVar9 < 2) goto LAB_1801676fc;
      uVar9 = uVar10 - 2;
      puVar6 = (uint *)((ulonglong)(bVar3 * uVar9) + *(longlong *)(param_1 + 0x78));
      for (; uVar9 != 0; uVar9 = uVar9 - 1) {
        if (*puVar6 == local_28[0]) goto LAB_1801676f7;
        puVar6 = (uint *)((longlong)puVar6 - (ulonglong)bVar3);
      }
      uVar9 = 0xffffffff;
    }
LAB_1801676f7:
    if (-1 < (int)uVar9) goto LAB_180167736;
  }
LAB_1801676fc:
  cVar4 = RTNetIPv4IsHdrValid(param_2,param_3,param_3,param_4 ^ 1);
  if (cVar4 == '\0') {
    return;
  }
  FUN_180166e80(param_1,1,local_28,"if/ipv4");
  bVar2 = true;
LAB_180167736:
  if (((*(char *)((longlong)param_2 + 9) == '\x11') && (uVar7 + 0xf9 <= param_3)) && (param_4 == 0))
  {
    puVar8 = (ushort *)((ulonglong)uVar7 + (longlong)param_2);
    uVar5 = puVar8[1] >> 8 | puVar8[1] << 8;
    if ((((uVar5 == 0x43) || ((ushort)(*puVar8 >> 8 | *puVar8 << 8) == 0x43)) &&
        (((ushort)(*puVar8 >> 8 | *puVar8 << 8) == 0x44 || (uVar5 == 0x44)))) &&
       ((bVar2 || (cVar4 = RTNetIPv4IsHdrValid(param_2,param_3,param_3,1), cVar4 != '\0')))) {
      FUN_180169a70(*(undefined8 *)(param_1 + 0x50),param_2,puVar8,param_3 + (uVar1 & 0xf) * -4);
    }
  }
  return;
}

