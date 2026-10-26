
void FUN_1801677d0(longlong param_1,longlong param_2,uint param_3)

{
  byte bVar1;
  longlong lVar2;
  uint uVar3;
  longlong *plVar4;
  uint uVar5;
  undefined1 local_28 [16];
  undefined1 local_18 [16];
  
  if (param_3 < 0x28) {
    return;
  }
  local_28 = *(undefined1 (*) [16])(param_2 + 8);
  lVar2 = local_28._0_8_;
  local_18._8_8_ = local_28._8_8_;
  if ((lVar2 == 0) && (local_18._8_8_ == 0)) {
    return;
  }
  if (local_28[0] == -1) {
    return;
  }
  if (((((local_28._0_2_ == 0) && (local_28._2_2_ == 0)) && (local_28._4_2_ == 0)) &&
      ((local_28._6_2_ == 0 && (local_28._8_2_ == 0)))) &&
     ((local_28._10_2_ == 0 && ((local_28._12_2_ == 0 && (local_28._14_2_ == 0x100)))))) {
    return;
  }
  if (*(char *)(param_2 + 7) != -1) {
    return;
  }
  uVar5 = (uint)*(byte *)(param_1 + 0x90);
  if (((*(byte *)(param_1 + 0x90) != 0) && (**(longlong **)(param_1 + 0x88) == lVar2)) &&
     ((*(longlong **)(param_1 + 0x88))[1] == local_18._8_8_)) {
    return;
  }
  if (1 < uVar5) {
    bVar1 = *(byte *)(param_1 + 0x93);
    uVar3 = uVar5 - 1;
    plVar4 = (longlong *)((ulonglong)(bVar1 * uVar3) + *(longlong *)(param_1 + 0x88));
    if ((*plVar4 != lVar2) || (plVar4[1] != local_18._8_8_)) {
      if (uVar3 < 2) goto LAB_1801678fe;
      uVar3 = uVar5 - 2;
      plVar4 = (longlong *)((ulonglong)(bVar1 * uVar3) + *(longlong *)(param_1 + 0x88));
      for (; uVar3 != 0; uVar3 = uVar3 - 1) {
        if ((*plVar4 == lVar2) && (plVar4[1] == local_18._8_8_)) goto LAB_1801678fa;
        plVar4 = (longlong *)((longlong)plVar4 - (ulonglong)bVar1);
      }
      uVar3 = 0xffffffff;
    }
LAB_1801678fa:
    if (-1 < (int)uVar3) {
      return;
    }
  }
LAB_1801678fe:
  local_18 = local_28;
  FUN_180166d50(param_1,2,local_28,"if/ipv6");
  return;
}

