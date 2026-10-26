
void FUN_180166fd0(undefined8 param_1,longlong *param_2,undefined8 param_3,undefined1 param_4)

{
  byte bVar1;
  int iVar2;
  byte bVar3;
  
  iVar2 = FUN_180167040(param_2,param_3,param_4);
  if ((-1 < iVar2) && (iVar2 < (int)(uint)*(byte *)(param_2 + 1))) {
    bVar3 = *(byte *)(param_2 + 1) - 1;
    *(byte *)(param_2 + 1) = bVar3;
    if (iVar2 < (int)(uint)bVar3) {
      bVar1 = *(byte *)((longlong)param_2 + 0xb);
      nocrt_memmove((longlong)(int)((uint)bVar1 * iVar2) + *param_2,
                    (longlong)(int)((iVar2 + 1) * (uint)bVar1) + *param_2,
                    (longlong)(int)(((uint)bVar3 - iVar2) * (uint)bVar1));
      return;
    }
  }
  return;
}

