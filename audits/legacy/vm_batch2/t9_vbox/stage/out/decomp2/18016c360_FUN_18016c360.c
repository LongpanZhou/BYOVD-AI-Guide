
undefined8
FUN_18016c360(uint *param_1,uint param_2,undefined1 param_3,longlong *param_4,longlong *param_5)

{
  uint *puVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  ulonglong uVar5;
  bool bVar6;
  
  uVar2 = param_1[5];
  uVar5 = (ulonglong)uVar2;
  uVar4 = param_2 + 7 & 0xfffffff8;
  uVar3 = param_1[2];
  if (uVar2 < uVar3) {
    if ((ulonglong)(uVar3 - uVar2) <= (ulonglong)uVar4 + 8) goto LAB_18016c480;
    uVar4 = uVar2 + 8 + uVar4;
  }
  else {
    if ((ulonglong)(param_1[1] - uVar2) < (ulonglong)uVar4 + 8) {
      if (uVar4 < uVar3 - *param_1) {
        LOCK();
        bVar6 = uVar2 == param_1[5];
        if (bVar6) {
          param_1[5] = *param_1 + uVar4;
        }
        UNLOCK();
        if (!bVar6) {
          return 0xffffffea;
        }
        *(undefined1 *)((longlong)param_1 + uVar5 + 3) = param_3;
        puVar1 = (uint *)((longlong)param_1 + uVar5);
        *puVar1 = *puVar1 & 0xff000000;
        *puVar1 = *puVar1 | param_2 & 0xffffff;
        puVar1[1] = *param_1 - uVar2;
        *param_4 = (longlong)puVar1;
        *param_5 = (ulonglong)*param_1 + (longlong)param_1;
        return 0;
      }
LAB_18016c480:
      *param_4 = 0;
      *param_5 = 0;
      *(longlong *)(param_1 + 10) = *(longlong *)(param_1 + 10) + 1;
      return 0xffffffd7;
    }
    uVar4 = uVar2 + 8 + uVar4;
    if (param_1[1] <= uVar4) {
      uVar4 = *param_1;
    }
  }
  LOCK();
  bVar6 = uVar2 == param_1[5];
  if (bVar6) {
    param_1[5] = uVar4;
  }
  UNLOCK();
  if (!bVar6) {
    return 0xffffffea;
  }
  param_1 = (uint *)((longlong)param_1 + uVar5);
  *(undefined1 *)((longlong)param_1 + 3) = param_3;
  *param_1 = *param_1 & 0xff000000;
  *param_1 = *param_1 | param_2 & 0xffffff;
  param_1[1] = 8;
  *param_4 = (longlong)param_1;
  *param_5 = (longlong)(param_1 + 2);
  return 0;
}

