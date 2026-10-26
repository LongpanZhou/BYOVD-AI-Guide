
int FUN_18016aac0(uint *param_1,longlong param_2,undefined4 *param_3)

{
  ushort uVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  ulonglong uVar5;
  void *_Dst;
  undefined8 *puVar6;
  undefined8 *_Dst_00;
  undefined8 *local_res10;
  uint *local_res20;
  undefined8 *local_38 [2];
  
  _Dst_00 = (undefined8 *)0x0;
  local_res20 = (uint *)0x0;
  local_res10 = (undefined8 *)0x0;
  if (*(char *)(param_2 + 0x18) == '\0') {
    iVar3 = FUN_18016c360(param_1,*(int *)(param_2 + 0x20),0x42,&local_res20,&local_res10);
    _Dst_00 = local_res10;
  }
  else {
    local_38[0] = (undefined8 *)0x0;
    iVar3 = FUN_18016c360(param_1,*(int *)(param_2 + 0x20) + 8,100,&local_res20,local_38);
    if (-1 < iVar3) {
      _Dst_00 = local_38[0] + 1;
      *local_38[0] = *(undefined8 *)(param_2 + 0x18);
      local_res10 = _Dst_00;
    }
  }
  if (iVar3 < 0) {
    return iVar3;
  }
  memcpy(_Dst_00,*(void **)(param_2 + 0x38),(ulonglong)*(uint *)(param_2 + 0x40));
  uVar1 = *(ushort *)(param_2 + 0x2c);
  if ((uVar1 != 1) &&
     (_Dst = (void *)((ulonglong)*(uint *)(param_2 + 0x40) + (longlong)_Dst_00), 1 < uVar1)) {
    puVar6 = (undefined8 *)(param_2 + 0x50);
    uVar5 = (ulonglong)(uVar1 - 1);
    do {
      uVar2 = *(uint *)(puVar6 + 1);
      memcpy(_Dst,(void *)*puVar6,(ulonglong)uVar2);
      _Dst = (void *)((longlong)_Dst + (ulonglong)uVar2);
      puVar6 = puVar6 + 3;
      uVar5 = uVar5 - 1;
    } while (uVar5 != 0);
  }
  if (param_3 != (undefined4 *)0x0) {
    *(undefined4 *)_Dst_00 = *param_3;
    *(undefined2 *)((longlong)_Dst_00 + 4) = *(undefined2 *)(param_3 + 1);
  }
  uVar2 = *local_res20;
  uVar4 = ((((uVar2 & 0xffffff) + 7 & 0xfffffff8) + local_res20[1]) - (int)param_1) +
          (int)local_res20;
  if (param_1[1] <= uVar4) {
    uVar4 = *param_1;
  }
  LOCK();
  param_1[4] = uVar4;
  UNLOCK();
  *(ulonglong *)(param_1 + 6) = *(longlong *)(param_1 + 6) + (ulonglong)(uVar2 & 0xffffff);
  *(longlong *)(param_1 + 8) = *(longlong *)(param_1 + 8) + 1;
  return 0;
}

