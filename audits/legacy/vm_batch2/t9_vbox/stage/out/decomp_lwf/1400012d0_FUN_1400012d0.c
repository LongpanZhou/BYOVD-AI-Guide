
void FUN_1400012d0(undefined8 *param_1)

{
  int iVar1;
  
  iVar1 = RTSemFastMutexCreate(param_1);
  if (-1 < iVar1) {
    param_1[1] = 0;
    param_1[2] = &LAB_140001270;
    param_1[3] = FUN_140001190;
    param_1[4] = 0x4674654e786f4256;
    *(undefined2 *)(param_1 + 5) = 0x746c;
    *(undefined1 *)((longlong)param_1 + 0x2a) = 0;
    param_1[0xb] = FUN_140001a30;
    *(undefined1 *)((longlong)param_1 + 100) = 0;
  }
  return;
}

