
void * __cdecl memcpy(void *_Dst,void *_Src,size_t _Size)

{
  ulonglong uVar1;
  undefined8 *puVar2;
  undefined8 *puVar3;
  undefined8 *puVar4;
  undefined8 *puVar5;
  
                    /* 0x428e0  1623  memcpy
                       0x428e0  1628  nocrt_memcpy */
  puVar3 = _Dst;
  for (uVar1 = _Size >> 3; uVar1 != 0; uVar1 = uVar1 - 1) {
    *puVar3 = *(undefined8 *)_Src;
    _Src = (undefined8 *)((longlong)_Src + 8);
    puVar3 = puVar3 + 1;
  }
  puVar2 = _Src;
  puVar4 = puVar3;
  if ((_Size & 4) != 0) {
    puVar4 = (undefined8 *)((longlong)puVar3 + 4);
    puVar2 = (undefined8 *)((longlong)_Src + 4);
    *(undefined4 *)puVar3 = *(undefined4 *)_Src;
  }
  puVar3 = puVar2;
  puVar5 = puVar4;
  if ((_Size & 2) != 0) {
    puVar5 = (undefined8 *)((longlong)puVar4 + 2);
    puVar3 = (undefined8 *)((longlong)puVar2 + 2);
    *(undefined2 *)puVar4 = *(undefined2 *)puVar2;
  }
  if ((_Size & 1) != 0) {
    *(undefined1 *)puVar5 = *(undefined1 *)puVar3;
  }
  return _Dst;
}

