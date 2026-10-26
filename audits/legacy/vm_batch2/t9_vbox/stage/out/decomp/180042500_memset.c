
void * __cdecl memset(void *_Dst,int _Val,size_t _Size)

{
  ulonglong uVar1;
  ulonglong uVar2;
  ulonglong *puVar3;
  
                    /* 0x42500  1624  memset
                       0x42500  1630  nocrt_memset */
  uVar1 = (ulonglong)(uint)_Val & 0xff;
  puVar3 = _Dst;
  if (0x1f < _Size) {
    uVar1 = (ulonglong)(_Val & 0xff) * 0x101010101010101;
    for (uVar2 = _Size >> 3; uVar2 != 0; uVar2 = uVar2 - 1) {
      *puVar3 = uVar1;
      puVar3 = puVar3 + 1;
    }
    _Size = _Size & 7;
  }
  for (; _Size != 0; _Size = _Size - 1) {
    *(char *)puVar3 = (char)uVar1;
    puVar3 = (ulonglong *)((longlong)puVar3 + 1);
  }
  return _Dst;
}

