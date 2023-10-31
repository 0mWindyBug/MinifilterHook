#pragma once
#include <ntddk.h>

typedef struct _RESTORE_NODE
{
	PVOID AddrOfCallback;
	LONG64 Callback;
	struct _RESTORE_NODE* Next;

}RESTORE_NODE, *PRESTORE_NODE;

