
{ ***********************************************************************

QIU Memory Manager 1.12 for Delphi

Description:
	a simple and compact MM for Delphi/XE

Homepage:
  https://code.google.com/p/qiumm/
  by qiusonglin (qiusonglin.hex@gmail.com)

Usage:
 - place this unit as the very first unit under the "uses" section in your
   project's .dpr file.

Other:
 - important: test only by D7,D2010
 - NOT test on the WIN64
 - support multithread, allocate memory for each thread manager.

Support:
 If you have trouble using QMM, you are welcome to drop me an e-mail at the
 address above.

License:
  Released under Mozilla Public License 1.1

  If you find QMM useful or you would like to support further development,
  a donation would be much appreciated.
  My PayPal account is: qiusonglin.hex@gmail.com

Change log:
  plz see: QMM.change.log
  last modified: 2014.01.05 by qiusonglin

 *********************************************************************** }
unit QMM;

interface

{$i QMM.inc}

{$if CompilerVersion < 17.0}
uses Windows;
{$else}
  {$i functions.inc}
{$ifend}

const
  QMM_VERSION = 1.12; 

type
  PSIZE = ^MSIZE;
{$if CompilerVersion < 22}
  MSIZE = Integer;
{$else}
  MSIZE = NativeInt;
{$ifend}
  MADDR = PAnsiChar;

  TMemoryStatus = record
    // allocate size = total_alloc - total_free
    total_alloc: Int64;
    total_free: Int64;
    // small allocate size = small_alloc - small_free
    small_alloc: Int64;
    small_free: Int64;
    // medium allocate size = medium_alloc - medium_free
    medium_alloc: Int64;
    medium_free: Int64;
    // large allocate size = large_alloc - large_free
    large_alloc: Int64;
    large_free: Int64;
    block_count: Integer;
  end;


{$ifdef debug}
function debug_memory_get(size: MSIZE): Pointer;
function debug_memory_alloc(size: MSIZE): Pointer;
function debug_memory_realloc(p: Pointer; size: MSIZE): Pointer;
function debug_memory_free(p: Pointer): Integer;
{$endif}

function qmm_memory_get(size: MSIZE): Pointer;
function qmm_memory_alloc(size: MSIZE): Pointer;
function qmm_memory_realloc(p: Pointer; new_size: MSIZE): Pointer;
function qmm_memory_free(p: Pointer): Integer;

function memory_register_leak(p: Pointer): Boolean;
function memory_unregister_leak(p: Pointer): Boolean;

function memory_status: TMemoryStatus;

{$ifdef debug}

type
  TDebugMemOP = (opGet, opRealloc, opFree);

var
  //
  // memory manager event callbacks on DEBUG
  // note: the callbacks is not threadsafe.
  //
  // the memory operations out of bounds, will trigger the event
  on_memory_error_proc: procedure(op: TDebugMemOP; address: Pointer; size: MSIZE);
  // after memory_get
  on_notify_get_proc: procedure(ptr: Pointer; size: MSIZE);
  // after memory_realloc
  on_notify_realloc_proc: procedure(old_ptr: Pointer; old_size: MSIZE;
    new_ptr: Pointer; new_size: MSIZE);
  // after memory_free
  on_notify_free_proc: procedure(ptr: Pointer; size: MSIZE; rc: Integer);
{$endif}

{$if CompilerVersion < 18}
var
  // report memory leak
  ReportMemoryLeaksOnShutdown: Boolean = false;
{$ifend}

implementation

{$if CompilerVersion < 17.0}
  {$i D2007_move.inc}
{$ifend}

type
  PSpinLock = ^TSpinLock;
  TSpinLock = TRTLCriticalSection;

procedure spinlock_init(lock: PSpinLock);
{$ifdef has_inline} inline; {$endif}
begin
  InitializeCriticalSectionAndSpinCount(lock^, 100);
end;

procedure spinlock_free(lock: PSpinLock);
{$ifdef has_inline} inline; {$endif}
begin
  DeleteCriticalSection(lock^);
end;

procedure spinlock_lock(lock: PSpinLock; timeout: Integer = 0);
{$ifdef has_inline} inline; {$endif}
begin
  EnterCriticalSection(lock^);
end;

procedure spinlock_unlock(lock: PSpinLock);
{$ifdef has_inline} inline; {$endif}
begin
  LeaveCriticalSection(lock^);
end;

var
  cMinAllocSize: MSIZE = 64 * 1024;

function align_bytes(size: MSIZE): MSIZE;
{$ifdef has_inline} inline; {$endif}
begin
  if size < cMinAllocSize then
    result := cMinAllocSize
  else
  if (size and (size - 1)) = 0 then
    result := size
  else
    result := (size + cMinAllocSize - 1) and -cMinAllocSize;
end;

function virtual_alloc(var size: MSIZE): Pointer;
{$ifdef has_inline} inline; {$endif}
begin
  size := align_bytes(size);
  result := VirtualAlloc(nil, size, MEM_COMMIT, PAGE_READWRITE);
  if result = nil then
    System.Error(reOutOfMemory);
end;

function virtual_free(data: Pointer): Boolean; overload;
{$ifdef has_inline} inline; {$endif}
begin
  result := VirtualFree(data, 0, MEM_RELEASE);
end;

function virtual_free(data: Pointer; size: MSIZE): Boolean; overload;
{$ifdef has_inline} inline; {$endif}
var
  info: TMemoryBasicInformation;
begin
  result := true;
  while size > 0 do
  begin
    VirtualQuery(data, info, sizeof(info));
    size := size - MSIZE(info.RegionSize);
    result := result and VirtualFree(data, 0, MEM_RELEASE);
    data := Pointer(MADDR(data) + info.RegionSize);
  end;
end;

// copy from fastmm4
procedure move32(const ASource; var ADest; ACount: MSIZE);
asm
{$ifdef win32}
  fild qword ptr [eax]
  fild qword ptr [eax + 8]
  fild qword ptr [eax + 16]
  fild qword ptr [eax + 24]
  fistp qword ptr [edx + 24]
  fistp qword ptr [edx + 16]
  fistp qword ptr [edx + 8]
  fistp qword ptr [edx]
{$else}
.noframe
  movdqa xmm0, [rcx]
  movdqa xmm1, [rcx + 16]
  movdqa [rdx], xmm0
  movdqa [rdx + 16], xmm1
{$endif}
end;

// copy from fastmm4
procedure move64(const ASource; var ADest; ACount: MSIZE);
asm
{$ifdef win32}
  fild qword ptr [eax]
  fild qword ptr [eax + 8]
  fild qword ptr [eax + 16]
  fild qword ptr [eax + 24]
  fild qword ptr [eax + 32]
  fild qword ptr [eax + 40]
  fild qword ptr [eax + 48]
  fild qword ptr [eax + 56]
  fistp qword ptr [edx + 56]
  fistp qword ptr [edx + 48]
  fistp qword ptr [edx + 40]
  fistp qword ptr [edx + 32]
  fistp qword ptr [edx + 24]
  fistp qword ptr [edx + 16]
  fistp qword ptr [edx + 8]
  fistp qword ptr [edx]
{$else}
.noframe
  movdqa xmm0, [rcx]
  movdqa xmm1, [rcx + 16]
  movdqa xmm2, [rcx + 32]
  movdqa xmm3, [rcx + 48]
  movdqa [rdx], xmm0
  movdqa [rdx + 16], xmm1
  movdqa [rdx + 32], xmm2
  movdqa [rdx + 48], xmm3
{$endif}
end;

{$ifopt c+}
function assert(condition: Boolean; step: Integer = 0): Boolean;
begin
  result := condition;
  if not result then
  begin
  {$ifdef win32}
    asm int 3 end;
  {$else}
    DebugBreak;
  {$endif}
    sleep(step);
  end;
end;
{$endif}

type
  PPLinkData = ^PLinkData;
  PLinkData = ^TLinkData;
  TLinkData = record
    data: Pointer;
    next: Pointer;
  end;

const
  FLAG_NONE           = $0;
  FLAG_USED           = $1;
  FLAG_LINK           = $2;
  FLAG_WAITFORFREE    = $4;
  FLAG_REGLEAK        = $8;
  FLAG_MASK           = FLAG_USED or FLAG_LINK or FLAG_WAITFORFREE or FLAG_REGLEAK;

  FLAG_BLOCK_MINI     = Integer($10000000);
  FLAG_BLOCK_SMALL    = Integer($20000000);
  FLAG_BLOCK_MEDIUM   = Integer($40000000);
  FLAG_BLOCK_LARGE    = Integer($80000000);
  FLAG_BLOCK_MASK     = Integer($F0000000);

const
  MIN_MEM_SIZE        = $20;
  MEM_PAGE_SIZE       = 1024 * 4;

  MAX_SIZE_MINI       = 256;
  MAX_SIZE_SMALL      = 1024 * 2;
  MAX_SIZE_MEDIUM     = 1024 * 128;

  BIT_STEP_MINI       = 5;
  BIT_STEP_SMALL      = 7;

  SIZE_BLOCK          = 1 * 1024 * 1024;
  MAX_THEAD_BLOCK     = 4;
  MAX_MANAGER_BLOCK   = 4;

  BIT_LINK_MEDIUM     = 13;
  MAX_LINK_MEDIUM     = 16;

const
  PER_THREAD_BUFFER_COUNT = 64;

type
  PMem = ^TMem;
  PMemBlock = ^TMemBlock;
  PMemItem = ^TMemItem;
  PPMemItems = ^PMemItems;
  PMemItems = ^TMemItems;
  PMemItemsBlock = ^TMemItemsBlock;

  PMemArray = ^TMemArray;
  TMemArray = array [0..0] of PMem;

  PMemItemBuffer = ^TMemItemBuffer;
  TMemItemBuffer = record
    next, prev: PMemItemBuffer;
    owner: PMemItems;
    item_count: Byte;
    used_count: Byte;
    free_index: Byte;
    free_item: PMemItem;
    idle_item: PMemItem;
    mem_block: Pointer;
    data: array [0..0] of Byte;
  end;

  TMemItems = record
    owner: PMemItemsBlock;
    item_size: Integer;
    item_step: Integer;
    item_flag_used: MSIZE;
    first_buffer: PMemItemBuffer;
    items_buffer: PMemItemBuffer;
    move_upsize: procedure(const source; var dest; count: MSIZE);
  end;

  TMemItemsBlock = record
    owner: Pointer;
    bflag: MSIZE;
    first_keep: LongBool;
    count, min, max, bits, step: Integer;
    lists: array [0..0] of PMemItems;
  end;

  PFreeItemBuffer = ^TFreeItemBuffer;
  TFreeItemBuffer = record
    next: PFreeItemBuffer;
    items: array [0..0] of TLinkData;
  end;

  TMemBlock = record
    owner: Pointer;
    used: LongBool;
    src_ptr: Pointer;
    end_ptr: Pointer;
    src_len: MSIZE;
    curr_mem: PMem;
    next, prev: PMemBlock;
  end;

  TMem = record
    flag: MSIZE;
    size: MSIZE;
    owner: PMemBlock;
    case Byte of
      0: (prev: PMem);
      1: (item_buffer: PMemItemBuffer);
  end;

  TMemItem = record
    mem: TMem;
    item_next: PMemItem;
  end;

  PMemLink = ^TMemLink;
  TMemLink = record
    mem: TMem;
    link_next, link_prev: PMemLink;
    link_index: Integer;
    link_size: PSIZE;
  end;

  PMemLinkArray = ^TMemLinkArray;
  TMemLinkArray = array [0..0] of PMemLink;

type
  PMemManager = ^TMemManager;
  PThreadMemory = ^TThreadMemory;

  TThreadMemory = object
  private
    initialized: Boolean;
    active: Boolean;
    owner: PMemManager;
    lock: TSpinLock;
    status: TMemoryStatus;
    block_buffer: PLinkData;
    block_buffer_count: Integer;
    function create_block(need_size: MSIZE): Pointer;
    procedure release_block(block: PMemBlock);
  private
    procedure add_link(mem: PMem);
    {$ifdef has_inline} inline; {$endif}
    procedure del_link(mem: PMem; mem_size: MSIZE);
    {$ifdef has_inline} inline; {$endif}
  private
    mini_block: PMemItemsBlock;
    small_block: PMemItemsBlock;
    function create_item_buffer(items: PMemItems): PMemItemBuffer;
    function mem_item_get(block: PMemItemsBlock; size: MSIZE): Pointer;
    {$ifdef has_inline} inline; {$endif}
    function mem_item_free(p: PMem): Integer;
    {$ifdef has_inline} inline; {$endif}
    procedure mem_item_free_buffer(buffer: PMemItemBuffer);
    {$ifdef has_inline} inline; {$endif}
  private
    owner_block: TMemBlock;
    medium_block: PMemBlock;
    medium_total_link_size: MSIZE;
    medium_links: array [0..MAX_LINK_MEDIUM - 1] of PMemLink;
    medium_link_sizes: array [0..MAX_LINK_MEDIUM - 1] of MSIZE;
    function medium_mem_get_with_leak(var size: MSIZE): Pointer;
    {$ifdef has_inline} inline; {$endif}
    procedure medium_mem_free_with_leak(p: Pointer);
    {$ifdef has_inline} inline; {$endif}
    function medium_get_idle(var size: MSIZE): Pointer;
    function medium_mem_get(size: MSIZE): Pointer;
    function medium_mem_realloc(curr: PMem; new_size: MSIZE): Pointer;
    function medium_mem_free(curr: PMem): Integer;
  private
    function large_mem_get(size: MSIZE): Pointer;
    {$ifdef has_inline} inline; {$endif}
    function large_mem_realloc(p: Pointer; new_size: MSIZE): Pointer;
    {$ifdef has_inline} inline; {$endif}
    function large_mem_free(p: Pointer): Integer;
    {$ifdef has_inline} inline; {$endif}
  public
    other_thread_free_lists: PLinkData;
    procedure do_freemem_from_other_thread;
    procedure freemem_by_other_thread(p: Pointer);
  public
    function memory_get(size: MSIZE): Pointer;
    {$ifdef has_inline} inline; {$endif}
    function memory_realloc(p: Pointer; new_size: MSIZE): Pointer;
    {$ifdef has_inline} inline; {$endif}
    function memory_free(p: Pointer): Integer;
    {$ifdef has_inline} inline; {$endif}
  public
    thread_id: Cardinal;
    link_next_thread: PThreadMemory;
    prev_thread_memory: PThreadMemory;
    next_thread_memory: PThreadMemory;
    procedure initialize(owner_: PMemManager; mini, small: PMemItemsBlock);
    procedure uninitialize;
    procedure reactive(thread_id_: Cardinal);
    procedure deactive;
  end;

{$ifndef has_thread_exit}
  PJump = ^TJump;
  TJump = packed record
    op_code  : Byte;
    distance: Integer;
  end;
{$endif}

  TMemManager = object
  private
    lock: TSpinlock;
    link_idle: PLinkData;
    link_buffer: PLinkData;
    mem_idle: PThreadMemory;
    mem_buffer: PLinkData;
    main_mgr: PThreadMemory;
    mem_mgrs: PThreadMemory;
    function pop_link: PLinkData;
    {$ifdef has_inline} inline; {$endif}
    procedure push_link(data: PLinkData);
    {$ifdef has_inline} inline; {$endif}
    procedure create_link_buffer;
    function pop_thread_memory: PThreadMemory;
    {$ifdef has_inline} inline; {$endif}
    procedure push_thread_memory(thread_memory: PThreadMemory);
    {$ifdef has_inline} inline; {$endif}
    procedure create_thread_memory_buffer;
  private
    used_mem_block: PLinkData;
    items_block_lock: TSpinlock;
    idle_items_block_addr: Pointer;
    idle_items_block_size: MSIZE;
    procedure create_mem_items_block(var block: PMemItemsBlock;
      thread: PThreadMemory; block_flag: MSIZE; min, max, bits: Integer);
  public
    leak_lock: TSpinlock;
    leak_list: PLinkData;
    function is_register_leak(address: Pointer): Boolean;
    function register_leak(address: Pointer): Boolean;
    function unregister_leak(address: Pointer): Boolean;
  public
    block_buffer: PLinkData;
    block_lock: TSpinLock;
    block_count: Integer;
    function create_block(var size: MSIZE; need_size: MSIZE): Pointer;
    {$ifdef has_inline} inline; {$endif}
    procedure release_block(block: PMemBlock);
    {$ifdef has_inline} inline; {$endif}
  public
    initialized: Boolean;
    procedure initialize;
    procedure uninitialize;
  public
    thread_count: Integer;
    function get_current_thread_memory(): PThreadMemory;
    {$ifdef has_inline} inline; {$endif}
    function create_thread_memory(thread_id: Cardinal): PThreadMemory;
    procedure release_thread_memory(thread_id: Cardinal);
  end;

const
  SIZE_HEADER = sizeof(TMem);

{$ifdef qmm_debug}

function mcheck_medium(step: Integer; block: PMemBlock; links: PMemLinkArray): Boolean;
var
  end_mem: MADDR;
  i, size, prev_size: MSIZE;
  prev, curr, next: PMem;
begin
  result := true;
  if (block = nil) or not block.used then exit;

  result := assert((block.src_len = SIZE_BLOCK - sizeof(TMemBlock) - SIZE_HEADER), step + 1);
  if not result then exit;
  curr := block.src_ptr;
  end_mem := block.end_ptr;
  while result and (MADDR(curr) < MADDR(end_mem)) do
  begin
    prev := curr.prev;
    size := curr.size;
    next := Pointer(MADDR(curr) + SIZE_HEADER + size);
    if prev <> nil then
    begin
      prev_size := prev.size;
      result := assert(MADDR(curr) = MADDR(prev) + SIZE_HEADER + prev_size, step + 2);
      if not result then break;
    end;
    if MADDR(next) < MADDR(end_mem) then
    begin
      result := assert(MADDR(next.prev) < MADDR(next), step + 3);
      if result then
        result := assert((next.prev = curr), step + 4);
      if result then
        result := assert(MADDR(next) = MADDR(curr) + SIZE_HEADER + size, step + 5);
      if not result then
        break;
    end;
    curr := next;
  end;
  if result then
    result := assert(block.src_len = SIZE_BLOCK - sizeof(TMemBlock) - SIZE_HEADER, step + 6);
  if result then
    result := assert((block.end_ptr = Pointer(MADDR(block) +
      block.src_len + sizeof(TMemBlock) + SIZE_HEADER)), step + 7);
  if result then
  begin
    for i := 0 to MAX_LINK_MEDIUM - 1 do
    begin
      curr := Pointer(links[i]);
      while result and (curr <> nil) do
      begin
        result := assert(curr.flag and FLAG_MASK = FLAG_LINK, step + 8);
        curr := Pointer(PMemLink(curr).link_next);
        if not result then
          break;
      end;
    end;
  end;
end;

{$endif}
procedure mprint(format: PAnsiChar; const argv: array of const);
var
  i: Integer;
  params: array [0..31] of Cardinal;
  buffer: array [0..127] of AnsiChar;
begin
  for i := low(argv) to high(argv) do
    params[i] := argv[i].VInteger;
  buffer[wvsprintfA(buffer, format, @params)] := #0;
  OutputDebugStringA(buffer);
end;

{ TThreadMemory }

procedure TThreadMemory.initialize(owner_: PMemManager; mini, small: PMemItemsBlock);
begin
  if initialized then exit;
  fillchar(self, sizeof(self), #0);
  initialized := true;
  spinlock_init(@lock);
  owner := owner_;
  owner_block.used := true;
  owner_block.owner := @self;
  mini_block := mini;
  small_block := small;
end;

procedure TThreadMemory.uninitialize;

  procedure free_block(var block: PMemBlock); overload;
  var
    next: PMemBlock;
  begin
    while block <> nil do
    begin
      next := block.next;
      virtual_free(block);
      block := next;
    end;
  end;

  procedure free_block(var block: PLinkData); overload;
  var
    link: PLinkData;
  begin
    while block <> nil do
    begin
      link := block.next;
      virtual_free(block.data);
      block := link;
    end;
  end;

begin
  if not initialized then exit;

  free_block(medium_block);
  free_block(block_buffer);
  spinlock_free(@lock);
  fillchar(self, sizeof(self), #0);
end;

procedure TThreadMemory.reactive(thread_id_: Cardinal);
begin
  thread_id := thread_id_;
  if other_thread_free_lists <> nil then
    do_freemem_from_other_thread;
  active := true;
  if MainThreadId = thread_id then
  begin
    if medium_block = nil then
      medium_block := create_block(0);
  end;
end;

procedure TThreadMemory.deactive;

  procedure free_mem_items(block: PMemItemsBlock);
  var
    i: Integer;
    items: PMemItems;
    buffer, next_buffer: PMemItemBuffer;
  begin
    items := Pointer(MADDR(block) + sizeof(TMemItemsBlock) +
      block.count * sizeof(Pointer));
    for i := 0 to block.count - 1 do
    begin
      buffer := items.items_buffer;
      while buffer <> nil do
      begin
        next_buffer := buffer.next;
        if (buffer.used_count = 0) or (buffer.used_count = buffer.free_index) then
        begin
          if buffer = items.first_buffer then
            items.first_buffer := nil;
          mem_item_free_buffer(buffer);
        end;
        buffer := next_buffer;
      end;
      if (items.first_buffer = nil) and (items.items_buffer <> nil) then
        items.first_buffer := items.items_buffer;
      inc(items);
    end;
  end;

var
  mem: PMem;
  next: PLinkData;
  block, next_block: PMemBlock;
begin
  active := false;
  if other_thread_free_lists <> nil then
    do_freemem_from_other_thread;

  free_mem_items(mini_block);
  free_mem_items(small_block);

  block := medium_block;
  while block <> nil do
  begin
    next_block := block.next;
    mem := block.src_ptr;
    if mem.size >= block.src_len then
      release_block(block);
    block := next_block;
  {$ifdef debug}
    mprint('tid: %d deactive release block', [thread_id]);
  {$endif}
  end;
  while block_buffer <> nil do
  begin
    next := block_buffer.next;
    owner.release_block(block_buffer.data);
    block_buffer := next;
  {$ifdef debug}
    mprint('tid: %d deactive release block', [thread_id]);
  {$endif}
  end;
  block_buffer_count := 0;
  thread_id := 0;
end;

procedure TThreadMemory.freemem_by_other_thread(p: Pointer);
var
  item: PLinkData;
begin
  spinlock_lock(@lock);
  with PMem(MADDR(p) - SIZE_HEADER)^ do
    flag := flag or FLAG_WAITFORFREE;
  item := p;
  item.data := p;
  item.next := other_thread_free_lists;
  other_thread_free_lists := item;
  spinlock_unlock(@lock);
end;

procedure TThreadMemory.do_freemem_from_other_thread;
var
  item, next: PLinkData;
begin
  if other_thread_free_lists = nil then exit;

  spinlock_lock(@lock);
  item := other_thread_free_lists;
  other_thread_free_lists := nil;
  spinlock_unlock(@lock);

  while item <> nil do
  begin
    next := item.next;
    memory_free(item.data);
    item := next;
  end;
end;

procedure TThreadMemory.add_link(mem: PMem);
var
  link: PMemLink;
  index: Integer;
  link_address: ^PMemLink;
begin
{$ifopt c+}
  if mem.flag > 0 then
    assert(mem.flag and FLAG_LINK <> FLAG_LINK);
  if mem.flag and FLAG_LINK = FLAG_LINK then exit;
{$endif}
  inc(medium_total_link_size, mem.size);
  mem.flag := FLAG_BLOCK_MEDIUM or FLAG_LINK;

  index := mem.size shr BIT_LINK_MEDIUM;
  if index >= MAX_LINK_MEDIUM then
    index := MAX_LINK_MEDIUM - 1;
  link := Pointer(mem);
  with link^ do
  begin
    link_index := index;
    link_size := @medium_link_sizes[index];
    inc(link_size^, mem.size);

    link_address := @medium_links[index];
    link_prev := nil;
    link_next := link_address^;
    if link_next <> nil then
      link_next.link_prev := link;
    link_address^ := link;
  end;

{$ifdef qmm_debug}
  if mem.flag > 0 then
    mcheck_medium(10, mem.owner, @medium_links);
{$endif}
end;

procedure TThreadMemory.del_link(mem: PMem; mem_size: MSIZE);
var
  link: PMemLink;
begin
{$ifopt c+}
  assert(mem.flag and FLAG_LINK = FLAG_LINK);
  if mem.flag and FLAG_LINK = FLAG_LINK then
{$endif}
  begin
    mem.flag := FLAG_BLOCK_MEDIUM;
    link := Pointer(mem);
    dec(medium_total_link_size, mem.size);
    with link^ do
    begin
      dec(link_size^, mem.size);
      if link_prev = nil then
      begin
        medium_links[link_index] := link_next;
        if link_next <> nil then
          link_next.link_prev := nil;
      end else
      begin
        link_prev.link_next := link_next;
        if link_next <> nil then
          link_next.link_prev := link_prev;
      end;
    end;
  end;
end;

function TThreadMemory.create_item_buffer(items: PMemItems): PMemItemBuffer;
const
  ITEM_COUNTs: array [0..MAX_SIZE_MINI shr BIT_STEP_MINI] of Byte = (
    //32, 32, 32, 16, 16, 8, 8, 4, 4
    60, 21, 24, 16, 14, 12, 10, 8, 8 );
var
  mem_size: MSIZE;
begin
  if items.item_size < MAX_SIZE_MINI then
    mem_size := sizeof(TMemItemBuffer) + items.item_step *
      ITEM_COUNTs[items.item_size shr BIT_STEP_MINI]
  else
    mem_size := sizeof(TMemItemBuffer) + items.item_step * 2;
  mem_size := (mem_size + MIN_MEM_SIZE - 1) and -MIN_MEM_SIZE;
  result := medium_mem_get_with_leak(mem_size);
  result.owner := items;
  result.item_count := (mem_size - sizeof(TMemItemBuffer)) div items.item_step;
  result.used_count := 0;
  result.free_index := 0;
  result.mem_block := PMem(MADDR(result) - SIZE_HEADER).owner;
  result.free_item := nil;
  result.idle_item := @result.data[0];
end;

function TThreadMemory.mem_item_get(block: PMemItemsBlock; size: MSIZE): Pointer;
var
  curr: PMem;
  items: PMemItems;
  buffer: PMemItemBuffer;
begin
  with block^ do
    items := lists[size shr bits];
  buffer := items.items_buffer;
  if (buffer = nil) or ((buffer.free_index = 0) and (buffer.used_count = buffer.item_count)) then
  begin
    with items^ do
    begin
      buffer := create_item_buffer(items);
      buffer.next := items_buffer;
      buffer.prev := nil;
      if items_buffer <> nil then
        items_buffer.prev := buffer;
      items_buffer := buffer;
      if (first_buffer = nil) and block.first_keep then
        first_buffer := buffer;
    end;
  end;

  with buffer^, items^, status do
  begin
    if (free_index > 0) then
    begin
      dec(free_index);
      curr := Pointer(free_item);
      free_item := free_item.item_next;
    end else
    begin
      curr := Pointer(idle_item);
      curr.owner := buffer.mem_block;
      curr.item_buffer := buffer;
      curr.size := item_size;
      inc(used_count);
      idle_item := Pointer(MADDR(curr) + item_step);
    end;
    curr.flag := item_flag_used;
    result := MADDR(curr) + SIZE_HEADER;
    total_alloc := total_alloc + item_size;
    small_alloc := small_alloc + item_size;
  end;
end;

procedure TThreadMemory.mem_item_free_buffer(buffer: PMemItemBuffer);
var
  items: PMemItems;
begin
  items := buffer.owner;
  if buffer.prev = nil then
  begin
    items.items_buffer := buffer.next;
    if items.items_buffer <> nil then
      buffer.owner.items_buffer.prev := nil;
  end else
  begin
    buffer.prev.next := buffer.next;
    if buffer.next <> nil then
      buffer.next.prev := buffer.prev;
  end;
  medium_mem_free_with_leak(buffer);
end;

function TThreadMemory.mem_item_free(p: PMem): Integer;
var
  item: PMemItem;
  items: PMemItems;
  buffer: PMemItemBuffer;
begin
  result := 0;
  p.flag := 0;
  buffer := p.item_buffer;
  items := buffer.owner;
  item := Pointer(p);
  with buffer^, items^ do
  begin
    item.item_next := Pointer(free_item);
    free_item := Pointer(item);
    inc(free_index);
    if (free_index = used_count) and (first_buffer <> buffer) then
    begin
      mem_item_free_buffer(buffer);
    end;
    with status do
    begin
      total_free := total_free + item_size;
      small_free := small_free + item_size;
    end;
  end;
end;

function TThreadMemory.medium_mem_get_with_leak(var size: MSIZE): Pointer;
var
  mem: PMem;
begin
  result := medium_mem_get(size);
  mem := PMem(MADDR(result) - SIZE_HEADER);
  size := mem.size;
  mem.flag := mem.flag or FLAG_REGLEAK;
end;

procedure TThreadMemory.medium_mem_free_with_leak(p: Pointer);
var
  mem: PMem;
begin
  mem := PMem(MADDR(p) - SIZE_HEADER);
  mem.flag := mem.flag and not FLAG_REGLEAK;
  medium_mem_free(mem);
end;

function TThreadMemory.medium_get_idle(var size: MSIZE): Pointer;
var
  block: PMemBlock;
  curr, next, next_next: PMem;
  link_index, link_size, limit_count, next_size: MSIZE;
label
  search_succed_, search_next_loop_;
begin
  result := nil;
  if medium_total_link_size < size then exit;

  curr := nil;
  link_index := (size shr BIT_LINK_MEDIUM);
  if link_index >= MAX_LINK_MEDIUM then
    link_index := MAX_LINK_MEDIUM - 1;

  if medium_link_sizes[link_index] < size then
    goto search_next_loop_;

  limit_count := 100;
  link_size := medium_link_sizes[link_index];
  curr := Pointer(medium_links[link_index]);
  repeat
  {$ifopt c+}
    assert(curr.flag and FLAG_LINK = FLAG_LINK);
  {$endif}
    if curr.size >= size then
    begin
      goto search_succed_;
    end;

    dec(link_size, curr.size);
    if link_size < size then
      goto search_next_loop_;
    curr := Pointer(PMemLink(curr).link_next);
    if curr = nil then
      goto search_next_loop_;
    dec(limit_count);
    if limit_count <= 0 then
      goto search_next_loop_;
  until false;

search_next_loop_:
  inc(link_index);
  while link_index <= MAX_LINK_MEDIUM - 1 do
  begin
    curr := Pointer(medium_links[link_index]);
    if curr = nil then
      inc(link_index)
    else
      goto search_succed_;
  end;
  exit;

search_succed_:
  del_link(curr, curr.size);
  block := curr.owner;
  next_size := curr.size - SIZE_HEADER - size;
  curr.flag := FLAG_BLOCK_MEDIUM or FLAG_USED;
  if next_size >= MAX_SIZE_SMALL then
  begin
    curr.size := size;
    next := Pointer(MADDR(curr) + SIZE_HEADER + size);
    next.flag := FLAG_BLOCK_MEDIUM;
    next.size := next_size;
    next.owner := block;
    next.prev := curr;
    next_next := Pointer(MADDR(next) + SIZE_HEADER + next_size);
    if MADDR(next_next) < MADDR(block.end_ptr) then
      next_next.prev := next;
    add_link(next);
  end else
    size := curr.size;
  result := MADDR(curr) + SIZE_HEADER;
end;

const
  LARGE_ALLOCATE_SIZE = SIZE_BLOCK - sizeof(TMemBlock) - SIZE_HEADER;
  MEDIUM_ALLOCATE_SIZE = LARGE_ALLOCATE_SIZE - SIZE_HEADER;

function TThreadMemory.medium_mem_get(size: MSIZE): Pointer;
var
  block: PMemBlock;
  curr, next, prev: PMem;
  next_size, prev_size: MSIZE;
label
  quit_;
begin
  result := medium_get_idle(size);
  if result <> nil then
  begin
    goto quit_;
  end;

  size := (size + MAX_SIZE_MINI - 1) and -MAX_SIZE_MINI;
  if size >= MEDIUM_ALLOCATE_SIZE then
    size := MEDIUM_ALLOCATE_SIZE;

  block := medium_block;
  if (block = nil) or (block.curr_mem = nil) then
    block := create_block(size);
{$ifdef qmm_debug}
  mcheck_medium(10, block, @medium_links);
{$endif}
  repeat
    curr := block.curr_mem;
    if curr.size >= size then
    begin
      next_size := curr.size - SIZE_HEADER - size;
      if next_size >= MAX_SIZE_SMALL then
      begin
        curr.flag := FLAG_BLOCK_MEDIUM or FLAG_USED;
        curr.size := size;
        next := Pointer(MADDR(curr) + SIZE_HEADER + size);
        next.flag := FLAG_BLOCK_MEDIUM;
        next.size := next_size;
        next.owner := block;
        next.prev := curr;
        block.curr_mem := next;
      end else
      begin
        size := curr.size;
        curr.flag := FLAG_BLOCK_MEDIUM or FLAG_USED;
        block.curr_mem := nil;
      end;
      result := MADDR(curr) + SIZE_HEADER;
      goto quit_;
    end else
    begin
      if curr.size >= MAX_SIZE_SMALL then
      begin
        add_link(curr);
      end else
      begin
        // merge curr to prev
        prev := curr.prev;
        prev_size := prev.size;
        if prev.flag and FLAG_MASK = FLAG_LINK then
        begin
          del_link(prev, prev_size);
          prev.size := prev_size + SIZE_HEADER + curr.size;
          add_link(prev);
        end else
        begin
          prev.size := prev.size + SIZE_HEADER + curr.size;
          with status do
          begin
            total_alloc := total_alloc + SIZE_HEADER + curr.size;
            medium_alloc := medium_alloc + SIZE_HEADER + curr.size;
          end;
        end;
      end;
      block.curr_mem := nil;
      block := create_block(size);
    end;
  until false;

quit_:
  with status do
  begin
    total_alloc := total_alloc + size;
    medium_alloc := medium_alloc + size;
  end;
{$ifdef qmm_debug}
  mcheck_medium(40, block, @medium_links);
{$endif}
end;

function TThreadMemory.medium_mem_realloc(curr: PMem; new_size: MSIZE): Pointer;
var
  block: PMemBlock;
  can_resize: Boolean;
  next, new_next, next_next: PMem;
  old_size, resize_size, remain_size, next_flag, calc_size: MSIZE;
begin
  result := MADDR(curr) + SIZE_HEADER;
{$ifdef qmm_debug}
  mcheck_medium(30, curr.owner, @medium_links);
{$endif}
  old_size := curr.size;
  if old_size >= new_size then
  begin
    if old_size - SIZE_HEADER - new_size < MAX_SIZE_SMALL then exit;

    result := memory_get(new_size);
    move((MADDR(curr) + SIZE_HEADER)^, result^, new_size);
    medium_mem_free(curr);
  end else
  begin
    //new_size > old_size
    can_resize := false;
    block := curr.owner;
    next := Pointer(MADDR(curr) + SIZE_HEADER + old_size);
    if MADDR(next) < MADDR(block.end_ptr) then
    begin
      next_flag := next.flag and FLAG_MASK;
      if next_flag in [FLAG_NONE, FLAG_LINK] then
      begin
        new_size := (new_size + MIN_MEM_SIZE - 1) and -MIN_MEM_SIZE;
        calc_size := old_size + SIZE_HEADER + next.size;
        can_resize := calc_size >= new_size;
        if can_resize then
        begin
          if next_flag = FLAG_NONE then
            next_next := nil
          else
          begin
            next_next := Pointer(MADDR(next) + SIZE_HEADER + next.size);
            if MADDR(next_next) >= MADDR(block.end_ptr) then
              next_next := nil;
            del_link(next, next.size);
          end;
          remain_size := calc_size - SIZE_HEADER - new_size;
          if remain_size >= MAX_SIZE_SMALL then
          begin
            curr.size := new_size;
            new_next := Pointer(MADDR(curr) + SIZE_HEADER + new_size);
            new_next.flag := FLAG_BLOCK_MEDIUM;
            new_next.size := remain_size;
            new_next.owner := block;
            new_next.prev := curr;
            if next_flag = FLAG_NONE then
              block.curr_mem := new_next
            else
            begin
              if next_next <> nil then
                next_next.prev := new_next;
              add_link(new_next);
            end;
          end else
          begin
            new_size := calc_size;
            curr.size := new_size;
            if next_flag = FLAG_NONE then
              block.curr_mem := nil
            else
            if next_next <> nil then
              next_next.prev := curr;
          end;
          resize_size := new_size - old_size;
          with status do
          begin
            total_alloc := total_alloc + resize_size;
            medium_alloc := medium_alloc + resize_size;
          end;
        {$ifdef qmm_debug}
          mcheck_medium(33, block, @medium_links);
        {$endif}
        end;
      end;
    end;

    if not can_resize then
    begin
      result := memory_get(new_size);
      move((MADDR(curr) + SIZE_HEADER)^, result^, old_size);
      medium_mem_free(curr);
    end;
  end;
end;

function TThreadMemory.medium_mem_free(curr: PMem): Integer;
var
  block: PMemBlock;
{$ifdef qmm_debug}
  is_released,
{$endif}
  is_merged: Boolean;
  prev, next, next_next: PMem;
  curr_size, free_size, next_flag: MSIZE;
begin
  result := 0;
  block := curr.owner;
{$ifdef qmm_debug}
  mcheck_medium(20, block, @medium_links);
  is_released := false;
{$endif}
  free_size := curr.size;
  curr_size := curr.size;
  is_merged := false;
  next := Pointer(MADDR(curr) + SIZE_HEADER + curr_size);
  prev := curr.prev;

  if MADDR(next) < MADDR(block.end_ptr) then
  begin
    next_flag := next.flag and FLAG_MASK;
    if next_flag in [FLAG_NONE, FLAG_LINK] then
    begin
      if next_flag = FLAG_LINK then
        del_link(next, next.size);
      next_next := Pointer(MADDR(next) + SIZE_HEADER + next.size);
      if MADDR(next_next) < MADDR(block.end_ptr) then
        next_next.prev := curr;
      curr.size := curr.size + SIZE_HEADER + next.size;
      if next_flag = FLAG_LINK then
      begin
        add_link(curr);
      end else
      begin
        if (block.curr_mem = next) or (block.curr_mem = nil) then
        begin
        {$ifopt c+}
          assert(block.curr_mem <> nil);
        {$endif}
          curr.flag := FLAG_BLOCK_MEDIUM;
          block.curr_mem := curr;
        end else
        begin
        {$ifopt c+}
          // error, never happen
          assert(next_flag = FLAG_NONE, 10);
        {$endif}
          add_link(curr);
        end;
      end;
      is_merged := true;
    end;
  end;

  if (prev <> nil) and (prev.flag and FLAG_LINK = FLAG_LINK) then
  begin
    next := Pointer(MADDR(curr) + SIZE_HEADER + curr.size);
    if MADDR(next) < MADDR(block.end_ptr) then
      next.prev := prev;
    del_link(prev, prev.size);
    prev.size := prev.size + SIZE_HEADER + curr.size;
    if curr.flag and FLAG_MASK = FLAG_LINK then
      del_link(curr, curr.size);
    if block.curr_mem = curr then
    begin
      block.curr_mem := prev;
    end else
    begin
      add_link(prev);
    end;
    is_merged := true;
  end;

  if not is_merged then
    add_link(curr)
  else
  begin
    curr := block.src_ptr;
    if (curr.size >= block.src_len) then
    begin
      if block = medium_block then
      begin
        if curr.flag and FLAG_LINK = FLAG_LINK then
          del_link(curr, curr.size);
        block.curr_mem := curr;
      end else
      begin
        release_block(block);
      {$ifdef qmm_debug}
        is_released := true;
      {$endif}
      end;
    end;
  end;
  with status do
  begin
    total_free := total_free + free_size;
    medium_free := medium_free + free_size;
  end;
{$ifdef qmm_debug}
  if not is_released then
    mcheck_medium(28, block, @medium_links);
{$endif}
end;

function TThreadMemory.large_mem_get(size: MSIZE): Pointer;
var
  curr: PMem;
begin
  size := size + SIZE_HEADER + cMinAllocSize;
  curr := virtual_alloc(size);
  size := size - SIZE_HEADER;
  curr.flag := FLAG_BLOCK_LARGE or FLAG_USED;
  curr.size := size;
  curr.owner := @owner_block;
  result := MADDR(curr) + SIZE_HEADER;

  with status do
  begin
    total_alloc := total_alloc + size;
    large_alloc := large_alloc + size;
  end;
end;

function TThreadMemory.large_mem_realloc(p: Pointer; new_size: MSIZE): Pointer;
var
  can_resize: Boolean;
  curr, next: PMem;
  resize_size: MSIZE;
begin
  curr := p;
  if curr.size >= new_size then
  begin
    result := memory_get(new_size);
    move((MADDR(p) + SIZE_HEADER)^, result^, new_size);
    large_mem_free(p);
  end else
  begin
    can_resize := false;
    next := Pointer(MADDR(curr) + SIZE_HEADER + curr.size);
    resize_size := (new_size - curr.size + cMinAllocSize - 1) and -cMinAllocSize;
    if VirtualAlloc(next, resize_size, MEM_RESERVE, PAGE_READWRITE) <> nil then
    begin
      can_resize := VirtualAlloc(next, resize_size, MEM_COMMIT, PAGE_READWRITE) <> nil;
      if can_resize then
      begin
        curr.size := curr.size + resize_size;
        with status do
        begin
          total_alloc := total_alloc + resize_size;
          large_alloc := large_alloc + resize_size;
        end;
      end;
    end;
    if not can_resize then
    begin
      result := large_mem_get(new_size);
      move((MADDR(p) + SIZE_HEADER)^, result^, curr.size);
      large_mem_free(p);
    end else
      result := MADDR(p) + SIZE_HEADER;
  end;
end;

function TThreadMemory.large_mem_free(p: Pointer): Integer;
var
  curr: PMem;
begin
  result := 0;
  curr := p;
  with status do
  begin
    total_free := total_free + curr.size;
    large_free := large_free + curr.size;
  end;
  virtual_free(curr, curr.size);
end;

procedure TThreadMemory.release_block(block: PMemBlock);
var
  mem: PMem;
  idle: PLinkData;
begin
  mem := block.src_ptr;
  if mem.size < block.src_len then exit;
  if mem.flag and FLAG_LINK = FLAG_LINK then
    del_link(mem, mem.size);
  if block.prev = nil then
  begin
    medium_block := block.next;
    if medium_block <> nil then
      medium_block.prev := nil;
  end else
  begin
    block.prev.next := block.next;
    if block.next <> nil then
      block.next.prev := block.prev;
  end;
  dec(status.block_count);
  block.used := false;
  block.next := nil;
  block.prev := nil;
  if block_buffer_count < MAX_THEAD_BLOCK then
  begin
    idle := Pointer(MADDR(block) + sizeof(TMemBlock));
    idle.data := block;
    idle.next := block_buffer;
    block_buffer := idle;
    inc(block_buffer_count);
  end else
    owner.release_block(block);
end;

function TThreadMemory.create_block(need_size: MSIZE): Pointer;
var
  mem: PMem;
  size: MSIZE;
  idle: PLinkData;
  new_block: PMemBlock;
begin
  result := nil;
  if not initialized then exit;
  size := SIZE_BLOCK;
  if block_buffer <> nil then
  begin
    idle := block_buffer;
    block_buffer := idle.next;
    new_block := idle.data;
    dec(block_buffer_count);
  end else
  begin
    new_block := owner.create_block(size, need_size);
    new_block.owner := @self;
    new_block.src_ptr := Pointer(MADDR(new_block) + sizeof(TMemBlock));
    new_block.end_ptr := Pointer(MADDR(new_block) + size);
    new_block.src_len := size - sizeof(TMemBlock) - SIZE_HEADER;
  end;
  new_block.used := true;
  if medium_block <> nil then
    medium_block.prev := new_block;
  new_block.next := medium_block;
  new_block.prev := nil;
  medium_block := new_block;
  new_block.curr_mem := new_block.src_ptr;
  mem := new_block.src_ptr;
  mem.owner := new_block;
  mem.prev := nil;
  mem.flag := FLAG_BLOCK_MEDIUM;
  mem.size := new_block.src_len;
  inc(status.block_count);
  result := new_block;
end;

function TThreadMemory.memory_get(size: MSIZE): Pointer;
begin
  if other_thread_free_lists <> nil then
    do_freemem_from_other_thread;
  size := (size + MIN_MEM_SIZE - 1) and -MIN_MEM_SIZE;
  if size < MAX_SIZE_SMALL then
  begin
    if size < MAX_SIZE_MINI then
      result := mem_item_get(mini_block, size)
    else
      result := mem_item_get(small_block, size);
  end else
  begin
    if size < LARGE_ALLOCATE_SIZE then
      result := medium_mem_get(size)
    else
      result := large_mem_get(size);
  end;
end;

function TThreadMemory.memory_realloc(p: Pointer; new_size: MSIZE): Pointer;
var
  curr: PMem;
begin
  if other_thread_free_lists <> nil then
    do_freemem_from_other_thread;

  result := p;
  curr := Pointer(MADDR(p) - SIZE_HEADER);
  if @self = curr.owner.owner then
  begin
    case curr.flag and FLAG_BLOCK_MASK of
      FLAG_BLOCK_MINI, FLAG_BLOCK_SMALL:
      begin
        result := memory_get(new_size);
        if new_size > curr.size then
          curr.item_buffer.owner.move_upsize((MADDR(curr) + SIZE_HEADER)^, result^, curr.size)
          //  move((MADDR(curr) + SIZE_HEADER)^, result^, curr.size)
        else
          move((MADDR(curr) + SIZE_HEADER)^, result^, new_size);
        mem_item_free(curr);
      end;
      FLAG_BLOCK_MEDIUM:
      begin
        result := medium_mem_realloc(curr, new_size);
      end;
      FLAG_BLOCK_LARGE:
      begin
        result := large_mem_realloc(curr, new_size);
      end;
    end;
  end else
  begin
    result := memory_get(new_size);
    if curr.size > new_size then
      move(p^, result^, new_size)
    else
      move(p^, result^, curr.size);
    PThreadMemory(curr.owner.owner).freemem_by_other_thread(p);
  end;
end;

function TThreadMemory.memory_free(p: Pointer): Integer;
var
  curr: PMem;
begin
  result := -1;
  if other_thread_free_lists <> nil then
    do_freemem_from_other_thread;

  curr := Pointer(MADDR(p) - SIZE_HEADER);
  if @self = curr.owner.owner then
  begin
    case curr.flag and FLAG_BLOCK_MASK of
      FLAG_BLOCK_MINI, FLAG_BLOCK_SMALL:
        result := mem_item_free(curr);
      FLAG_BLOCK_MEDIUM:
        result := medium_mem_free(curr);
      FLAG_BLOCK_LARGE:
        result := large_mem_free(curr);
    end;
  end else
  begin
    PThreadMemory(curr.owner.owner).freemem_by_other_thread(p);
    result := 0;
  end;
end;

{ TMemManager }

var
  mem_mgr: TMemManager;

threadvar
  local_thread_memory: PThreadMemory;

{$ifdef has_thread_exit}
var
  prev_end_thread: procedure(code: Integer);

procedure qmm_end_thread(code: Integer);
begin
  mem_mgr.release_thread_memory(GetCurrentThreadId);
  if assigned(prev_end_thread) then
    prev_end_thread(code);
end;

{$else}

var
  old_api_thread_exit: TJump;
  old_sys_thread_exit: TJump;

procedure api_thread_exit(code: Integer); stdcall;
begin
  mem_mgr.release_thread_memory(GetCurrentThreadId);
  // nothing to do
end;

procedure sys_thread_exit(code: Integer);
begin
  mem_mgr.release_thread_memory(GetCurrentThreadId);
  // nothing to do
end;

function _replace_function(src, dest: Pointer; var old_jump: TJump): Boolean;
const
  OP_JMP = $E9;
var
  jump: PJump;
  old_protect: Cardinal;
begin
  result := VirtualProtect(src, sizeof(TJump), PAGE_EXECUTE_READWRITE, old_protect);
  if not result then exit;

  jump := PJump(src);
  if jump.op_code <> OP_JMP then
  begin
    old_jump := jump^;
    jump^.op_code   := OP_JMP;
    jump^.distance := MADDR(dest) - MADDR(src) - sizeof(TJump);
    FlushInstructionCache(GetCurrentProcess, src, sizeof(TJump));
  end;
  VirtualProtect(src, sizeof(TJump), old_protect, old_protect);
end;

procedure _restore_function(func: Pointer; var old_jump: TJump);
var
  old_protect: Cardinal;
begin
  if old_jump.op_code = 0 then exit;
  if VirtualProtect(func, sizeof(TJump), PAGE_EXECUTE_READWRITE, old_protect) then
  begin
    PJump(func)^ := old_jump;
    fillchar(old_jump, sizeof(TJump), #0);
    FlushInstructionCache(GetCurrentProcess, func, SizeOf(TJump));
  end;
  VirtualProtect(func, sizeof(TJump), old_protect, old_protect);
end;
{$endif}

procedure TMemManager.initialize;
begin
  fillchar(self, sizeof(self), #0);
  initialized := true;
  spinlock_init(@lock);
  spinlock_init(@block_lock);
  spinlock_init(@leak_lock);
  spinlock_init(@items_block_lock);
{$ifndef has_thread_exit}
  _replace_function(@Windows.ExitThread, @api_thread_exit, old_api_thread_exit);
  _replace_function(@System.EndThread, @sys_thread_exit, old_sys_thread_exit);
{$else}
  prev_end_thread := SystemThreadEndProc;
  SystemThreadEndProc := qmm_end_thread;
{$endif}
  main_mgr := create_thread_memory(MainThreadID);
end;

procedure TMemManager.uninitialize;
var
  count: Integer;
  next, block: PLinkData;
  thread_memory: PThreadMemory;
begin
  if not initialized then exit;
  initialized := false;
  while mem_buffer <> nil do
  begin
    next := mem_buffer.next;
    count := align_bytes(PER_THREAD_BUFFER_COUNT * sizeof(TThreadMemory)) div sizeof(TThreadMemory);
    thread_memory := mem_buffer.data;
    while count > 0 do
    begin
      if thread_memory.initialized then
        thread_memory.uninitialize;
      inc(thread_memory);
      dec(count);
    end;
    virtual_free(mem_buffer.data);
    mem_buffer := next;
  end;

  block := used_mem_block;
  while block <> nil do
  begin
    next := block.next;
    virtual_free(block);
    block := next;
  end;

  block := block_buffer;
  while block <> nil do
  begin
    next := block.next;
    virtual_free(block);
    block := next;
  end;

  while link_buffer <> nil do
  begin
    next := link_buffer.next;
    virtual_free(link_buffer.data);
    link_buffer := next;
  end;
{$ifndef has_thread_exit}
  _restore_function(@Windows.ExitThread, old_api_thread_exit);
  _restore_function(@System.EndThread, old_sys_thread_exit);
{$else}
  SystemThreadEndProc := prev_end_thread;
{$endif}
  spinlock_free(@lock);
  spinlock_free(@block_lock);
  spinlock_free(@leak_lock);
  spinlock_free(@items_block_lock);
  fillchar(self, sizeof(self), #0);
end;

procedure TMemManager.create_link_buffer;
var
  addr: Pointer;
  link: PLinkData;
  size, count: MSIZE;
begin
  size := MEM_PAGE_SIZE;
  addr := virtual_alloc(size);
  link := addr;
  count := size div sizeof(TLinkData);
  while count > 0 do
  begin
    link.next := link_idle;
    link_idle := link;
    inc(link);
    dec(count);
  end;
  link := link_idle;
  link_idle := link.next;
  link.data := addr;
  link.next := link_buffer;
  link_buffer := link;
end;

function TMemManager.pop_link: PLinkData;
begin
  if link_idle = nil then
    create_link_buffer;
  result := link_idle;
  link_idle := result.next;
end;

procedure TMemManager.push_link(data: PLinkData);
begin
  data.next := link_idle;
  link_idle := data;
end;

procedure TMemManager.release_block(block: PMemBlock);
var
  link: PLinkData;
begin
  spinlock_lock(@block_lock);
  if block_count < MAX_MANAGER_BLOCK then
  begin
    link := Pointer(MADDR(block) + sizeof(TMemBlock));
    link.data := block;
    link.next := block_buffer;
    block_buffer := link;
    inc(block_count);
    spinlock_unlock(@block_lock);
  end else
  begin
    spinlock_unlock(@block_lock);
    virtual_free(block);
  end;
{$ifdef qmm_debug}
  mprint('release_block: tid: %d %d', [GetCurrentThreadId]);
{$endif}
end;

function TMemManager.create_block(var size: MSIZE; need_size: MSIZE): Pointer;
var
  link: PLinkData;
begin
  size := SIZE_BLOCK;
  spinlock_lock(@block_lock);
  if block_buffer <> nil then
  begin
    link := block_buffer;
    block_buffer := link.next;
    result := link.data;
    dec(block_count);
    spinlock_unlock(@block_lock);
  end else
  begin
    spinlock_unlock(@block_lock);
    result := virtual_alloc(size);
  end;
{$ifdef qmm_debug}
  mprint('create block: tid: %d', [GetCurrentThreadId]);
{$endif}
end;

procedure TMemManager.create_mem_items_block(var block: PMemItemsBlock;
  thread: PThreadMemory; block_flag: MSIZE; min, max, bits: Integer);
var
  link: PLinkData;
  items: PMemItems;
  i, size, item_count, item_step: MSIZE;
begin
  item_step := 1 shl bits;
  item_count := (max div item_step) + 1;
  size := sizeof(TMemItemsBlock) + item_count * sizeof(Pointer) +
    item_count * sizeof(TMemItems);

  if idle_items_block_size < size then
  begin
    idle_items_block_size := cMinAllocSize;
    idle_items_block_addr := virtual_alloc(idle_items_block_size);
    link := pop_link();
    link.data := idle_items_block_addr;
    link.next := used_mem_block;
    used_mem_block := link;
  end;
  block := idle_items_block_addr;
  idle_items_block_addr := MADDR(idle_items_block_addr) + size + sizeof(Pointer);
  idle_items_block_size := idle_items_block_size - size - sizeof(Pointer);

  fillchar(block^, size, #0);
  block.owner := thread;
  block.bflag := block_flag;
  block.count := item_count;
  block.min := min;
  block.max := max;
  block.bits := bits;
  block.step := item_step;
  block.first_keep := max = MAX_SIZE_MINI;
  items := Pointer(MADDR(block) + sizeof(TMemItemsBlock) +
    item_count * sizeof(Pointer));
  for i := 0 to item_count - 1 do
  begin
    items.owner := block;
    items.item_size := min + item_step * i;
    items.item_step := items.item_size + SIZE_HEADER;
    items.item_flag_used := block_flag or FLAG_USED;
    if items.item_size = 32 then
      items.move_upsize := move32
    else
    if items.item_size = 64 then
      items.move_upsize := move64
    else
      items.move_upsize := @move;
    block.lists[i] := items;
    inc(items);
  end;
end;

procedure TMemManager.create_thread_memory_buffer;
var
  addr: Pointer;
  link: PLinkData;
  size, count: MSIZE;
  thread: PThreadMemory;
begin
  size := PER_THREAD_BUFFER_COUNT * sizeof(TThreadMemory);
  addr := virtual_alloc(size);
  link := pop_link;
  link.data := addr;
  link.next := mem_buffer;
  mem_buffer := link;

  count := size div sizeof(TThreadMemory);
  thread := addr;
  while count > 0 do
  begin
    fillchar(thread^, sizeof(TThreadMemory), 0);
    thread.link_next_thread := mem_idle;
    mem_idle := thread;
    inc(thread);
    dec(count);
  end;
end;

function TMemManager.pop_thread_memory: PThreadMemory;
begin
  spinlock_lock(@lock);
  if mem_idle = nil then
    create_thread_memory_buffer;
  result := mem_idle;
  mem_idle := result.link_next_thread;
  result.link_next_thread := nil;
  spinlock_unlock(@lock);
end;

procedure TMemManager.push_thread_memory(thread_memory: PThreadMemory);
begin
  spinlock_lock(@lock);
  thread_memory.link_next_thread := mem_idle;
  mem_idle := thread_memory;
  spinlock_unlock(@lock);
end;

function TMemManager.create_thread_memory(thread_id: Cardinal): PThreadMemory;
var
  mini_block, small_block: PMemItemsBlock;
begin
  result := nil;
  if not initialized then exit;

  result := pop_thread_memory;
  if not result.initialized then
  begin
    spinlock_lock(@items_block_lock);
    create_mem_items_block(mini_block, result, FLAG_BLOCK_MINI, 0,
      MAX_SIZE_MINI, BIT_STEP_MINI);
    create_mem_items_block(small_block, result, FLAG_BLOCK_SMALL,
      MAX_SIZE_MINI, MAX_SIZE_SMALL, BIT_STEP_SMALL);
    spinlock_unlock(@items_block_lock);
    result.initialize(@self, mini_block, small_block);
  end;
  result.reactive(thread_id);
  local_thread_memory := result;

  spinlock_lock(@lock);
  result.prev_thread_memory := nil;
  result.next_thread_memory := mem_mgrs;
  if mem_mgrs <> nil then
    mem_mgrs.prev_thread_memory := result;
  mem_mgrs := result;
  inc(thread_count);
  System.IsMultiThread := thread_count > 1;
  spinlock_unlock(@lock);
end;

procedure TMemManager.release_thread_memory(thread_id: Cardinal);
var
  thread: PThreadMemory;
begin
  if not initialized or (local_thread_memory = nil) then exit;

  thread := local_thread_memory;
  local_thread_memory := nil;
  thread.deactive();

  spinlock_lock(@lock);
  if thread.prev_thread_memory = nil then
  begin
    mem_mgrs := thread.next_thread_memory;
    if mem_mgrs <> nil then
      mem_mgrs.prev_thread_memory := nil;
  end else
  begin
    thread.prev_thread_memory.next_thread_memory := thread.next_thread_memory;
    if thread.next_thread_memory <> nil then
      thread.next_thread_memory.prev_thread_memory := thread.prev_thread_memory;
  end;
  // if only main thread, then ...
  thread.prev_thread_memory := nil;
  thread.next_thread_memory := nil;
  dec(thread_count);
  System.IsMultiThread := thread_count > 1;
  spinlock_unlock(@lock);
  push_thread_memory(thread);
end;

function TMemManager.get_current_thread_memory(): PThreadMemory;
begin
  result := local_thread_memory;
  if (result = nil) then
    result := create_thread_memory(GetCurrentThreadId);
end;

function TMemManager.is_register_leak(address: Pointer): Boolean;
var
  link: PLinkData;
begin
  result := false;
  link := leak_list;
  while not result and (link <> nil) do
  begin
    if link.data = address then
    begin
      result := true;
      break;
    end;
    link := link.next;
  end;
end;

function TMemManager.register_leak(address: Pointer): Boolean;
var
  link: PLinkData;
begin
  result := true;
  spinlock_lock(@leak_lock);
  link := pop_link;
  link.data := address;
  link.next := leak_list;
  leak_list := link;
  spinlock_unlock(@leak_lock);
end;

function TMemManager.unregister_leak(address: Pointer): Boolean;
var
  link, prev: PLinkData;
begin
  result := false;
  spinlock_lock(@leak_lock);
  link := leak_list;
  prev := nil;
  while not result and (link <> nil) do
  begin
    if link.data = address then
    begin
      if prev = nil then
        leak_list := link.next
      else
        prev.next := link.next;
      push_link(link);
      result := true;
      break;
    end;
    prev := link;
    link := link.next;
  end;
  spinlock_lock(@leak_lock);
end;

function memory_get(size: MSIZE): Pointer;
begin
  result := mem_mgr.get_current_thread_memory.memory_get(size);
end;

function qmm_memory_get(size: MSIZE): Pointer;
begin
  result := memory_get(size);
end;

function memory_alloc(size: MSIZE): Pointer;
begin
  result := memory_get(size);
  if result <> nil then
    fillchar(result^, size, #0);
end;

function qmm_memory_alloc(size: MSIZE): Pointer;
begin
  result := memory_alloc(size);
end;

const
  MIN_SIZE_KEEP = MAX_SIZE_MINI shr 2;

function memory_realloc(p: Pointer; new_size: MSIZE): Pointer;
var
  curr: PMem;
  diff: MSIZE;
begin
  curr := Pointer(MADDR(p) - SIZE_HEADER);
  if curr.flag and FLAG_MASK = FLAG_USED then
  begin
    if (curr.size >= new_size) then
    begin
      diff := curr.size - new_size;
      if diff <= MIN_SIZE_KEEP then
        result := p
      else
      begin
        if (new_size >= (curr.size shr 1)) then
        begin
          result := p
        end else
        begin
          result := mem_mgr.get_current_thread_memory.memory_realloc(p, new_size);
        end;
      end;
    end else
    begin
      result := mem_mgr.get_current_thread_memory.memory_realloc(p, new_size);
    end;
  end else
  begin
  {$ifdef qmm_debug}
    mprint('realloc.invalid pointer: %.8X, flag: %.8X, size: $%.8X',
      [Integer(curr), curr.flag, curr.size]);
  {$endif}
    result := nil;
  end;
end;

function qmm_memory_realloc(p: Pointer; new_size: MSIZE): Pointer;
begin
  if p <> nil then
  begin
    if new_size > 0 then
      result := memory_realloc(p, new_size)
    else
      result := nil;
  end else
  begin
    if new_size > 0 then
      result := memory_get(new_size)
    else
      result := nil;
  end;
end;

function memory_free(p: Pointer): Integer;
begin
  if PMem(MADDR(p) - SIZE_HEADER).flag and FLAG_USED = FLAG_USED then
    result := mem_mgr.get_current_thread_memory.memory_free(p)
  else
  begin
  {$ifdef qmm_debug}
    with PMem(MADDR(p) - SIZE_HEADER)^ do
      mprint('free.invalid pointer: %.8X, flag: %.8X, size: $%.8X',
        [Integer(p) - SIZE_HEADER, flag, size]);
  {$endif}
    result := -1;
  end;
end;

function qmm_memory_free(p: Pointer): Integer;
begin
  if p <> nil then
    result := memory_free(p)
  else
    result := 0;
end;

{$ifdef debug}
type
  PDebugMem = ^TDebugMem;
  TDebugMem = record
    ori_size: MSIZE;
    first_tag: Cardinal;
    last_tag: PCardinal;
  end;

const
  TAG_FIRST = $FEEBFCDF;
  TAG_LAST =  $EBEFFEFB;

function debug_memory_get(size: MSIZE): Pointer;
var
  mem: PDebugMem;
begin
  mem := memory_get(size + sizeof(TDebugMem) + sizeof(Cardinal));
{$ifopt c+}
  assert(mem <> nil);
{$endif}
  mem.ori_size := size;
  mem.first_tag := TAG_FIRST;
  mem.last_tag := Pointer(MADDR(mem) + sizeof(TDebugMem) + size);
  mem.last_tag^ := TAG_LAST;
  result := MADDR(mem) + sizeof(TDebugMem);
  if assigned(on_notify_get_proc) then
    on_notify_get_proc(result, size);
end;

function debug_memory_alloc(size: MSIZE): Pointer;
begin
  result := debug_memory_get(size);
  if result <> nil then
    fillchar(result^, size, #0);
end;

function debug_memory_check(op: TDebugMemOP; mem: PDebugMem): Boolean;
begin
  result := (mem = nil) or ((mem.first_tag = TAG_FIRST) and
    (MADDR(mem.last_tag) = MADDR(mem) + sizeof(TDebugMem) + mem.ori_size) and
    (mem.last_tag^ = TAG_LAST));
  if not result then
  begin
    if not assigned(on_memory_error_proc) then
    begin
      assert(false);
    end else
      on_memory_error_proc(op, MADDR(mem) + sizeof(TDebugMem), mem.ori_size);
  end;
end;

function debug_memory_realloc(p: Pointer; size: MSIZE): Pointer;
var
  ori_size: MSIZE;
  ori_mem, new_mem: PDebugMem;
  last_tag: Pointer;
begin
  ori_mem := Pointer(MADDR(p) - sizeof(TDebugMem));
  ori_size := ori_mem.ori_size;
  debug_memory_check(opRealloc, ori_mem);
  last_tag := ori_mem.last_tag;
  new_mem := memory_realloc(ori_mem, size + sizeof(TDebugMem) + sizeof(Cardinal));

  assert(new_mem <> nil);
  if (new_mem <> nil) and (last_tag <> new_mem.last_tag) or (new_mem.first_tag <> TAG_FIRST) then
  begin
    assert(false);
  end;

  new_mem.ori_size := size;
  new_mem.first_tag := TAG_FIRST;
  new_mem.last_tag := Pointer(MADDR(new_mem)+ sizeof(TDebugMem) + size);
  new_mem.last_tag^ := TAG_LAST;
  result := MADDR(new_mem) + sizeof(TDebugMem);
  if assigned(on_notify_realloc_proc) then
    on_notify_realloc_proc(p, ori_size, result, size);
end;

function debug_memory_free(p: Pointer): Integer;
var
  mem: PDebugMem;
  size: MSIZE;
begin
  mem := Pointer(MADDR(p) - sizeof(TDebugMem));
  debug_memory_check(opFree, mem);
  size := mem.ori_size;
  result := memory_free(mem);
  if assigned(on_notify_free_proc) then
    on_notify_free_proc(p, size, result);
end;
{$endif}

function memory_register_leak(p: Pointer): Boolean;
begin
  result := mem_mgr.register_leak(p);
end;

function memory_unregister_leak(p: Pointer): Boolean;
begin
  result := mem_mgr.unregister_leak(p);
end;

function memory_status: TMemoryStatus;
var
  thread_memory: PThreadMemory;
begin
  fillchar(result, sizeof(result), #0);
  thread_memory := mem_mgr.mem_mgrs;
  while thread_memory <> nil do
  begin
    if thread_memory.initialized then
      with thread_memory.status do
      begin
        result.total_alloc := result.total_alloc + total_alloc;
        result.total_free := result.total_free + total_free;
        result.small_alloc := result.small_alloc + small_alloc;
        result.small_free := result.small_free + small_free;
        result.medium_alloc := result.medium_alloc + medium_alloc;
        result.medium_free := result.medium_free + medium_free;
        result.large_alloc := result.large_alloc + large_alloc;
        result.large_free := result.large_free + large_free;
        result.block_count := result.block_count + block_count;
      end;
    thread_memory := thread_memory.next_thread_memory;
  end;
  thread_memory := mem_mgr.mem_idle;
  while thread_memory <> nil do
  begin
    if not thread_memory.initialized then
      break;
    with thread_memory.status do
    begin
      result.total_alloc := result.total_alloc + total_alloc;
      result.total_free := result.total_free + total_free;
      result.small_alloc := result.small_alloc + small_alloc;
      result.small_free := result.small_free + small_free;
      result.medium_alloc := result.medium_alloc + medium_alloc;
      result.medium_free := result.medium_free + medium_free;
      result.large_alloc := result.large_alloc + large_alloc;
      result.large_free := result.large_free + large_free;
      result.block_count := result.block_count + block_count;
    end;
    thread_memory := thread_memory.link_next_thread;
  end;
end;

type
  TStringType = (stUnknow, stAnsi, stUnicode);
  PStrRec = ^StrRec;
  StrRec = packed record
  {$ifdef WIN64}
    _padding: Integer;
  {$endif}
  {$if CompilerVersion >= 20}
    code: Word;
    char_size: Word;
  {$ifend}
    ref_cnt: Integer;
    len: Integer;
  end;

// code from FastMM4.pas.DetectStringData
function detect_string_type(mem: Pointer; mem_size: Integer): TStringType;
var
  rec: PStrRec;
  char_size, str_len: Integer;
begin
  result := stUnknow;
  rec := mem;
  if (rec.ref_cnt > 255) or (rec.len <= 0) then exit;
{$if CompilerVersion >= 20}
  char_size := rec.char_size;
  if not (char_size in [1, 2]) then exit;
{$else}
  char_size := 1;
{$ifend}
  str_len := rec.len;
  if str_len > ((mem_size - sizeof(StrRec)) div char_size) then exit;
  if char_size = 1 then
  begin
    if (PAnsiChar(mem) + sizeof(StrRec) + str_len)^ = #0 then
      result := stAnsi
  end else
  begin
    if PWideChar(MADDR(mem) + sizeof(StrRec) + str_len * char_size)^ = #0 then
      result := stUnicode;
  end;
end;

// code from FastMM4.pas.DetectClassInstance
function detect_class(mem: Pointer): TClass;
const
  MEM_PAGE_PROTECTs =
    PAGE_READONLY or PAGE_READWRITE or PAGE_EXECUTE or
    PAGE_EXECUTE_READ or PAGE_EXECUTE_READWRITE or PAGE_EXECUTE_WRITECOPY;
var
  mem_info: TMemoryBasicInformation;

  function valid_VMT(address: Pointer): Boolean;
  begin
    if (MSIZE(address) > 65535) and (MSIZE(address) and 3 = 0) then
    begin
      if (MADDR(mem_info.BaseAddress) > MADDR(address))
        or ((MADDR(mem_info.BaseAddress) + mem_info.RegionSize) < (MADDR(address) + 4)) then
      begin
        mem_info.RegionSize := 0;
        VirtualQuery(address, mem_info, sizeof(mem_info));
      end;
      result := (mem_info.RegionSize >= 4)
        and (mem_info.State = MEM_COMMIT)
        and (mem_info.Protect and MEM_PAGE_PROTECTs <> 0)
        and (mem_info.Protect and PAGE_GUARD = 0);
    end else
      result := false;
  end;

  function valid_class(p: Pointer; depth: Integer): Boolean;
  var
    parent: PPointer;
  begin
    if (depth < 255) and valid_VMT(MADDR(p) + vmtSelfPtr) and
      valid_VMT(MADDR(p) + vmtParent) then
    begin
      parent := PPointer(MADDR(p) + vmtParent)^;
      result := (PPointer(MADDR(p) + vmtSelfPtr)^ = p) and
        ((parent = nil) or (valid_VMT(parent) and valid_class(parent^, depth + 1)));
    end else
      result := false;
  end;

begin
  fillchar(mem_info, sizeof(mem_info), #0);
  mem_info.RegionSize := 0;
  result := PPointer(mem)^;
  if not valid_class(result, 0) then
    result := nil;
end;

procedure to_hex(src: PByte; src_len: Integer; dest: MADDR; dest_len: Integer);
const
  TABLEs: PAnsiChar = '0123456789ABCDEF';
var
  index: Integer;
begin
  if dest_len < src_len shl 2 then
    src_len := dest_len shr 2;
  fillchar(dest^, dest_len, #0);
  index := 0;
  while src_len > 0 do
  begin
    inc(index);
    (dest + 0)^ := TABLEs[src^ shr $4];
    (dest + 1)^ := TABLEs[src^ and $f];
    if index and $f = 0 then
    begin
      (dest + 2)^ := #13;
      (dest + 3)^ := #10;
      inc(dest, 4);
    end else
    begin
     (dest + 2)^ := #32;
      inc(dest, 3);
    end;
    inc(src);
    dec(src_len);
  end;
end;

procedure get_file(path: PAnsiChar; size: Integer; filename: PAnsichar);
var
  val, flen: Integer;
begin
  fillchar(path[0], size, #0);
  val := GetModuleFileNameA(HInstance, path, size) - 4;
  while val > 0 do
  begin
    dec(val);
    if path[val] in ['\', '/'] then
      break;
  end;
  path[val + 1] := #0;
  flen := lstrlenA(filename);
  lstrcatA(path, filename);
  path[val + flen + 1] := #0;
end;

procedure report_memory_leak_to_file();
var
  log_file: THandle;
  log_val, log_len: Integer;
  log_buf: array [0..$FFFF] of AnsiChar;

  procedure report_file_open;
  var
    report_file: array [0..MAX_PATH - 1] of AnsiChar;
  begin
    if log_file = INVALID_HANDLE_VALUE then exit;
    if log_file = 0 then
    begin
      get_file(report_file, MAX_PATH, 'memory.leak.txt');
      log_file := CreateFileA(report_file, GENERIC_WRITE,
        FILE_SHARE_READ, nil, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
      if log_file = INVALID_HANDLE_VALUE then exit;
      SetFilePointer(log_file, 0, nil, FILE_END);
    end;
  end;

  procedure report_write(buf: Pointer; size: Integer);
  var
    bytes: Cardinal;
  begin
    report_file_open;
    if ((log_val + size + 2) > log_len) or (size = 0)  then
    begin
      WriteFile(log_file, log_buf[0], log_val, bytes, nil);
      log_val := 0;;
    end;
    if size > 0 then
    begin
      move(buf^, (log_buf + log_val)^, size);
      inc(log_val, size);
      if not ((log_buf + log_val - 1)^ in [#13, #10]) then
      begin
        (log_buf + log_val)^ := #13;
        (log_buf + log_val + 1)^ := #10;
        inc(log_val, 2);
      end;
    end;
  end;

  procedure report_format(format: PAnsiChar;
    const argv: array of const);
  var
    i, buf_val: Integer;
    params: array [0..31] of Cardinal;
    buffer: array [0..1023] of AnsiChar;
  begin
    if Length(argv) > 0 then
    begin
      for i := low(argv) to high(argv) do
        params[i] := argv[i].VInteger;
      buf_val := wvsprintfA(buffer, format, @params);
    end else
    begin
      fillchar(buffer, sizeof(buffer), #0);
      lstrcatA(buffer, format);
      buf_val := lstrlenA(buffer);
    end;
    report_write(@buffer, buf_val);
  end;

var
  is_log_start, is_log_threadid: Boolean;
  curr_thread_id, last_thread_id: Cardinal;
  leak_index: Integer;

  procedure report_leak(mem: Pointer; mem_size: MSIZE);
  var
    SI: TSystemTime;
    ptr: PAnsiChar;
    str_rec: PStrRec;
    instance_class: TClass;
    curr_mem: Pointer;
    buffer: array [0..1023] of AnsiChar;
  begin
    if not is_log_start then
    begin
      is_log_start := true;
      fillchar(buffer[0], 80, '=');
      buffer[80] := #0;
      report_format('%s'#13#10'This application has leaked memory(excluding expected leaks registered):',
        [Integer(@buffer[0])]);
      GetLocalTime(SI);
      report_format('log start: %.4d-%.2d-%.2d %.2d:%.2d:%.2d',
        [SI.wYear, SI.wMonth, SI.wDay, SI.wHour, SI.wMinute, SI.wSecond]);
      MessageBoxA(0, '!!The app has leaked memory, please see "memory.leak.txt"!!!', 'leaked', MB_ICONWARNING);
    end;
    if not is_log_threadid then
    begin
      if last_thread_id <> 0 then
      begin
        fillchar(buffer[0], 80, '-');
        buffer[80] := #0;
        report_format('%s', [Integer(@buffer[0])]);
      end;
      is_log_threadid := true;
      report_format('----------------main thread id: %d, current thread id: %.5d------------------',
        [MainThreadId, curr_thread_id]);
    end;

    inc(leak_index);
    report_format('leak %d:', [leak_index]);
  {$ifdef debug}
    curr_mem := MADDR(mem) + sizeof(TDebugMem);
  {$else}
    curr_mem := Pointer(MADDR(mem) + SIZE_HEADER);
  {$endif}
    instance_class := detect_class(curr_mem);
    if instance_class <> nil then
    begin
      fillchar(buffer[0], sizeof(buffer), #0);
      ptr := Pointer(PPointer(Integer(curr_mem^) + vmtClassName)^);
      move((ptr + 1)^, buffer[0], Byte(ptr^));
      report_format('Class Name: %s, instance address: $%.8X, instance size: %d, mem size: %d', [
        Integer(@buffer[0]), Integer(curr_mem),
        PInteger(Integer(curr_mem^) + vmtInstanceSize)^, mem_size]);
      to_hex(curr_mem, PInteger(Integer(curr_mem^) + vmtInstanceSize)^, buffer, sizeof(buffer));
      report_format('%s', [MSIZE(@buffer[0])]);
    end else
    begin
      case detect_string_type(curr_mem, mem_size) of
        stUnknow:
        begin
          to_hex(curr_mem, mem_size, buffer, sizeof(buffer));
          report_format('unknow data: $%.8X, size: %d, data: '#13#10'%s', [
            Integer(curr_mem), mem_size, Integer(@buffer[0])]);
        end;
        stAnsi:
        begin
          str_rec := curr_mem;
          ptr := MADDR(curr_mem) + sizeof(StrRec);
          report_format('AnsiString: $%.8X, string len: %d, string:'#13#10'%s', [
            Integer(ptr), str_rec.len, Integer(ptr)]);
        end;
        stUnicode:
        begin
          str_rec := curr_mem;
          ptr := MADDR(curr_mem) + sizeof(StrRec);
          buffer[WideCharToMultiByte(CP_ACP, 0, PWideChar(ptr),
            str_rec.len, buffer, sizeof(buffer), nil, nil)] := #0;
          report_format('UnicodeString: $%.8X, string len: %d, string:'#13#10'%s', [
            Integer(ptr), str_rec.len, Integer(@buffer)]);
        end;
      end;
    end;
  end;

  procedure report_mem_items_block(block: PMemItemsBlock);
  var
    item_buf: PMemItemBuffer;
    item: PMem;
    items: PMemItems;
  {$ifdef debug}
    debug_mem: PDebugMem;
  {$endif}
    used_flag: MSIZE;
    i, item_step, item_count: Integer;
  begin
    // used: FLAG_USED
    // waitfor free: (FLAG_USED OR FLAG_WAITFORFREE)
    used_flag := FLAG_USED;
    for i := 0 to block.count - 1 do
    begin
      items := block.lists[i];
      item_step := items.item_size + SIZE_HEADER;
      item_buf := items.items_buffer;
      while item_buf <> nil do
      begin
        if (item_buf.used_count > 0) and (item_buf.free_index <> item_buf.used_count) then
        begin
          item_count := item_buf.item_count;
          item := @item_buf.data[0];
          while item_count > 0 do
          begin
            if item.flag and FLAG_MASK = used_flag then
            begin
            {$ifdef debug}
              debug_mem := Pointer(MADDR(item) + SIZE_HEADER);
              if not mem_mgr.is_register_leak(MADDR(debug_mem) + sizeof(TDebugMem)) then
                report_leak(debug_mem, debug_mem.ori_size);
            {$else}
              if not mem_mgr.is_register_leak(MADDR(item) + SIZE_HEADER) then
                report_leak(item, item.size);
            {$endif}
            end;
            item := Pointer(MADDR(item) + item_step);
            dec(item_count);
          end;
        end;
        item_buf := item_buf.next;
      end;
    end;
  end;

  procedure report_block(block: PMemBlock);
  var
  {$ifdef debug}
    debug_mem: PDebugMem;
  {$endif}
    start, curr, next: PMem;
    used_flag, used_len, curr_size: MSIZE;
  begin
    // used: FLAG_USED
    // waitfor free: (FLAG_USED OR FLAG_WAITFORFREE)
    used_flag := FLAG_USED;
    while (block <> nil) do
    begin
      start := block.src_ptr;
      curr := start;
      if block.curr_mem = nil then
        used_len := block.src_len
      else
        used_len := MADDR(block.curr_mem) - MADDR(start);
      while ((MADDR(curr) - MADDR(start)) <= used_len) do
      begin
        curr_size := curr.size;
        next := Pointer(MADDR(curr) + SIZE_HEADER + curr_size);
        if curr.flag and FLAG_MASK = used_flag then
        begin
        {$ifdef debug}
          debug_mem := Pointer(MADDR(curr) + SIZE_HEADER);
          assert((curr.owner <> nil) and (curr.owner.owner <> nil));
          if not mem_mgr.is_register_leak(MADDR(debug_mem) + sizeof(TDebugMem)) then
            report_leak(debug_mem, debug_mem.ori_size);
        {$else}
          if not mem_mgr.is_register_leak(MADDR(curr) + SIZE_HEADER) then
            report_leak(curr, curr_size);
        {$endif}
        end;
        curr := next;
      end;
      block := block.next;
    end;
  end;

var
  SI: TSystemTime;
  thread_memory: PThreadMemory;
  buffer: array [0..MAX_PATH - 1] of AnsiChar;
begin
  log_file := 0;
  is_log_start := false;
  is_log_threadid := false;
  last_thread_id := 0;
  curr_thread_id := 0;
  try
    log_val := 0;
    log_len := sizeof(log_buf);

    thread_memory := mem_mgr.mem_mgrs;
    while thread_memory <> nil do
    begin
      if thread_memory.initialized then
      begin
        if last_thread_id <> thread_memory.thread_id then
        begin
          leak_index := 0;
          if is_log_threadid and (curr_thread_id <> 0) then
          begin
            report_format('-------------------------------------------------------------------------------', []);
          end;
          is_log_threadid := false;
          last_thread_id := curr_thread_id;
          curr_thread_id := thread_memory.thread_id;
        end;
        report_mem_items_block(thread_memory.mini_block);
        report_mem_items_block(thread_memory.small_block);
        report_block(thread_memory.medium_block);
        if is_log_threadid and (curr_thread_id <> 0) then
        begin
          report_format('--------------------------------------------------------------------------------', []);
        end;
      end;
      thread_memory := thread_memory.next_thread_memory;
    end;


    if is_log_start then
    begin
      GetLocalTime(SI);
      report_format('log end: %.4d-%.2d-%.2d %.2d:%.2d:%.2d',
        [SI.wYear, SI.wMonth, SI.wDay, SI.wHour, SI.wMinute, SI.wSecond]);
      fillchar(buffer[0], 77, '=');
      buffer[77] := #0;
      report_format('%sEND', [Integer(@buffer[0])]);
    end;
    if log_val > 0 then
      report_write(nil, 0);
  finally
    if (log_file <> 0) and (log_file <> INVALID_HANDLE_VALUE) then
      CloseHandle(log_file);
  end;
end;

{ init/uninit }

type
  PMM = ^TMM;
  TMM = System.{$ifdef has_mm_ex} TMemoryManagerEx {$else} TMemoryManager {$endif};

var
  old_mm, new_mm: TMM;

  is_qmm_set: Boolean = false;
  share_map_handle: THandle = 0;

//
//code from FastMM4
//
type
  PShareMessage = ^TShareMessage;
  TShareMessage = packed record
    mm_size: Cardinal;
    mm: Pointer;
  end;

procedure do_share_memmgr(var mm: TMM);
var
  pid: Cardinal;
  share: PShareMessage;
{$ifdef debug}
  out_string,
{$endif}
  share_name: array [0..63] of AnsiChar;
begin
  pid := GetCurrentProcessId;
  fillchar(share_name, sizeof(share_name), #0);
  wvsprintfA(share_name, 'share_qiu_mm_pid_%.8x', @pid);
  share_map_handle := OpenFileMappingA(FILE_MAP_READ, false, share_name);
  if share_map_handle = 0 then
  begin
    if not system.IsLibrary then
    begin
      share_map_handle := CreateFileMappingA(INVALID_HANDLE_VALUE, nil,
        PAGE_READWRITE, 0, sizeof(TShareMessage), share_name);
      share := MapViewOfFile(share_map_handle, FILE_MAP_WRITE, 0, 0, 0);
      share.mm_size := sizeof(TMM);
      share.mm := @mm;
      UnmapViewOfFile(share);
    {$ifdef debug}
      OutputDebugStringA('create share memory manager succed');
    {$endif}
    end else
    begin
    {$ifdef debug}
      OutputDebugStringA('DLL: cann''t open share map');
    {$endif}
    end;
  end else
  begin
    share := MapViewOfFile(share_map_handle, FILE_MAP_READ, 0, 0, 0);
    if share.mm_size = sizeof(TMM) then
    begin
      mm := PMM(share.mm)^;
    {$ifdef debug}
      OutputDebugStringA('read share memory manager succed');
    {$endif}
    end else
    begin
    {$ifdef debug}
      wvsprintfA(out_string, 'share mm fail: mm_size: %d <> sizeof(TMM)', @share.mm_size);
      OutputDebugStringA(out_string);
    {$endif}
    end;
    UnmapViewOfFile(share);
    CloseHandle(share_map_handle);
    share_map_handle := 0;
  end;
end;

procedure initialize_memory_manager;

  function get_allocated_size(): Int64;
{$ifdef has_mm_ex}
  var
    i: Integer;
    state: TMemoryManagerState;
  begin
    GetMemoryManagerState(state);
    result := state.TotalAllocatedMediumBlockSize + state.TotalAllocatedLargeBlockSize;
    for i := 0 to NumSmallBlockTypes - 1 do
      with state.SmallBlockTypeStates[i] do
        result := result + UseableBlockSize * AllocatedBlockCount;
  end;
{$else}
  begin
  {$warn symbol_platform off}
  {$warn symbol_deprecated off}
    result := GetHeapStatus.TotalAllocated;
  {$warn symbol_platform on}
  {$warn symbol_deprecated on}
  end;
{$endif}

var
  SI: TSystemInfo;
begin
  if is_qmm_set then exit;
  GetSystemInfo(SI);
  cMinAllocSize := SI.dwAllocationGranularity;

  mem_mgr.initialize;
  new_mm.GetMem := @{$ifndef debug}memory_get{$else}debug_memory_get{$endif};
  new_mm.FreeMem := @{$ifndef debug}memory_free{$else}debug_memory_free{$endif};
  new_mm.ReallocMem := @{$ifndef debug}memory_realloc{$else}debug_memory_realloc{$endif};
{$ifdef has_mm_ex}
  new_mm.AllocMem := @{$ifndef debug}memory_alloc{$else}debug_memory_alloc{$endif};
  new_mm.RegisterExpectedMemoryLeak := @memory_register_leak;
  new_mm.UnRegisterExpectedMemoryLeak := @memory_unregister_leak;
{$endif}

  do_share_memmgr(new_mm);

  if (is_qmm_set) or (System.IsMemoryManagerSet) or
    (get_allocated_size() > 0) then
    exit;

  GetMemoryManager(old_mm);
  SetMemoryManager(new_mm);
  is_qmm_set := true;
end;

procedure finalize_memory_manager;
begin
  if ReportMemoryLeaksOnShutdown then
    report_memory_leak_to_file();

  if is_qmm_set then
  begin
    SetMemoryManager(old_mm);
    is_qmm_set := false;
  end;

  if share_map_handle <> 0 then
  begin
    CloseHandle(share_map_handle);
    share_map_handle := 0;
  end;
  mem_mgr.uninitialize;
end;

initialization
  initialize_memory_manager;
finalization
  finalize_memory_manager;

end.
