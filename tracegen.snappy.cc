
#include <fstream>
#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <set>
#include <stdlib.h>
#include <stdint.h>
#include <snappy.h>

#include "pin.H"

using namespace std;

uint64_t num_instrs;
ofstream curr_file;
//bool     tracing;

const uint32_t instr_group_size = 100000;

/* ===================================================================== */
/* Command-line options */
/* ===================================================================== */
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE,    "pintool",
                            "o", "/home/jishen/experiments/tracegen.snappy",
                            "specify pinatrace file name");

/*KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE,    "pintool",                       
  "o", "/gpfs/home/juz138/scratch/tracegen.out",              
  "specify pinatrace file name");*/


// TODO: define PTSInstrTrace somewhere else!
// Currently, it is also defined in PTS.h, which is bad!
struct PTSInstrTrace
{
  uint64_t waddr;
  uint32_t wlen;
  uint64_t raddr;
  uint64_t raddr2;
  uint32_t rlen;
  uint64_t ip;
  uint32_t category;
  bool     isbranch;
  bool     isbranchtaken;
  uint32_t rr0;
  uint32_t rr1;
  uint32_t rr2;
  uint32_t rr3;
  uint32_t rw0;
  uint32_t rw1;
  uint32_t rw2;
  uint32_t rw3;
  uint32_t threadid;
};

PTSInstrTrace instrs[instr_group_size];
const size_t maxCompressedLength = snappy::MaxCompressedLength(sizeof(PTSInstrTrace)*instr_group_size);  
char * compressed;
size_t * compressed_length;


VOID Init(uint32_t argc, char ** argv)
{
  //tracing    = false;
  num_instrs = 0;
  
  compressed = new char[maxCompressedLength];
  compressed_length = new size_t;    
}


LOCALFUN VOID Fini(int code, VOID * v)
{
  curr_file.close();
}

VOID ProcessMemIns(ADDRINT ip,
		   ADDRINT raddr, ADDRINT raddr2, UINT32 rlen,
		   ADDRINT waddr, UINT32  wlen,
		   BOOL    isbranch,
		   BOOL    isbranchtaken,
		   UINT32  category,
		   UINT32  rr0,
		   UINT32  rr1,
		   UINT32  rr2,
		   UINT32  rr3,
		   UINT32  rw0,
		   UINT32  rw1,
		   UINT32  rw2,
		   UINT32  rw3,
		   THREADID threadid)
{  
  bool tracing = true;
  
  if (tracing) {
    PTSInstrTrace & curr_instr = instrs[num_instrs%instr_group_size];
    curr_instr.waddr = waddr;
    curr_instr.wlen  = wlen;
    curr_instr.raddr = raddr;
    curr_instr.raddr2 = raddr2;
    curr_instr.rlen  = rlen;
    curr_instr.ip    = ip;
    curr_instr.category = category;
    curr_instr.isbranch = isbranch;
    curr_instr.isbranchtaken = isbranchtaken;
    curr_instr.rr0 = rr0;
    curr_instr.rr1 = rr1;
    curr_instr.rr2 = rr2;
    curr_instr.rr3 = rr3;
    curr_instr.rw0 = rw0;
    curr_instr.rw1 = rw1;
    curr_instr.rw2 = rw2;
    curr_instr.rw3 = rw3;
    curr_instr.threadid = threadid;
    
    num_instrs++;
    if ((num_instrs % instr_group_size) == 0) {
      curr_file.open(KnobOutputFile.Value().c_str(), ios::binary|ios::app);
      if (!curr_file.good()) {
	cout << "failed to open tracegen.snappy"  << endl;
	exit(1);
      }
      
      snappy::RawCompress((char *)instrs, sizeof(PTSInstrTrace)*instr_group_size, compressed, compressed_length);
      curr_file.write((char *)compressed_length, sizeof(size_t));
      curr_file.write(compressed, *compressed_length);
    }
        
    curr_file.close();
    
  }
  else {
    num_instrs++;
  }
}


LOCALFUN VOID Instruction(INS ins, VOID *v)
{
  bool is_mem_wr   = INS_IsMemoryWrite(ins);
  bool is_mem_rd   = INS_IsMemoryRead(ins);
  bool has_mem_rd2 = INS_HasMemoryRead2(ins);

  if (is_mem_wr && is_mem_rd && has_mem_rd2) 
  {
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)ProcessMemIns,
        IARG_INST_PTR,
        IARG_MEMORYREAD_EA,
        IARG_MEMORYREAD2_EA,
        IARG_MEMORYREAD_SIZE,
        IARG_MEMORYWRITE_EA,
        IARG_MEMORYWRITE_SIZE,
        IARG_BOOL, INS_IsBranchOrCall(ins),
        IARG_BRANCH_TAKEN,
        IARG_UINT32,  INS_Category(ins),
        IARG_UINT32, INS_RegR(ins, 0),
        IARG_UINT32, INS_RegR(ins, 1),
        IARG_UINT32, INS_RegR(ins, 2),
        IARG_UINT32, INS_RegR(ins, 3),
        IARG_UINT32, INS_RegW(ins, 0),
        IARG_UINT32, INS_RegW(ins, 1),
        IARG_UINT32, INS_RegW(ins, 2),
        IARG_UINT32, INS_RegW(ins, 3),
		   IARG_THREAD_ID,
        IARG_END);
  }
  else if (is_mem_wr && is_mem_rd && !has_mem_rd2) 
  {
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)ProcessMemIns,
        IARG_INST_PTR,
        IARG_MEMORYREAD_EA,
        IARG_ADDRINT, (ADDRINT)0,
        IARG_MEMORYREAD_SIZE,
        IARG_MEMORYWRITE_EA,
        IARG_MEMORYWRITE_SIZE,
        IARG_BOOL, INS_IsBranchOrCall(ins),
        IARG_BRANCH_TAKEN,
        IARG_UINT32,  INS_Category(ins),
        IARG_UINT32, INS_RegR(ins, 0),
        IARG_UINT32, INS_RegR(ins, 1),
        IARG_UINT32, INS_RegR(ins, 2),
        IARG_UINT32, INS_RegR(ins, 3),
        IARG_UINT32, INS_RegW(ins, 0),
        IARG_UINT32, INS_RegW(ins, 1),
        IARG_UINT32, INS_RegW(ins, 2),
        IARG_UINT32, INS_RegW(ins, 3),
		   IARG_THREAD_ID,
        IARG_END);
  }
  else if (is_mem_wr && !is_mem_rd) 
  {
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)ProcessMemIns,
        IARG_INST_PTR,
        IARG_ADDRINT, (ADDRINT)0,
        IARG_ADDRINT, (ADDRINT)0,
        IARG_UINT32, 0,
        IARG_MEMORYWRITE_EA,
        IARG_MEMORYWRITE_SIZE,
        IARG_BOOL, INS_IsBranchOrCall(ins),
        IARG_BRANCH_TAKEN,
        IARG_UINT32, INS_Category(ins),
        IARG_UINT32, INS_RegR(ins, 0),
        IARG_UINT32, INS_RegR(ins, 1),
        IARG_UINT32, INS_RegR(ins, 2),
        IARG_UINT32, INS_RegR(ins, 3),
        IARG_UINT32, INS_RegW(ins, 0),
        IARG_UINT32, INS_RegW(ins, 1),
        IARG_UINT32, INS_RegW(ins, 2),
        IARG_UINT32, INS_RegW(ins, 3),
		   IARG_THREAD_ID,
        IARG_END);
  }
  else if (!is_mem_wr && is_mem_rd && has_mem_rd2)
  {
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)ProcessMemIns,
        IARG_INST_PTR,
        IARG_MEMORYREAD_EA,
        IARG_MEMORYREAD2_EA,
        IARG_MEMORYREAD_SIZE,
        IARG_ADDRINT, (ADDRINT)0,
        IARG_UINT32, 0,
        IARG_BOOL, INS_IsBranchOrCall(ins),
        IARG_BRANCH_TAKEN,
        IARG_UINT32, INS_Category(ins),
        IARG_UINT32, INS_RegR(ins, 0),
        IARG_UINT32, INS_RegR(ins, 1),
        IARG_UINT32, INS_RegR(ins, 2),
        IARG_UINT32, INS_RegR(ins, 3),
        IARG_UINT32, INS_RegW(ins, 0),
        IARG_UINT32, INS_RegW(ins, 1),
        IARG_UINT32, INS_RegW(ins, 2),
        IARG_UINT32, INS_RegW(ins, 3),
		   IARG_THREAD_ID,
        IARG_END);
  }
  else if (!is_mem_wr && is_mem_rd && !has_mem_rd2) 
  {
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)ProcessMemIns,
        IARG_INST_PTR,
        IARG_MEMORYREAD_EA,
        IARG_ADDRINT, (ADDRINT)0,
        IARG_MEMORYREAD_SIZE,
        IARG_ADDRINT, (ADDRINT)0,
        IARG_UINT32, 0,
        IARG_BOOL, INS_IsBranchOrCall(ins),
        IARG_BRANCH_TAKEN,
        IARG_UINT32, INS_Category(ins),
        IARG_UINT32, INS_RegR(ins, 0),
        IARG_UINT32, INS_RegR(ins, 1),
        IARG_UINT32, INS_RegR(ins, 2),
        IARG_UINT32, INS_RegR(ins, 3),
        IARG_UINT32, INS_RegW(ins, 0),
        IARG_UINT32, INS_RegW(ins, 1),
        IARG_UINT32, INS_RegW(ins, 2),
        IARG_UINT32, INS_RegW(ins, 3),
		   IARG_THREAD_ID,
        IARG_END);
  }
  else
  {
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)ProcessMemIns,
        IARG_INST_PTR,
        IARG_ADDRINT, (ADDRINT)0,
        IARG_ADDRINT, (ADDRINT)0,
        IARG_UINT32,  0,
        IARG_ADDRINT, (ADDRINT)0,
        IARG_UINT32,  0,
        IARG_BOOL, INS_IsBranchOrCall(ins),
        IARG_BRANCH_TAKEN,
        IARG_UINT32, INS_Category(ins),
        IARG_UINT32, INS_RegR(ins, 0),
        IARG_UINT32, INS_RegR(ins, 1),
        IARG_UINT32, INS_RegR(ins, 2),
        IARG_UINT32, INS_RegR(ins, 3),
        IARG_UINT32, INS_RegW(ins, 0),
        IARG_UINT32, INS_RegW(ins, 1),
        IARG_UINT32, INS_RegW(ins, 2),
        IARG_UINT32, INS_RegW(ins, 3),
		   IARG_THREAD_ID,
        IARG_END);
  }
}


GLOBALFUN int main(int argc, char *argv[])
{    
  Init(argc, argv);
  PIN_InitSymbols();
  PIN_Init(argc, argv);


  INS_AddInstrumentFunction(Instruction, 0);
  PIN_AddFiniFunction(Fini, 0);

  // Never returns
  PIN_StartProgram();

  return 0; // make compiler happy
}

