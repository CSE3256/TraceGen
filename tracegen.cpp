#include <fstream>
#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <set>
#include <stdlib.h>
#include <stdint.h>
//#include <snappy.h>
#include <sstream>

#include "pin.H"

using namespace std;

/* ===================================================================== */
/* Command-line options */
/* ===================================================================== */
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE,    "pintool",
			    "o", "~/experiments/tracegen.out",
			    "specify pinatrace file name");

 /*KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE,    "pintool",
			    "o", "/gpfs/home/juz138/scratch/tracegen.out",
			    "specify pinatrace file name");*/

//uint64_t num_instrs;

ofstream curr_file;

//const uint32_t instr_group_size = 100000;
 
VOID Fini(int code, VOID * v)
{
  curr_file << "#eof" << endl;
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
  if (curr_file.good()) {    
    curr_file <<  waddr << " " << wlen << " " << raddr << " " << raddr2 << " " 
	      << rlen << " " << ip << " " << category << " " 
	      << isbranch << " " << isbranchtaken << " " 
	      << rr0 << " " << rr1 << " " << rr2 << " " << rr3 << " " 
	      << rw0 << " " << rw1 << " " << rw2 << " " << rw3 << " "
	      << threadid << endl;
  }
  else {
    cout << "trace file is not correctly opened" << endl;
    exit(1);
  }  
}

VOID Instruction(INS ins, VOID *v)
{
  bool is_mem_wr   = INS_IsMemoryWrite(ins);
  bool is_mem_rd   = INS_IsMemoryRead(ins);
  bool has_mem_rd2 = INS_HasMemoryRead2(ins);

  if (is_mem_wr && is_mem_rd && has_mem_rd2) 
  {
    INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)ProcessMemIns,
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
    INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)ProcessMemIns,
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
    INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)ProcessMemIns,
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
    INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)ProcessMemIns,
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
    INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)ProcessMemIns,
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
    INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)ProcessMemIns,
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

INT32 Usage()
{
  cerr << "This Pintool prints a trace for McSim.\n"<< endl;  
  exit(1);
}


//GLOBALFUN 
int main(int argc, char *argv[])
{  

  if (PIN_Init(argc, argv)) return Usage();
  PIN_InitSymbols();    
  
  curr_file.open(KnobOutputFile.Value().c_str(), ios::binary);

  INS_AddInstrumentFunction(Instruction, 0);

  PIN_AddFiniFunction(Fini, 0);

  // Never returns
  PIN_StartProgram();

  curr_file.close();
  return 0; // make compiler happy
}

