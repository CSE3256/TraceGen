#include <fstream>
#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <cstring>
#include <set>
#include <stdlib.h>
#include <stdint.h>
#include <sstream>

#include <zlib.h>

#include "pin.H"

using namespace std;

#define INS_GRP_SIZE 1024
#define SIZE 32768

/* ===================================================================== */
/* Command-line options */
/* ===================================================================== */
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE,    "pintool",
			    "o", "/home/jishen/experiments/tracegen.out",
			    "specify pinatrace file name");

/*KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE,    "pintool",
			    "o", "/gpfs/home/juz138/scratch/tracegen.out",
			    "specify pinatrace file name");*/

uint64_t num_instrs;
ofstream curr_file;
ostringstream instrs;

/** Compress a STL string using zlib with given compression level and return
  * the binary data. */
string compress_string(const string& str, int compressionlevel = Z_BEST_COMPRESSION)
{
  z_stream zs; // z_stream is zlib's control structure
  memset(&zs, 0, sizeof(zs));
  
  if (deflateInit(&zs, compressionlevel) != Z_OK) {
    cout << "deflateInit failed while compressing." << endl;
    exit(1);
  }
  
  zs.next_in = (Bytef*)str.data();
  zs.avail_in = str.size();           // set the z_stream's input
  
  int ret;
  char outbuffer[SIZE];
  string outstring;
  
  // retrieve the compressed bytes blockwise
  do {
    zs.next_out = reinterpret_cast<Bytef*>(outbuffer);
    zs.avail_out = sizeof(outbuffer);
    
    ret = deflate(&zs, Z_FINISH);
    
    if (outstring.size() < zs.total_out) {
      // append the block to the output string
      outstring.append(outbuffer, zs.total_out - outstring.size());
    }
  } while (ret == Z_OK);
  
  deflateEnd(&zs);
  
  if (ret != Z_STREAM_END) {          // an error occurred that was not EOF
    ostringstream oss;
    oss << "Exception during zlib compression: (" << ret << ") " << zs.msg;
    cout << oss.str() << endl;
    exit(1);
  }
  
  return outstring;
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
  //ostringstream instrs;

  instrs <<  waddr << " " << wlen << " " << raddr << " " << raddr2 << " " 
	    << rlen << " " << ip << " " << category << " " 
	    << isbranch << " " << isbranchtaken << " " 
	    << rr0 << " " << rr1 << " " << rr2 << " " << rr3 << " " 
	    << rw0 << " " << rw1 << " " << rw2 << " " << rw3 << " "
	    << threadid << "\n ";  

  ++num_instrs;

  if (num_instrs >= INS_GRP_SIZE) {
    if (curr_file.good()) {
      string instr_str = instrs.str();
      string compressed = compress_string(instr_str);
    
      curr_file << compressed;
      instrs.str("");
      instrs.clear();
      num_instrs = 0;
    }
    else {
      cout << "trace file is not correctly opened" << endl;
      exit(1);
    } 
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


VOID Fini(int code, VOID * v)
{
  curr_file << "#eof" << endl;
  curr_file.close();
}

//GLOBALFUN 
int main(int argc, char *argv[])
{  

  if (PIN_Init(argc, argv)) return Usage();
  
  num_instrs = 0;
  
  PIN_InitSymbols(); 
  
  curr_file.open(KnobOutputFile.Value().c_str()); //, ios::binary);

  INS_AddInstrumentFunction(Instruction, 0);

  PIN_AddFiniFunction(Fini, 0);

  // Never returns
  PIN_StartProgram();

  //curr_file.close();
  return 0; // make compiler happy
}

