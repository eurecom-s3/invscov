#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/DepthFirstIterator.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/ADT/Triple.h"
#include "llvm/ADT/Twine.h"
#include "llvm/Analysis/MemoryBuiltins.h"
#include "llvm/Analysis/TargetLibraryInfo.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/BinaryFormat/MachO.h"
#include "llvm/IR/Argument.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CallSite.h"
#include "llvm/IR/Comdat.h"
#include "llvm/IR/Constant.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DIBuilder.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/DebugLoc.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalAlias.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/InstVisitor.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/MDBuilder.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/Use.h"
#include "llvm/IR/Value.h"
#include "llvm/IR/Verifier.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/MC/MCSectionMachO.h"
#include "llvm/Pass.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/MathExtras.h"
#include "llvm/Support/ScopedPrinter.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Instrumentation.h"
#include "llvm/Transforms/Utils/ASanStackFrameLayout.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/Local.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include "llvm/Transforms/Utils/PromoteMemToReg.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <climits>
#include <iomanip>
#include <limits>
#include <memory>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <tuple>
#include <fstream>

#include "RangeAnalysis.h"

#define MAX_DEPTH 3

using namespace llvm;
using namespace RangeAnalysis;

static size_t TypeSizeToSizeIndex(uint32_t TypeSize) {
  if (TypeSize == 1) TypeSize = 8;
  size_t Res = countTrailingZeros(TypeSize / 8);
  return Res;
}

static void ReplaceAll(std::string& S, std::string P, std::string R) {
  size_t pos = S.find(P);
  while(pos != std::string::npos) {
    S.replace(pos, P.size(), R);
    pos = S.find(P, pos + R.size());
  }
}

static std::string GetVarName(Value* V) {

  std::string name;
  if (V->hasName())
    return "_" + V->getName().str();
  return "";

}

static Instruction *IRBSplitBlockAndInsertIfThen(IRBuilder<>& IRB, Value *Cond,
                                          Instruction *SplitBefore,
                                          BasicBlock *ThenTarget = nullptr,
                                          bool Unreachable = false) {
   BasicBlock *Head = SplitBefore->getParent();
   BasicBlock *Tail = Head->splitBasicBlock(SplitBefore->getIterator());
   Instruction *HeadOldTerm = Head->getTerminator();
   LLVMContext &C = Head->getContext();
   Instruction *CheckTerm;
   BasicBlock *ThenBlock = BasicBlock::Create(C, "", Head->getParent(), Tail);
   if (Unreachable)
     CheckTerm = new UnreachableInst(C, ThenBlock);
   else if (ThenTarget)
     CheckTerm = BranchInst::Create(ThenTarget, ThenBlock);
   else
     CheckTerm = BranchInst::Create(Tail, ThenBlock);
   CheckTerm->setDebugLoc(SplitBefore->getDebugLoc());
   BranchInst *HeadNewTerm =
     BranchInst::Create(/*ifTrue*/ThenBlock, /*ifFalse*/Tail, Cond);
   ReplaceInstWithInst(HeadOldTerm, HeadNewTerm);
   IRB.SetInsertPoint(&*Tail->getFirstInsertionPt());
   return CheckTerm;
}

static void IRBSplitBlockAndInsertIfThenElse(IRBuilder<>& IRB, Value *Cond,
                                      Instruction *SplitBefore,
                                      Instruction **ThenTerm,
                                      Instruction **ElseTerm) {
  BasicBlock *Head = SplitBefore->getParent();
  BasicBlock *Tail = Head->splitBasicBlock(SplitBefore->getIterator());
  Instruction *HeadOldTerm = Head->getTerminator();
  LLVMContext &C = Head->getContext();
  BasicBlock *ThenBlock = BasicBlock::Create(C, "", Head->getParent(), Tail);
  BasicBlock *ElseBlock = BasicBlock::Create(C, "", Head->getParent(), Tail);
  *ThenTerm = BranchInst::Create(Tail, ThenBlock);
  (*ThenTerm)->setDebugLoc(SplitBefore->getDebugLoc());
  *ElseTerm = BranchInst::Create(Tail, ElseBlock);
  (*ElseTerm)->setDebugLoc(SplitBefore->getDebugLoc());
  BranchInst *HeadNewTerm =
   BranchInst::Create(/*ifTrue*/ThenBlock, /*ifFalse*/ElseBlock, Cond);
  ReplaceInstWithInst(HeadOldTerm, HeadNewTerm);
  IRB.SetInsertPoint(&*Tail->getFirstInsertionPt());
}

struct BBInfo {

  std::string Name;

  std::vector< Value* > Locals;
  std::vector< std::vector<Value*> > GEPs;
  std::vector< std::vector<Value*> > LDs;
  std::vector< std::vector<Value*> > STs;

};

struct InvsCovDump {

  InvsCovDump(Module& _M, Function &_F, LoopInfo &_LI, IntraProceduralRA<Cousot> &_RA) : M(_M), F(_F), LI(_LI), RA(_RA) {
    initialize();
  }
  
  static bool isBlacklisted(const Function *F) {

    static const char *Blacklist[] = {

        "asan.", "llvm.", "sancov.", "__ubsan_handle_", "ign.", "__afl_",
        "_fini", "__libc_csu", "__asan",  "__msan", "msan."

    };

    for (auto const &BlacklistFunc : Blacklist) {

      if (F->getName().startswith(BlacklistFunc)) return true;

    }
    
    //if (F->getName() == "main") return true;
    if (F->getName() == "_start") return true;

    return false;

  }
  
  void initialize();
  bool instrumentFunction();
  
  bool dumpVariable(IRBuilder<>& IRB, std::map<Value*, int>& Comp, std::string prefix_name, Value* V);

  Type *VoidTy, *Int8Ty, *Int16Ty, *Int32Ty, *Int64Ty, *FloatTy, *DoubleTy,
       *StructTy, *Int8PTy, *Int16PTy, *Int32PTy, *Int64PTy, *FloatPTy,
       *DoublePTy, *StructPTy, *FuncTy;
  Type *IntTypeSized[4];

  Function* dbgDeclareFn;

  FunctionCallee invscovDumpSignedIntFns[4];
  FunctionCallee invscovDumpUnsignedIntFns[4];
  FunctionCallee invscovDumpFloatFn, invscovDumpDoubleFn;
  FunctionCallee invscovDumpNosenseFn;
  
  FunctionCallee invscovDumpLockFn, invscovDumpUnlockFn;
  FunctionCallee invscovDumpEnterPrologueFn, invscovDumpExitPrologueFn,
                 invscovDumpEpilogueFn, invscovDumpLoopPrologueFn;
  
  FunctionCallee invscovAreaIsMappedFn, invscovAreaIsValidFn;
  
  FunctionCallee randFn;
  
  LLVMContext *C;
  Module& M;
  Function &F;
  LoopInfo &LI;
  IntraProceduralRA<Cousot> &RA;
  int LongSize;
  
  bool hasCalls;
  std::map< Type*, std::set<unsigned> > usedFields;
  std::map< Type*, MDNode* > structMDs;
  std::map< Type*, bool > usedForCalls;
  
  std::vector<DILocalVariable*> DbgVars;
  
  std::string funcname;
  std::ofstream decls;
  std::string invscov_output_path;

};

void InvsCovDump::initialize() {

  if (getenv("INVSCOV_OUTPUT_PATH"))
    invscov_output_path = getenv("INVSCOV_OUTPUT_PATH");
  else
    invscov_output_path = "invscov_output";
  
  funcname = M.getModuleIdentifier() + ":" + F.getName().str();
  if (funcname.size() >= 2 && funcname[0] == '.' && funcname[1] == '/')
    funcname.erase(0, 2);
  ReplaceAll(funcname, "\\", "\\\\"); // invscov naming convention
  ReplaceAll(funcname, " ", "\\_");
  ReplaceAll(funcname, "/", "_");

  C = &(M.getContext());
  
  LongSize = M.getDataLayout().getPointerSizeInBits();

  VoidTy = Type::getVoidTy(*C);

  Int8Ty = IntegerType::get(*C, 8);
  Int16Ty = IntegerType::get(*C, 16);
  Int32Ty = IntegerType::get(*C, 32);
  Int64Ty = IntegerType::get(*C, 64);

  FloatTy = Type::getFloatTy(*C);
  DoubleTy = Type::getDoubleTy(*C);

  StructTy = StructType::create(*C);
  
  Int8PTy  = PointerType::get(Int8Ty, 0);
  Int16PTy = PointerType::get(Int16Ty, 0);
  Int32PTy = PointerType::get(Int32Ty, 0);
  Int64PTy = PointerType::get(Int64Ty, 0);

  FloatPTy = PointerType::get(FloatTy, 0);
  DoublePTy = PointerType::get(DoubleTy, 0);

  StructPTy = PointerType::get(StructTy, 0);

  FuncTy = FunctionType::get(VoidTy, true);

  dbgDeclareFn = M.getFunction("llvm.dbg.declare");
  
  IntTypeSized[0] = Int8Ty;
  IntTypeSized[1] = Int16Ty;
  IntTypeSized[2] = Int32Ty;
  IntTypeSized[3] = Int64Ty;
  
  invscovDumpSignedIntFns[0] = M.getOrInsertFunction("__invscov_dump_i8", VoidTy, Int8PTy, Int8Ty);
  invscovDumpSignedIntFns[1] = M.getOrInsertFunction("__invscov_dump_i16", VoidTy, Int8PTy, Int16Ty);
  invscovDumpSignedIntFns[2] = M.getOrInsertFunction("__invscov_dump_i32", VoidTy, Int8PTy, Int32Ty);
  invscovDumpSignedIntFns[3] = M.getOrInsertFunction("__invscov_dump_i64", VoidTy, Int8PTy, Int64Ty);
  
  invscovDumpUnsignedIntFns[0] = M.getOrInsertFunction("__invscov_dump_u8", VoidTy, Int8PTy, Int8Ty);
  invscovDumpUnsignedIntFns[1] = M.getOrInsertFunction("__invscov_dump_u16", VoidTy, Int8PTy, Int16Ty);
  invscovDumpUnsignedIntFns[2] = M.getOrInsertFunction("__invscov_dump_u32", VoidTy, Int8PTy, Int32Ty);
  invscovDumpUnsignedIntFns[3] = M.getOrInsertFunction("__invscov_dump_u64", VoidTy, Int8PTy, Int64Ty);
  
  invscovDumpFloatFn = M.getOrInsertFunction("__invscov_dump_f", VoidTy, Int8PTy, FloatTy);
  invscovDumpDoubleFn = M.getOrInsertFunction("__invscov_dump_d", VoidTy, Int8PTy, DoublePTy);
  
  invscovDumpNosenseFn = M.getOrInsertFunction("__invscov_dump_nosense", VoidTy, Int8PTy);
  
  invscovDumpLockFn = M.getOrInsertFunction("__invscov_dump_lock", VoidTy);
  invscovDumpUnlockFn = M.getOrInsertFunction("__invscov_dump_unlock", VoidTy);
  
  Type* SizeTTy = IntTypeSized[TypeSizeToSizeIndex(LongSize)];
  invscovDumpEnterPrologueFn = M.getOrInsertFunction("__invscov_dump_enter_prologue", SizeTTy, Int8PTy);
  invscovDumpExitPrologueFn = M.getOrInsertFunction("__invscov_dump_exit_prologue", VoidTy, Int8PTy, Int32Ty, SizeTTy);
  invscovDumpEpilogueFn = M.getOrInsertFunction("__invscov_dump_epilogue", VoidTy);
  invscovDumpLoopPrologueFn = M.getOrInsertFunction("__invscov_dump_loop_prologue", SizeTTy, Int8PTy, Int32Ty);
  
  invscovAreaIsMappedFn = M.getOrInsertFunction("__invscov_area_is_mapped", Int8Ty, Int8PTy, SizeTTy);
  invscovAreaIsValidFn = M.getOrInsertFunction("__invscov_area_is_valid", Int8Ty, Int8PTy, SizeTTy);
  
  randFn = M.getOrInsertFunction("rand", Int32Ty);

}

bool InvsCovDump::dumpVariable(IRBuilder<>& IRB, std::map<Value*, int>& Comp, std::string prefix_name, Value* V) {

  bool FunctionModified = false;
  Type *T = V->getType();
  
  std::string name = prefix_name + GetVarName(V);
  int CompID = -1;
  if (Comp.find(V) != Comp.end())
    CompID = Comp[V];
  
  Range Rng = RA.getRange(V);
  
   switch (T->getTypeID()) {
    case Type::IntegerTyID: {
      TypeSize BitsNum = T->getPrimitiveSizeInBits();
      if (BitsNum > 64) break;
      
      if (BitsNum == 1)
        V = IRB.CreateIntCast(V, Int8Ty, true);
      
      size_t SizeIndex = TypeSizeToSizeIndex(BitsNum);
      
      decls << "      {\"name\": \"" << name << "\", \"kind\": "
            << "\"var\", \"comp\": " << CompID << ", \"addr\": " << V;

      bool Signed = true; // min >= 0 false
      if (BitsNum > 1 && !Rng.isUnknown() && !Rng.isEmpty()) {
        bool HasMin = !Rng.getLower().eq(RA.getMin()) && Rng.getLower().getActiveBits() <= 64;
        bool HasMax = !Rng.getUpper().eq(RA.getMax()) && Rng.getUpper().getActiveBits() <= 64;
        if (HasMin && HasMax) {
          switch(SizeIndex) {
            case 0: {
              int8_t A = (int8_t)Rng.getLower().getSExtValue();
              int8_t B = (int8_t)Rng.getUpper().getSExtValue();
              if (B < A) {
                uint8_t UA = (uint8_t)Rng.getLower().getZExtValue();
                uint8_t UB = (uint8_t)Rng.getUpper().getZExtValue();
                if (B >= A) {
                  decls << ", \"min\": " << (unsigned)UA;
                  if (UB < UCHAR_MAX) decls << ", \"max\": " << (unsigned)UB;
                  Signed = false;
                }
              } else {
                if (A >= 0) Signed = false;
                if (A > SCHAR_MIN) decls << ", \"min\": " << (int)A;
                if (B < SCHAR_MAX) decls << ", \"max\": " << (int)B;
              }
              break;
            }
            case 1: {
              int16_t A = (int16_t)Rng.getLower().getSExtValue();
              int16_t B = (int16_t)Rng.getUpper().getSExtValue();
              if (B < A) {
                uint16_t UA = (uint16_t)Rng.getLower().getZExtValue();
                uint16_t UB = (uint16_t)Rng.getUpper().getZExtValue();
                if (B >= A) {
                  decls << ", \"min\": " << UA;
                  if (UB < USHRT_MAX) decls << ", \"max\": " << UB;
                  Signed = false;
                }
              } else {
                if (A >= 0) Signed = false;
                if (A > SHRT_MIN) decls << ", \"min\": " << A;
                if (B < SHRT_MAX) decls << ", \"max\": " << B;
              }
              break;
            }
            case 2: {
              int32_t A = (int32_t)Rng.getLower().getSExtValue();
              int32_t B = (int32_t)Rng.getUpper().getSExtValue();
              if (B < A) {
                uint32_t UA = (uint32_t)Rng.getLower().getZExtValue();
                uint32_t UB = (uint32_t)Rng.getUpper().getZExtValue();
                if (B >= A) {
                  decls << ", \"min\": " << UA;
                  if (UB < UINT_MAX) decls << ", \"max\": " << UB;
                  Signed = false;
                }
              } else {
                if (A >= 0) Signed = false;
                if (A > INT_MIN) decls << ", \"min\": " << A;
                if (B < INT_MAX) decls << ", \"max\": " << B;
              }
              break;
            }
            case 3: {
              int64_t A = (int64_t)Rng.getLower().getSExtValue();
              int64_t B = (int64_t)Rng.getUpper().getSExtValue();
              if (B < A) {
                uint64_t UA = (uint64_t)Rng.getLower().getZExtValue();
                uint64_t UB = (uint64_t)Rng.getUpper().getZExtValue();
                if (B >= A) {
                  decls << ", \"min\": " << UA;
                  if (UB < UINT_MAX) decls << ", \"max\": " << UB;
                  Signed = false;
                }
              } else {
                if (A >= 0) Signed = false;
                if (A > INT_MIN) decls << ", \"min\": " << A;
                if (B < INT_MAX) decls << ", \"max\": " << B;
              }
              break;
            }
          }
        } else if (HasMin) {
          int64_t A = (int64_t)Rng.getLower().getSExtValue();
          if (A >= 0) Signed = false;
          switch(SizeIndex) {
            case 0:
            decls << ", \"min\": " << (int)(int8_t)Rng.getLower().getSExtValue();
            break;
            case 1:
            decls << ", \"max\": " << (int16_t)Rng.getLower().getSExtValue();
            break;
            case 2:
            decls << ", \"max\": " << (int32_t)Rng.getLower().getSExtValue();
            break;
            case 3:
            decls << ", \"max\": " << (int64_t)Rng.getLower().getSExtValue();
            break;
          }
        } else if (HasMax) {
          switch(SizeIndex) {
            case 0:
            decls << ", \"max\": " << (int)(int8_t)Rng.getUpper().getSExtValue();
            break;
            case 1:
            decls << ", \"max\": " << (int16_t)Rng.getUpper().getSExtValue();
            break;
            case 2:
            decls << ", \"max\": " << (int32_t)Rng.getUpper().getSExtValue();
            break;
            case 3:
            decls << ", \"max\": " << (int64_t)Rng.getUpper().getSExtValue();
            break;
          }
        }
      }
      decls << ", \"signed\": " << Signed <<  ", \"type\": \""
            << (Signed ? "i" : "u") << BitsNum << "\"},\n";
      
      Value *N = IRB.CreateGlobalStringPtr(name);
      Value *I = IRB.CreateBitCast(V, IntTypeSized[SizeIndex]);
      CallInst* CI;
      if (Signed)
        CI = IRB.CreateCall(invscovDumpSignedIntFns[SizeIndex], ArrayRef<Value*>{N, I});
      else
        CI = IRB.CreateCall(invscovDumpUnsignedIntFns[SizeIndex], ArrayRef<Value*>{N, I});
      CI->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(*C, None));
      
      FunctionModified = true;
      break;
    }
    case Type::FloatTyID: {

      decls << "      {\"name\": \"" << name << "\", \"type\": \"" << "float"
            << "\", \"kind\": " << "\"var\", \"comp\": " << CompID
            << ", \"addr\": " << V << "},\n";
    
      Value *N = IRB.CreateGlobalStringPtr(name);
      Value *I = IRB.CreateBitCast(V, FloatTy);
      CallInst* CI = IRB.CreateCall(invscovDumpFloatFn, ArrayRef<Value*>{N, I});
      CI->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(*C, None));
      
      FunctionModified = true;
      break;
    }
    case Type::DoubleTyID: {

      decls << "      {\"name\": \"" << name << "\", \"type\": \"" << "double"
            << "\", \"kind\": " << "\"var\", \"comp\": " << CompID
            << ", \"addr\": " << V << "},\n";

      Value *N = IRB.CreateGlobalStringPtr(name);
      Value *I = IRB.CreateBitCast(V, DoubleTy);
      CallInst* CI = IRB.CreateCall(invscovDumpDoubleFn, ArrayRef<Value*>{N, I});
      CI->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(*C, None));

      FunctionModified = true;
      break;
    }
    case Type::PointerTyID: {

      // TODO evaluate the impact of this removal

      /*decls << "      {\"name\": \"" << name << "\", \"type\": \"" << (LongSize == 64 ? "u64" : "u32")
            << "\", \"kind\": " << "\"var\", \"comp\": " << CompID
            << ", \"addr\": " << V << "},\n";

      size_t SizeIndex = TypeSizeToSizeIndex(LongSize);
      
      Value *N = IRB.CreateGlobalStringPtr(name);
      Value *I = IRB.CreatePtrToInt(V, IntTypeSized[SizeIndex]);
      CallInst* CI = IRB.CreateCall(invscovDumpSignedIntFns[SizeIndex], ArrayRef<Value*>{N, I});
      CI->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(*C, None));

      FunctionModified = true;*/
      break;
    }
    // case Type::ArrayTyID:
    // case Type::VectorTyID:
    // break;

    default:
      break;
  }

  return FunctionModified;

}

static void AddComp(std::map<Value*, int>& Comp, int& CompID, Value* A) {

  bool hasA = Comp.find(A) != Comp.end();

  if (!hasA) {
    Comp[A] = CompID;
    ++CompID;
  }

}

static void MergeComp(std::map<Value*, int>& Comp, int& CompID, Value* A, Value* B) {

  bool hasA = Comp.find(A) != Comp.end();
  bool hasB = Comp.find(B) != Comp.end();

  if (hasA && !hasB)
    Comp[B] = Comp[A];
  else if(!hasA && hasB)
    Comp[A] = Comp[B];
  else if (!hasA && !hasB) {
    Comp[A] = CompID;
    Comp[B] = CompID;
    ++CompID;
  } else {
    int AID = Comp[A];
    int BID = Comp[B];
    for (auto& K : Comp) {
      if (K.second == BID)
        K.second = AID;
    }
  }

}

bool InvsCovDump::instrumentFunction() {

  bool FunctionModified = false;

  if (isBlacklisted(&F)) return FunctionModified; // not supported

  std::string decls_name = funcname;
  if (decls_name.size() > 200) {
    decls_name = decls_name.substr(0, 200) + "<" + std::to_string((uintptr_t)&F) + ">";
  }

  decls.open(invscov_output_path + "/" + decls_name + "_decls.literal.part");
  if (!decls.good()) {
    errs() << "FATAL: Failed to open (w) the file '" << invscov_output_path + "/" + decls_name + "_decls.literal.part" << "'\n";
    abort();
  }
  
  std::vector<BasicBlock*> BBs;
  std::set<Value*> DbgVals;

  std::map<Value*, int> Comp;
  int CompID = 0;
  
  for(Function::arg_iterator it = F.arg_begin(); it != F.arg_end(); ++it) {
    Argument *A = &*it;
    Value *V = static_cast<Value*>(A);
    
    if (DbgVals.find(V) == DbgVals.end())
      DbgVals.insert(V);
    
  }

  for (auto &BB : F) {
    BBs.push_back(&BB);
    for (auto &Inst : BB) {
    
      if (UnaryOperator* O = dyn_cast<UnaryOperator>(&Inst)) {
        MergeComp(Comp, CompID, O, O->getOperand(0));
      } else if (BinaryOperator* O = dyn_cast<BinaryOperator>(&Inst)) {
        MergeComp(Comp, CompID, O->getOperand(0), O->getOperand(1));
        MergeComp(Comp, CompID, O, O->getOperand(1));
      } else if (CastInst* C = dyn_cast<CastInst>(&Inst)) {
        MergeComp(Comp, CompID, C, C->getOperand(0));
      } else if (GetElementPtrInst* G = dyn_cast<GetElementPtrInst>(&Inst)) {
        MergeComp(Comp, CompID, G, G->getPointerOperand());
        Value* First = nullptr;
        for (auto Idx = G->idx_begin(); Idx != G->idx_end(); ++Idx) {
          if (Idx->get() && !isa<ConstantInt>(Idx->get())) {
            if (First) MergeComp(Comp, CompID, First, Idx->get());
            else First = Idx->get();
          }
        }
      } else if (LoadInst* L = dyn_cast<LoadInst>(&Inst)) {
        AddComp(Comp, CompID, L);
      }
    
      if (DbgValueInst* DbgValue = dyn_cast<DbgValueInst>(&Inst)) {

        if (DbgValue->getValue()&& !isa<Constant>(DbgValue->getValue()) && 
            DbgVals.find(DbgValue->getValue()) == DbgVals.end())
          DbgVals.insert(DbgValue->getValue());

      } else if(ReturnInst* RI = dyn_cast<ReturnInst>(&Inst)) {
      
        Value* RV = RI->getReturnValue();
        if (RV && DbgVals.find(RV) == DbgVals.end())
          DbgVals.insert(RV);
      
      }

    }
  }
  
  std::map<BasicBlock*, BBInfo> Infos;
  
  for (auto BB : BBs) {
  
    std::string BBp;
    raw_string_ostream OS(BBp);
    BB->printAsOperand(OS, false);
    auto BBname = funcname + "#" + OS.str();
  
    Infos[BB].Name = BBname;
    
    for (auto &Inst : *BB) {
    
      if (Inst.getMetadata(M.getMDKindID("nosanitize")))
        continue;
      
      if (isa<PHINode>(&Inst)) continue;
      
      for (auto op = Inst.op_begin(); op != Inst.op_end(); ++op) {
        Value* V = op->get();
        if (DbgVals.find(V) != DbgVals.end()) {
          if (std::find(Infos[BB].Locals.begin(), Infos[BB].Locals.end(), V) == Infos[BB].Locals.end())
            Infos[BB].Locals.push_back(V);
        }
      }
    
      if(auto GEP = dyn_cast<GetElementPtrInst>(&Inst)) {

        if(!isa<PointerType>(GEP->getSourceElementType()))
          continue;
        if (!GEP->hasIndices())
          continue;

        std::vector<Value*> OP;
        OP.push_back(GEP->getPointerOperand());
        for (auto Idx = GEP->idx_begin(); Idx != GEP->idx_end(); ++Idx) {
          if (Idx->get() && !isa<ConstantInt>(Idx->get()))
            OP.push_back(Idx->get());
        }
        
        if (OP.size() > 1)
          Infos[BB].GEPs.push_back(OP);

      } else if (auto LD = dyn_cast<LoadInst>(&Inst)) {
        
        std::vector<Value*> OP;
        OP.push_back(LD->getPointerOperand());
        OP.push_back(LD);
        
        Infos[BB].LDs.push_back(OP);
        
      } else if (auto ST = dyn_cast<StoreInst>(&Inst)) {
        
        std::vector<Value*> OP;
        OP.push_back(ST->getPointerOperand());
        OP.push_back(ST->getValueOperand());
        
        Infos[BB].STs.push_back(OP);
        
      }
    }
  
  }
  
  for (auto BB : BBs) {
  
    std::string BBname = Infos[BB].Name;
    
    M.getOrInsertGlobal(BBname + "__cnt", Int64Ty);
    GlobalVariable* CntGbl = M.getNamedGlobal(BBname + "__cnt");
    CntGbl->setLinkage(GlobalValue::CommonLinkage);
    CntGbl->setInitializer(ConstantInt::get(Int64Ty, 0, true));
    
    IRBuilder<> CntIRB(BB->getTerminator());
    LoadInst* CntL = CntIRB.CreateLoad(CntGbl);
    CntL->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(*C, None));
    StoreInst* CntS = CntIRB.CreateStore(CntIRB.CreateAdd(CntL, ConstantInt::get(Int64Ty, 1, true)), CntGbl);
    CntS->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(*C, None));
    
    Instruction* Cmp = CntIRB.Insert(new ICmpInst(ICmpInst::ICMP_ULT, CntL, ConstantInt::get(Int64Ty, 128, true)));
    Instruction* ThenBlock, *ElseBlock;
    IRBSplitBlockAndInsertIfThenElse(CntIRB, Cmp, Cmp->getNextNode(), &ThenBlock, &ElseBlock);
    
    IRBuilder<> RndIRB(ElseBlock);
    CallInst* Rnd = RndIRB.CreateCall(randFn);
    Rnd->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(*C, None));
    
    // rnd & 31
    Value* Guard = RndIRB.CreateAnd(Rnd, ConstantInt::get(Int32Ty, 31, true));
    Instruction* Cmp1 = RndIRB.Insert(new ICmpInst(ICmpInst::ICMP_EQ, Guard, ConstantInt::get(Int32Ty, 0, true)));
    IRBSplitBlockAndInsertIfThen(CntIRB, Cmp1, Cmp1->getNextNode(), ThenBlock->getParent());
    
    IRBuilder<> IRB(ThenBlock);
    
    CallInst* CI = IRB.CreateCall(invscovDumpLockFn);
    CI->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(*C, None));
    
    std::set<Value*> Dumpeds;
    
    std::string BBname1 = BBname;
    ReplaceAll(BBname1, "\"", "\\\"");
    decls << "{\n  \"name\": \"" << BBname1 << "\",\n";
    decls << "  \"ppts\": {\n    \"ENTER\": [\n";

    Value *N = IRB.CreateGlobalStringPtr(BBname);
    CallInst *InvNonce = IRB.CreateCall(invscovDumpEnterPrologueFn, ArrayRef<Value*>{N});
    InvNonce->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(*C, None));
    
    for (size_t i = 0; i < Infos[BB].Locals.size(); ++i) {
    
      if (Dumpeds.find(Infos[BB].Locals[i]) == Dumpeds.end()) {
        dumpVariable(IRB, Comp, "LOC_" + std::to_string(i), Infos[BB].Locals[i]);
        Dumpeds.insert(Infos[BB].Locals[i]);
      }
    
    }
    
    for (size_t i = 0; i < Infos[BB].GEPs.size(); ++i) {
    
      if (!isa<Constant>(Infos[BB].GEPs[i][0]) &&
          Dumpeds.find(Infos[BB].GEPs[i][0]) == Dumpeds.end()) {
        dumpVariable(IRB, Comp, "GEPPtr_" + std::to_string(i), Infos[BB].GEPs[i][0]);
        Dumpeds.insert(Infos[BB].GEPs[i][0]);
      }

      for (size_t j = 1; j < Infos[BB].GEPs[i].size(); ++j) {
        if (Dumpeds.find(Infos[BB].GEPs[i][j]) == Dumpeds.end()) {
          dumpVariable(IRB, Comp, "GEPIdx_" + std::to_string(i) + "_" + std::to_string(j), Infos[BB].GEPs[i][j]);
          Dumpeds.insert(Infos[BB].GEPs[i][j]);
        }
      }

    }
    
    for (size_t i = 0; i < Infos[BB].LDs.size(); ++i) {
    
      if (!isa<Constant>(Infos[BB].LDs[i][0]) &&
          Dumpeds.find(Infos[BB].LDs[i][0]) == Dumpeds.end()) {
        dumpVariable(IRB, Comp, "LDPtr_" + std::to_string(i), Infos[BB].LDs[i][0]);
        Dumpeds.insert(Infos[BB].LDs[i][0]);
      }
      if (!isa<Constant>(Infos[BB].LDs[i][1]) &&
          Dumpeds.find(Infos[BB].LDs[i][1]) == Dumpeds.end()) {
        dumpVariable(IRB, Comp, "LDVal_" + std::to_string(i), Infos[BB].LDs[i][1]);
        Dumpeds.insert(Infos[BB].LDs[i][1]);
      }

    }
    
    for (size_t i = 0; i < Infos[BB].STs.size(); ++i) {
    
      if (!isa<Constant>(Infos[BB].STs[i][0]) &&
          Dumpeds.find(Infos[BB].STs[i][0]) == Dumpeds.end()) {
        dumpVariable(IRB, Comp, "STPtr_" + std::to_string(i), Infos[BB].STs[i][0]);
        Dumpeds.insert(Infos[BB].STs[i][0]);
      }
      if (!isa<Constant>(Infos[BB].STs[i][1]) &&
          Dumpeds.find(Infos[BB].STs[i][1]) == Dumpeds.end()) {
        dumpVariable(IRB, Comp, "STVal_" + std::to_string(i), Infos[BB].STs[i][1]);
        Dumpeds.insert(Infos[BB].STs[i][1]);
      }

    }
    
    decls << "    ],\n";

    CI = IRB.CreateCall(invscovDumpEpilogueFn);
    CI->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(*C, None));
    
    decls << "    \"EXIT0" << "\": [\n";
    
    Value *I = ConstantInt::get(Int32Ty, 0, true);
    CI = IRB.CreateCall(invscovDumpExitPrologueFn, ArrayRef<Value*>{N, I, InvNonce});
    CI->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(*C, None));
    
    Dumpeds.clear();
     for (size_t i = 0; i < Infos[BB].Locals.size(); ++i) {
    
      if (Dumpeds.find(Infos[BB].Locals[i]) == Dumpeds.end()) {
        dumpVariable(IRB, Comp, "LOC_" + std::to_string(i), Infos[BB].Locals[i]);
        Dumpeds.insert(Infos[BB].Locals[i]);
      }
    
    }
    
    for (size_t i = 0; i < Infos[BB].GEPs.size(); ++i) {
    
      if (!isa<Constant>(Infos[BB].GEPs[i][0]) &&
          Dumpeds.find(Infos[BB].GEPs[i][0]) == Dumpeds.end()) {
        dumpVariable(IRB, Comp, "GEPPtr_" + std::to_string(i), Infos[BB].GEPs[i][0]);
        Dumpeds.insert(Infos[BB].GEPs[i][0]);
      }

      for (size_t j = 1; j < Infos[BB].GEPs[i].size(); ++j) {
        if (Dumpeds.find(Infos[BB].GEPs[i][j]) == Dumpeds.end()) {
          dumpVariable(IRB, Comp, "GEPIdx_" + std::to_string(i) + "_" + std::to_string(j), Infos[BB].GEPs[i][j]);
          Dumpeds.insert(Infos[BB].GEPs[i][j]);
        }
      }

    }
    
    for (size_t i = 0; i < Infos[BB].LDs.size(); ++i) {
    
      if (!isa<Constant>(Infos[BB].LDs[i][0]) &&
          Dumpeds.find(Infos[BB].LDs[i][0]) == Dumpeds.end()) {
        dumpVariable(IRB, Comp, "LDPtr_" + std::to_string(i), Infos[BB].LDs[i][0]);
        Dumpeds.insert(Infos[BB].LDs[i][0]);
      }
      if (!isa<Constant>(Infos[BB].LDs[i][1]) &&
          Dumpeds.find(Infos[BB].LDs[i][1]) == Dumpeds.end()) {
        dumpVariable(IRB, Comp, "LDVal_" + std::to_string(i), Infos[BB].LDs[i][1]);
        Dumpeds.insert(Infos[BB].LDs[i][1]);
      }

    }
    
    for (size_t i = 0; i < Infos[BB].STs.size(); ++i) {
    
      if (!isa<Constant>(Infos[BB].STs[i][0]) &&
          Dumpeds.find(Infos[BB].STs[i][0]) == Dumpeds.end()) {
        dumpVariable(IRB, Comp, "STPtr_" + std::to_string(i), Infos[BB].STs[i][0]);
        Dumpeds.insert(Infos[BB].STs[i][0]);
      }
      if (!isa<Constant>(Infos[BB].STs[i][1]) &&
          Dumpeds.find(Infos[BB].STs[i][1]) == Dumpeds.end()) {
        dumpVariable(IRB, Comp, "STVal_" + std::to_string(i), Infos[BB].STs[i][1]);
        Dumpeds.insert(Infos[BB].STs[i][1]);
      }

    }
    
    decls << "    ]";
    decls << "\n  }\n},\n";
    
    CI = IRB.CreateCall(invscovDumpEpilogueFn);
    CI->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(*C, None));
    
    CI = IRB.CreateCall(invscovDumpUnlockFn);
    CI->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(*C, None));

  }

  decls.close();
  
  return FunctionModified;
  
}

class InvsCovDumpFunctionPass : public FunctionPass {
public:
  static char ID;

  explicit InvsCovDumpFunctionPass() : FunctionPass(ID) {}

  void getAnalysisUsage(AnalysisUsage &AU) const override {
    AU.setPreservesCFG();
    AU.addRequired<LoopInfoWrapperPass>();
    AU.addRequired<IntraProceduralRA<Cousot>>();
  }

  StringRef getPassName() const override {
    return "InvsCovDumpPass";
  }

  bool runOnFunction(Function &F) override {
    Module &M = *F.getParent();
    LoopInfo &LI = getAnalysis<LoopInfoWrapperPass>().getLoopInfo();
    IntraProceduralRA<Cousot> &RA = getAnalysis<IntraProceduralRA<Cousot>>();
    InvsCovDump DI(M, F, LI, RA);
    bool r = DI.instrumentFunction();
    verifyFunction(F);
    return r;
  }
};


char InvsCovDumpFunctionPass::ID = 0;

static void registerInvsCovPass(const PassManagerBuilder &,
                               legacy::PassManagerBase &PM) {

  PM.add(new InvsCovDumpFunctionPass());

}

static RegisterStandardPasses RegisterInvsCovPass(
    PassManagerBuilder::EP_OptimizerLast, registerInvsCovPass);

static RegisterStandardPasses RegisterInvsCovPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerInvsCovPass);

static RegisterPass<InvsCovDumpFunctionPass>
    X("invscov-dump", "InvsCovDumpPass",
      false,
      false
    );


