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
#include <iomanip>
#include <limits>
#include <memory>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <tuple>
#include <fstream>

#include "json.hpp"

using namespace llvm;
using json = nlohmann::json;

static json* Constrs = nullptr;

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

static std::string GenLoadRepr(Value* V) {

  if (LoadInst* LD = dyn_cast<LoadInst>(V)) {
    return "LD(" + GenLoadRepr(LD->getPointerOperand()) + ")";
  }
  
  if (GetElementPtrInst* GEP = dyn_cast<GetElementPtrInst>(V)) {
    bool cnst = true;
    std::string OP = "GEP";
    for (auto Idx = GEP->idx_begin(); Idx != GEP->idx_end(); ++Idx) {
      if (!isa<ConstantInt>(Idx->get()))
        cnst = false;
      else
        OP += "_" + std::to_string(static_cast<ConstantInt*>(Idx->get())->getZExtValue());
    }
    if (cnst)
      return OP + "(" + GenLoadRepr(GEP->getPointerOperand()) + ")";
  }
  
  std::ostringstream oss;
  oss << (void*)V;
  return oss.str();

}

struct BBInfo {

  std::string Name;
  bool HasConstrs;
  std::map<std::string, Value*> Variables;
  std::map<std::string, std::string> LoadReprs;

  std::map<std::string, Value*> Hashes;

  std::vector<BasicBlock*> Dominators;
  std::vector<BasicBlock*> Dominateds;

};

struct InvsCovInstrument {

  InvsCovInstrument(Module& _M, Function &_F, LoopInfo &_LI, DominatorTree &_DT)
                    : M(_M), F(_F), LI(_LI), DT(_DT) {
    initialize();
  }
  
  static bool isBlacklisted(const Function *F) {

    static const char *Blacklist[] = {

        "asan.", "llvm.", "sancov.", "__ubsan_handle_", "ign.", "__afl_",
        "_fini", "__libc_csu", "__asan",  "__msan", "msan.",

    };

    for (auto const &BlacklistFunc : Blacklist) {

      if (F->getName().startswith(BlacklistFunc)) { return true; }

    }
    
    if (F->getName() == "main") return true;
    if (F->getName() == "LLVMFuzzerTestOneInput") return true;
    if (F->getName() == "_start") return true;

    return false;

  }
  
  void initialize();
  bool instrumentFunction();
  
  Type *VoidTy, *Int8Ty, *Int16Ty, *Int32Ty, *Int64Ty, *FloatTy, *DoubleTy,
       *StructTy, *Int8PTy, *Int16PTy, *Int32PTy, *Int64PTy, *FloatPTy,
       *DoublePTy, *StructPTy, *FuncTy;
  Type *IntTypeSized[4];

  Function* dbgDeclareFn;

  GlobalVariable* AFLState, *AFLPrevLoc;

  LLVMContext *C;
  Module& M;
  Function &F;
  LoopInfo &LI;
  DominatorTree &DT;
  int LongSize;
  
  std::string funcname;
  
  std::vector<DILocalVariable*> DbgVars;
  std::map<BasicBlock*, BBInfo*> Infos;

};

void InvsCovInstrument::initialize() {

  if (Constrs == nullptr) {
    std::string invscov_constrs_path = "invscov_output/constrs.json";
    if (getenv("INVSCOV_OUTPUT_PATH"))
      invscov_constrs_path = getenv("INVSCOV_OUTPUT_PATH") + std::string("/constrs.json");
    
    Constrs = new json();
    
    errs() << invscov_constrs_path << "\n";
    std::ifstream f(invscov_constrs_path);
    if (!f.good()) {
      errs() << "FATAL: Failed to open (r) the file '" << invscov_constrs_path << "'\n";
      abort();
    }
    f >> *Constrs;
    f.close();
  }
  
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
  
  //AFLState = M.getGlobalVariable("__afl_state");
  //assert (AFLState != nullptr);
  
  AFLPrevLoc = M.getGlobalVariable("__afl_prev_loc");
  if (AFLPrevLoc == nullptr)
    AFLPrevLoc = new GlobalVariable(
      M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_prev_loc", 0,
      GlobalVariable::GeneralDynamicTLSModel, 0, false);

}

bool InvsCovInstrument::instrumentFunction() {

  bool FunctionModified = false;

  if (isBlacklisted(&F)) return FunctionModified; // not supported
  
  std::vector<BasicBlock*> BBs;
  std::set<Value*> DbgVals;
  
  for(Function::arg_iterator it = F.arg_begin(); it != F.arg_end(); ++it) {
    Argument *A = &*it;
    Value *V = static_cast<Value*>(A);
    
    if (DbgVals.find(V) == DbgVals.end())
      DbgVals.insert(V);
    
  }

  for (auto &BB : F) {
    BBs.push_back(&BB);
    for (auto &Inst : BB) {
      if (DbgValueInst* DbgValue = dyn_cast<DbgValueInst>(&Inst)) {

        if (!isa<Constant>(DbgValue->getValue()) && 
            DbgVals.find(DbgValue->getValue()) == DbgVals.end())
          DbgVals.insert(DbgValue->getValue());

      } else if(ReturnInst* RI = dyn_cast<ReturnInst>(&Inst)) {
      
        Value* RV = RI->getReturnValue();
        if (RV && DbgVals.find(RV) == DbgVals.end())
          DbgVals.insert(RV);
      
      }
    }
  }
  
  for (auto BB : BBs) {
  
    std::string BBp;
    raw_string_ostream OS(BBp);
    BB->printAsOperand(OS, false);
    auto BBname = funcname + "#" + OS.str();
    
    std::vector< Value* > Locals;
    std::vector< std::vector<Value*> > GEPs;
    std::vector< std::vector<Value*> > LDs;
    std::vector< std::vector<Value*> > STs;
    
    if (Constrs->find(BBname) != Constrs->end()) {

      for (auto &Inst : *BB) {
      
        if (Inst.getMetadata(M.getMDKindID("nosanitize")))
          continue;
        
        if (isa<PHINode>(&Inst)) continue;
        
        for (auto op = Inst.op_begin(); op != Inst.op_end(); ++op) {
          Value* V = op->get();
          if (DbgVals.find(V) != DbgVals.end()) {
            if (std::find(Locals.begin(), Locals.end(), V) == Locals.end())
              Locals.push_back(V);
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
            if (!isa<ConstantInt>(Idx->get()))
              OP.push_back(Idx->get());
          }
          
          if (OP.size() > 1)
            GEPs.push_back(OP);

        } else if (auto LD = dyn_cast<LoadInst>(&Inst)) {
          
          std::vector<Value*> OP;
          OP.push_back(LD->getPointerOperand());
          OP.push_back(LD);
          
          LDs.push_back(OP);
          
        } else if (auto ST = dyn_cast<StoreInst>(&Inst)) {
          
          std::vector<Value*> OP;
          OP.push_back(ST->getPointerOperand());
          OP.push_back(ST->getValueOperand());
          
          STs.push_back(OP);
          
        }
      }
    
    }
    
    BBInfo* Info = new BBInfo();
    Info->Name = BBname;
    Info->HasConstrs = Constrs->find(BBname) != Constrs->end();
    
    for (size_t i = 0; i < Locals.size(); ++i) {
    
      Info->Variables["LOC_" + std::to_string(i) + GetVarName(Locals[i])] = Locals[i];

    }

    for (size_t i = 0; i < GEPs.size(); ++i) {
    
      Info->Variables["GEPPtr_" + std::to_string(i) + GetVarName(GEPs[i][0])] = GEPs[i][0];
      for (size_t j = 1; j < GEPs[i].size(); ++j)
        Info->Variables["GEPIdx_" + std::to_string(i) + "_" + std::to_string(j) + GetVarName(GEPs[i][j])] = GEPs[i][j];

    }
    
    for (size_t i = 0; i < LDs.size(); ++i) {
    
      Info->Variables["LDPtr_" + std::to_string(i) + GetVarName(LDs[i][0])] = LDs[i][0];
      Info->Variables["LDVal_" + std::to_string(i) + GetVarName(LDs[i][1])] = LDs[i][1];

    }
    
    for (size_t i = 0; i < STs.size(); ++i) {
    
      Info->Variables["STPtr_" + std::to_string(i) + GetVarName(STs[i][0])] = STs[i][0];
      Info->Variables["STVal_" + std::to_string(i) + GetVarName(STs[i][1])] = STs[i][1];

    }
    
    for (auto& P : Info->Variables) {
      Info->LoadReprs[P.first] = GenLoadRepr(P.second);
    }
    Infos[BB] = Info;
  
  }
  
  for (auto BB : BBs) {
  
    //if (Infos.find(BB) == Infos.end()) continue;
  
    SmallVector<BasicBlock*, 3> Doms;
    DT.getDescendants(BB, Doms);
    for (auto DBB : Doms) {
      if (DBB != BB) {
        Infos[DBB]->Dominators.push_back(BB);
        Infos[BB]->Dominateds.push_back(DBB); 
      }
    }
  
  }
  
  for (auto BB : BBs) {
  
    if (!Infos[BB]->HasConstrs) continue;

    auto CST = (*Constrs)[Infos[BB]->Name];
    IRBuilder<> IRB(BB->getTerminator());
    
    for (auto& JC : CST["ENTER"]["constrs"]) {
    
      std::string Rep = JC["rep"].get<std::string>();
      bool Dominated = false;

      for (auto Dom : Infos[BB]->Dominators) {
      
        if (!Infos[Dom]->HasConstrs) continue;
        
        for (auto &DJC : (*Constrs)[Infos[Dom]->Name]["ENTER"]["constrs"]) {
        
          std::string DCRep = DJC["rep"].get<std::string>();
          if (DCRep == Rep && DJC["type"].get<int>() == JC["type"].get<int>()) {
          
            bool Eq = true;
            for (size_t i = 0; i < JC["vars"].size(); ++i) {

              auto N1 = JC["vars"][i].get<std::string>();
              auto N2 = DJC["vars"][i].get<std::string>();
              
              if (Infos[BB]->Variables[N1] != Infos[Dom]->Variables[N2])
                Eq = false;
            
            }
            
            if (Eq) {
              Dominated = true;
              errs() << JC["func"].get<std::string>() << " dominated by " << DJC["func"].get<std::string>() << "\n";
            }
          
          }
        
        }
      
      }
      
      if (Dominated) continue;
    
      std::vector<Value*> Params;
      std::vector<Type*> ParamsTy;
      
      errs() << "Inserting call to " << JC["func"].get<std::string>() << "\n";
     
      bool mustSkip = false;
      for (auto& NJ : JC["vars"]) {

        auto N = NJ.get<std::string>();

        if (Infos[BB]->Variables[N] == nullptr) {
          mustSkip = true;
          break;
        }

        Params.push_back(Infos[BB]->Variables[N]);
        ParamsTy.push_back(Infos[BB]->Variables[N]->getType());
      
      }

      if (mustSkip) {
        errs() << "SKIPPING\n";
        continue;
      }

      FunctionCallee ConstrFn = M.getOrInsertFunction(JC["func"].get<std::string>(), FunctionType::get(Int32Ty, ParamsTy, false));
      Value* H = IRB.CreateCall(ConstrFn, Params);
      Infos[BB]->Hashes[JC["func"].get<std::string>()] = H;
      
      for (auto Dom : Infos[BB]->Dominateds) {

        bool Useds = true;
        for (auto& NJ : JC["vars"]) {
        
          auto N = NJ.get<std::string>();
          Value *V = Infos[BB]->Variables[N];

          if (!V->isUsedInBasicBlock(Dom))
            Useds = false;
        
        }
        
        if (Useds) Infos[Dom]->Hashes[JC["func"].get<std::string>()] = H;
      
      }
      
    }
    
  }
  
  for (auto BB : BBs) {
  
    IRBuilder<> IRB(BB->getTerminator());
    
    Instruction* PrevLoc = IRB.CreateLoad(AFLPrevLoc);
    PrevLoc->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(*C, None));
    
    Value* X = PrevLoc;
    for (auto T : Infos[BB]->Hashes)
      X = IRB.CreateXor(X, T.second);

    Instruction* ST = IRB.CreateStore(X, AFLPrevLoc);
    ST->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(*C, None));
  
  }
  
  for (auto I : Infos)
    delete I.second;
  
  return FunctionModified;
  
}

class InvsCovInstrumentFunctionPass : public FunctionPass {
public:
  static char ID;

  explicit InvsCovInstrumentFunctionPass() : FunctionPass(ID) {}

  void getAnalysisUsage(AnalysisUsage &AU) const override {
    AU.setPreservesCFG();
    AU.addRequired<LoopInfoWrapperPass>();
    AU.addRequired<DominatorTreeWrapperPass>();
  }

  StringRef getPassName() const override {
    return "InvsCovInstrumentFunctionPass";
  }

  bool runOnFunction(Function &F) override {
    Module &M = *F.getParent();
    LoopInfo &LI = getAnalysis<LoopInfoWrapperPass>().getLoopInfo();
    DominatorTree &DT = getAnalysis<DominatorTreeWrapperPass>().getDomTree();
    InvsCovInstrument DI(M, F, LI, DT);
    bool r = DI.instrumentFunction();
    verifyFunction(F);
    return r;
  }
};


char InvsCovInstrumentFunctionPass::ID = 0;

static void registerInvsCovPass(const PassManagerBuilder &,
                               legacy::PassManagerBase &PM) {

  PM.add(new InvsCovInstrumentFunctionPass());

}

static RegisterStandardPasses RegisterInvsCovPass(
    PassManagerBuilder::EP_OptimizerLast, registerInvsCovPass);

static RegisterStandardPasses RegisterInvsCovPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerInvsCovPass);

static RegisterPass<InvsCovInstrumentFunctionPass>
    X("invscov-instrument", "InvsCovInstrumentFunctionPass",
      false,
      false
    );

