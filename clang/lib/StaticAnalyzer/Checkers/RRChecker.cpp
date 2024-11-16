//
// Created by Victoria Nguyen on 11/12/24.
//
#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallDescription.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include <utility>

using namespace clang;
using namespace ento;


class RRChecker : public Checker<check::PostCall>{
  const CallDescription PCreate{CDM::CLibrary, {"pthread_create"}, 4};
public:
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
};

void RRChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  if(!PCreate.matches(Call)){return;}

  // pthread_create returns either 0 or not 0 -> this gets turned into some kind of symbol
  // a valid symbol means something was returned by the function; a null indicates nothing was returned
  SymbolRef s = Call.getReturnValue().getAsSymbol();
  if(!s){return;}

  // retrieve the SourceLocation and use the CallEvent's SourceManager to decode the line address
  const SourceManager &sm = C.getSourceManager();
  SourceLocation l = Call.getDecl() -> getLocation();
  llvm::outs() << "pthread_create detected at " << sm.getSpellingLineNumber(l) << "\n";
}

void ento::registerRRChecker(CheckerManager &mgr) {
  mgr.registerChecker<RRChecker>();
}


bool ento::shouldRegisterRRChecker(const CheckerManager &mgr) {
  return true;
}