
#include "CephProxyInterface.h"
#include "CephproxyOp.h"

completion_t CompletionInit(userCallback_t fn, void *cbArg)
{
    Completion *c = new Completion(fn, cbArg);
    completion_t rc = c;
    return rc;
}
void CompletionDestroy(completion_t c){
    Completion *comp = static_cast<Completion *>(c);
    delete comp;
}
