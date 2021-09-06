#include "RadosWorker.h"
#include "CephProxyOp.h"
#include "RadosWrapper.h"

#include <pthread.h>
#include <string>
#include <vector>
#include <utility>

void RadosIOWorker::Queue(rados_ioctx_t ioctx, ceph_proxy_op_t op, completion_t c )
{
    std::unique_lock ul(ioworkerLock);

    RequestCtx reqCtx;
    reqCtx.ioctx = ioctx;
    reqCtx.op = op;
    reqCtx.comp = c;

    if (Ops.empty()) {
	ioworkerCond.notify_all();
    }

    Ops.push_back(reqCtx);
}

void* RadosIOWorker::OpHandler() {
    std::unique_lock ul(ioworkerLock);

    while(!ioworkerStop) {
	while(!Ops.empty()) {
	    std::vector<RequestCtx> ls;
	    ls.swap(Ops);
	    ioworkerRunning = true;
    	    ul.unlock();

            int ret;
	    for (auto opair : ls) {
  		Completion *c = static_cast<Completion *>(opair.comp);
		ret = RadosOperationAioOperate(proxy->radosClient, opair.op, opair.ioctx, c->fn, c->cbArg);
		if (ret < 0 ) {
		    std::cout << "Rados Aio operate failed: " << ret << std::endl;
		    continue;
		}
	    }
	    ls.clear();

	    ul.lock();
	    ioworkerRunning = false;
	}
	
	if (ioworkerEmptyWait) {
	    ioworkerEmptyCond.notify_all();
	}

	if (ioworkerStop == true) {
	    break;
	}

	ioworkerCond.wait(ul);
    }
    ioworkerEmptyCond.notify_all();
    ioworkerStop = false;
  
    return (void *)NULL;
}
