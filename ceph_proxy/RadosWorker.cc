#include "RadosWorker.h"
#include "CephProxyop.h"
#include "RadosWrapper.h"

#include <pthread.h>
#include <string>
#include <vector>
#include <utility>

void RadosIoWorker::Queue(rados_ioctx_t ioctx, ceph_proxy_op_t op, commpletion_t c )
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

void* RadosIoWorker::opHandler() {
    std::unique_lock ul(ioworkerLock);

    while(!ioworkerStop) {
	while(!Ops.empty()) {
	    std::vector<RequestCtx> ls;
	    ls.swqp(Ops);
	    ioworkerRuning = true;
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
	    ioworkerRuning = false;
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
    ioworkerStop == false;
  
    return (void *)NULL;
}
