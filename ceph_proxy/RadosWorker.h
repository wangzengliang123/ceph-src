#ifndef _CEPH_PROXY_RADOS_WORKER_H_
#define _CEPH_PROXY_RADOS_WORKER_H_

#include "CephProxyInterface.h"
#include "CephProxy.h"

#include <unistd.h>
#include <pthread.h>

#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <condition_variable>

#define WORKER_MAX_NUM 8

const unsigned PAGE_SIZE = sysconf(_SC_PAGESIZE);
const unsigned long PAGE_MASK = ~(unsigned long)(PAGE_SIZE -1);

typedef enum {
    RADOSWORKER_INITED = 0,
    RADOSWORKER_RUNING = 1,
    RADOSWORKER_DOWNED = 2,
} WorkerState;

typedef enum {
    IOWORKER_INITED   = 0,
    IOWORKER_RUNNING  = 1,
    IOWORKER_STOP     = 2,
} IOWorkerState;

class CephProxy;

class MyThread {
private:
    pthread_t threadId;
    int cpuId;
    const char *threadName;

    void *entryWrapper() {
	return entry();
    }
public:
    MyThread(const MyThread&) = delete;
    MyThread& operator=(const MyThread&) = delete;

    MyThread():threadId(0), cpuId(-1), threadName(NULL) {

    }

    virtual ~MyThread() {

    }

protected:
    virtual void *entry() = 0;
private:
    static void *_entryFunc(void *arg) {
	void *r = ((MyThread*)arg)->entryWrapper();
	return r;
    }
public:
    const pthread_t &GetThreadId() const {
	return threadId;
    }

    bool IsStarted() const {
	return threadId != 0;
    }

    bool AmSelf() const {
     	return (pthread_self() ==threadId);
    }

    int TryCreate(size_t stacksize) {

	pthread_attr_t *threadAttr = nullptr;
	pthread_attr_t threadAttrLoc;

	stacksize &= PAGE_MASK;
	if (stacksize) {
	    threadAttr = &threadAttrLoc;
	    pthread_attr_init(threadAttr);
	    pthread_attr_setstacksize(threadAttr, stacksize);
	}

	int r = pthread_create(&threadId, nullptr, _entryFunc, (void *)this);

	if (threadAttr) {
	    pthread_attr_destroy(threadAttr);
	}

	return r;
    }

    void Create(const char *name, size_t stacksize = 0 ) {
	threadName = name;
	int ret = TryCreate(stacksize);
	if (ret != 0) {
	    std::cout << "Thread::try_create(): pthread_create failed with error " << ret << std::endl;
	}
    }

   int Join(void **prval = 0) {
	if(threadId == 0) {
	    return -EINVAL;
	}
	int status = pthread_join(threadId, prval);
	if (status != 0) {
	    std::cout<<"Thread::Join: pthread_Join failed with error " << status << std::endl;
	}
	threadId = 0;
	return status;
    }

    int Detach() {
	return pthread_detach(threadId);
    }

    int SetAffinity(int id) {
	// TODO:
	int r = 0;
	cpuId = id;
	return r;
    }
};
struct RequestCtx {
    rados_ioctx_t ioctx;
    ceph_proxy_op_t op;
    completion_t comp;
public:
    RequestCtx() {

    }

    RequestCtx(rados_ioctx_t _ioctx, ceph_proxy_op_t _op, completion_t _comp):
	ioctx(_ioctx), op(_op), comp(_comp) {
    }

    RequestCtx(const RequestCtx &ctx) {
	ioctx = ctx.ioctx;
	op = ctx.op;
	comp = ctx.comp;
    }

    ~RequestCtx() {
    
    }
};

class RadosIOWorker {
public:
    std::mutex ioworkerLock;
    std::condition_variable ioworkerCond;
    std::condition_variable ioworkerEmptyCond;

    bool ioworkerStop;
    bool ioworkerRunning;
    bool ioworkerEmptyWait;

    CephProxy *proxy;
    std::vector<RequestCtx> Ops;
    std::string workerName;

    class IOWorker : public MyThread {
    public:
	RadosIOWorker *ioworker;
	IOWorker(RadosIOWorker *w): ioworker(w) {

	}
	
	~IOWorker() {

	}
    public:
	void *entry() override {
	    return ioworker->OpHandler();
	}
    } ioThread;

public:
    RadosIOWorker(CephProxy *_proxy):
	ioworkerStop(false),ioworkerRunning(false),
	ioworkerEmptyWait(false), proxy(_proxy),
	workerName("ioworker"), ioThread(this){
    }

    ~RadosIOWorker() {

    }

    void StartProc() {
	ioThread.Create(workerName.c_str());
    }

    void StopProc() {
	ioworkerLock.lock();
	ioworkerStop = true;
	ioworkerCond.notify_all();
	ioworkerLock.unlock();
	ioThread.Join();
    }

    void WaitForEmpty() {
	std::unique_lock<std::mutex> ul(ioworkerLock);
	while(!Ops.empty() || ioworkerRunning) {
	    ioworkerEmptyWait = true;
	    ioworkerEmptyCond.wait(ul);
	}
	ioworkerEmptyWait = false;
    }

    void Queue(rados_ioctx_t ioctx, ceph_proxy_op_t op, completion_t c);
    void *OpHandler();
};

class RadosWorker {
private:
    int workerNum;
    CephProxy *proxy;
    std::vector<RadosIOWorker *> ioWorkers;
    int curIdx;
public:
    RadosWorker(CephProxy *proxy): workerNum(1), proxy(proxy), curIdx(0) {
    }

    RadosWorker(int num, CephProxy *proxy): workerNum(num), proxy(proxy), curIdx(0) {
	if (workerNum > WORKER_MAX_NUM) {
            workerNum = WORKER_MAX_NUM;
	}
    }

    ~RadosWorker() {
	proxy = nullptr;
    }

    void Start() {
	for (int i = 0; i < workerNum; i++) {
	    RadosIOWorker *ioworker = new  RadosIOWorker(this->proxy);
	    ioworker->StartProc();
	    ioWorkers.push_back(ioworker);
	}
    }

    void Stop() {
	for ( int i = 0; i < workerNum; i++) {
	   ioWorkers[i]->WaitForEmpty();
	   ioWorkers[i]->StopProc();
	   delete ioWorkers[i];
	}

	ioWorkers.clear();
    }
    
    void Queue(rados_ioctx_t ioctx, ceph_proxy_op_t op, completion_t c) {
	int index = curIdx;
	curIdx = (curIdx + 1) % workerNum;
	ioWorkers[index]->Queue(ioctx, op, c);
    }
};

#endif
