#ifndef _CEPH_PROXY_H_
#define _CEPH_PROXY_H_

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <iostream>
#include <string>

#include "CephProxyInterface.h"
#include "RadosWorker.h"
#include "PoolContext.h"

typedef void *rados_client_t;

class RadosWorker;

typedef enum {
	PROXY_INITING = 1,
	PROXY_ACTIVE = 2,
	PROXY_DOWN = 3,
}CephProxyState;

struct ProxyConfig {
    std::string cephConfigFile;
    std::string logPath;
    size_t workerNum;
    bool useCheck;
};

class CephProxy {
public:
	rados_client_t radosClient;
	IOCtxTable ptable;
	ProxyConfig config;
	RadosWorker *worker;
	CephProxyState state;

	static CephProxy *instance;
private:
	CephProxy(): state(PROXY_DOWN) { }
public:
	static CephProxy *GetProxy() {
	    if ( instance == nullptr) {
		 instance = new CephProxy();
	     }
	     return instance;
	}

	int Init(const std::string& cephConf,const std::string &logPath, size_t wNum);
	void Shutdown();
	void Enqueue(rados_ioctx_t ioctx, ceph_proxy_op_t op, completion_t c);
	CephProxyState GetState() const;
	rados_ioctx_t GetIoCtx(const std::string& pool);
	rados_ioctx_t GetIoCtx2(const int64_t poolId);
	int GetClusterStat(CephClusterStat *stat);
	int GetPoolStat(rados_ioctx_t ctx, CephPoolStat *stat);
};

#endif
