#include "CephProxyInterface.h"
#include "CephProxy.h"
#include "PoolContext.h"
#include "RadosWrapper.h"
#include "CephProxyOp.h"
#include "RadosWorker.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <strings.h>

#include <iostream>
#include <string>
#include <vector>


CephProxy *CephProxy::instance = nullptr;

int CephProxy::Init(const std::string& cephconf,const std::string &logPath, size_t wNum)
{
    int ret = 0;
    config.cephConfigFile = cephConf;
    config.logPath = logPath;
    config.workerNum = wNum;
    state = PROXY_INITING;

    ret = RadosClientInit(&radosClient, config.cephConfigFile);
    if ( ret < 0) {
	fprintf(stderr, "RadosClient Init failed: %d\n", ret);
	return ret;
    }

    ret = ptable.Init();
    if ( ret != 0 ) {
	fprintf(stderr, "PoolCtxTable Init failed :%d.\n",ret);
	goto init_out;
    } 

    worker = new RadosWorker(config.workerNum, this);
    worker->Start();
    state = PROXY_ACTIVE;
    return ret;

init_out:
	RadosClientShutdown(radosClient);
	return ret;
}

void CephProxy::Shutdown() {

    if (worker) {
	worker->Stop();
	delete worker;
	worker = nullptr;
    }

    ptable.Clear();
    RadosClientShutdown(radosClient);
    state = PROXY_DOWN;
}

void CephProxy::Enqueue(rados_ioctx_t ioctx, ceph_proxy_op_t op, completion_t c)
{
	worker->Queue(ioctx, op, c);
}

rados_ioctx_t CephProxy::GetIoCtx(const std::string& pool)
{
	rados_ioctx_t ioctx = ptable.GetIoCtx(pool);
	if (ioctx == nullptr) {
	    int ret = RadosCreateIoCtx(radosClient, pool ,&ioctx);
	    if (ret != 0) {
		std::cout << "Create IoCtx failed: " << ret << std::endl;
		return nullptr;
	    }
            ptable.Insert(pool, ioctx);
	}
	return ioctx;
}

rados_ioctx_t CephProxy::GetIoCtx2(const int64_t poolId)
{
	rados_ioctx_t ioctx = ptable.GetIoCtx(poolId);
	if (ioctx == nullptr) {
	    int ret = RadosCreateIoCtx2(radosClient, poolId ,&ioctx);
	    if (ret != 0) {
		std::cout << "Create Ioctx failed: " << ret << std::endl;
		return nullptr;
	    }
            ptable.Insert(poolId, ioctx);
	}
	return ioctx;
}

int CephProxy::GetClusterStat(CephClusterStat *stat)
{
	return RadosGetClusterStat(radosClient, stat);
}

int CephProxy::GetPoolStat(rados_ioctx_t ctx, CephPoolStat *stat)
{
	return RadosGetPoolStat(radosClient, ctx, stat);
}

CephProxyState CephProxy::GetState() const {
	return state;
}


