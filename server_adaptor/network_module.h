/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: Interact with Messanger(ClientAdaptor) and CCM agent.
 */

#ifndef NETWORK_MODULE_H
#define NETWORK_MODULE_H

#include <queue>
#include <pthread.h>
#include <thread>
#include <string>
#include <vector>
#include <message/MOSDOp.h>
#include <message/MOSDOpReply.h>

#include "sa_server_dispatcher.h"
#include "sa_client_dispatcher.h"
#include "sa_def.h"
#include "client_op_queue.h" 

class OphandlerModule;
class NetworkModule {
    OphandlerModule *ptrOphandleInstance { nullptr };
    pthread_t serverThread { 0 };
    pthread_t clientThread { 0 };
    pthread_t transToOpreqThread { 0 } ;
    pthread_t sendOpreplyThread { 0 };

    bool startServerThread { false };
    bool startClientThread { false };
    bool startTranToOpreqThread { false };
    bool startSendOpreplyThread { false };

    Messenger *serverMessenger { nullptr };
    SaServerDispatcher *serverDispatcher { nullptr };
    entity_addr_t recvBindAddr;
    Messenger *clientMessenger { nullptr };
    SaClientDispatcher *clientDispatcher { nullptr };
    entity_addr_t sendBindAddr;

    std::string recvAddr { "localhost" };
    std::string recvPort { "1234" };
    std::string sendAddr { "localhost" };
    std::string sendPort { "1234" };

    MsgModule *ptrMsgModule { nullptr };
    std::queue<MOSDOp *> qReadyTransToOpreq {};
    std::queue<MOSDOpReply *> qSendToClientAdaptor {};

    bool testPing { false };
    bool testMosdop { false };

    uint64_t ptNum { 0 };
    uint64_t queueNum { 0 };
    uint64_t totalPtNum { 0 };
    std::map<uint32_t, uint32_t> nodePtMap;
    std::vector<std::thread> doOpThread {};
    std::vector<ClientOpQueue *> opDispatcher {};
    std::vector<bool> finishThread {};

    int InitMessenger();
    int FinishMessenger();

public:
    NetworkModule() = delete;
    explicit NetworkModule(OphandlerModule *p)
    {
        if (p) {
            ptrOphandleInstance = p;
        }
    }

    ~NetworkModule()
    {
        if (ptrMsgModule) {
            delete ptrMsgModule;
        }
        ptrOphandleInstance = nullptr;
        if (serverMessenger) {
            delete serverMessenger;
        }
        if (clientMessenger) {
            delete clientMessenger;
        }
        if (clientDispatcher) {
            delete clientDispatcher;
        }
        if (serverDispatcher) {
            delete serverDispatcher;
        }
    }

    int InitNetworkModule(const std::string &rAddr, const std::string &rPort, const std::string &sAddr,
        const std::string &sPort);
    int FinishNetworkModule();
    int ThreadFuncBodyServer();
    int ThreadFuncBodyClient();

    void CreateWorkThread(uint32_t ptNum, uint32_t queueNum, uint32_t clusterTotalPtNum,
        std::map<uint32_t, uint32_t> &localPtMap, uint32_t coreNumber);
    void StopThread();
    void OpHandlerThread(int threadNum, int coreId);
    MsgModule *GetMsgModule()
    {
        return ptrMsgModule;
    }
    uint32_t EnqueueClientop(MOSDOp *opReq);
};

void FinishCacheOps(void *op, int32_t r);
void ProcessBuf(const char *buf, uint32_t len, int cnt, void *p);

void EncodeOmapGetkeys(const SaBatchKeys *batchKeys, int i, MOSDOp *p);
void EncodeOmapGetVals(const SaBatchKv *Kvs, int i, MOSDOp *mosdop);
void EncodeOmapGetvalsbykeys(const SaBatchKv *keyValue, int i, MOSDOp *mosdop);
void EncodeRead(uint64_t opType, unsigned int offset, unsigned int len, char *buf, unsigned int bufLen, int i,
    MOSDOp *mosdop);
void SetOpResult(int i, int32_t ret, MOSDOp *op);
void EncodeXattrGetXattr(const SaBatchKv *keyValue, int i, MOSDOp *mosdop);
void EncodeXattrGetXattrs(const SaBatchKv *keyValue, int i, MOSDOp *mosdop);
void EncodeGetOpstat(uint64_t psize, time_t ptime, int i, MOSDOp *mosdop);
#endif

