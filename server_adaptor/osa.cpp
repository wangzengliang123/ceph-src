#include <string> 
#include <iostream>
#include <vector>

#include <global/global_init.h>

#include "network_module.h"
#include "config_read.h"
#include "salog.h" 
#include "osa.h"
#include "conf_parser.h"

using namespace std;

NetworkModule *g_ptrNetwork = nullptr;
namespace {
const string LOG_TYPE = "SAO_INTERFACE";
const int ERROR_PORT = 101;
}

class OphandlerModule;
void OSA_DoTest(bool testPing, bool testMosdop);

ClassHandler *rpc_handler = nullptr;
void cls_initialize(ClassHandler *ch);

int rpc_init()
{
	ClassHandler::ClassData *cls = nullptr;
	int ret;
	ret = rpc_handler->open_class(string("rgw"), &cls);
	if (ret) {
	   Salog(LV_WARNING, LOG_TYPE, "open cls_rgw failed");
	   return ret;
        }

	cls = nullptr;
	ret = rpc_handler->open_class(string("lock", &cls);
	if (ret) {
	   Salog(LV_WARNING, LOG_TYPE, "open cls_lock failed");
	   return ret;
	}
	return 0;
}

bool IsDigit(const char *c, uint32_t length)
{
   for ( int i = 0; i < length; i++) {
	if (c[i] < '0' || c[i] > '9') {
	    return false;
	}
   }
   return true;
}

int OSA_InitExt(void *ophandler, uint32_t ptNum, uint32_t clusterTotalPtNum, std::map<uint32_t, uint32_t> &localPtMap)
{
    InitSalog("/var/log", "sa", LV_DEBUG, LV_DEBUG);
    Salog(LV_WARNING, LOG_TYPE, "OSA Init 0901J");

    char *confPath = GetConfPath();
    string filePath = confPath;
    filePath += "config_sa.conf";
    Salog(LV_WARNING, LOG_TYPE, "OSA conf_file path is %s", filePath.c_str());
    CacheClusterConfigInit(filePath.c_str());
    string rAddr = GetListenIp();
    string rPort = GetListenPort();
    int portNum = atoi(rPort.c_str());
    if (IsDigit(rPort.c_str(), rPort.size()) == false ) {
	Salog(LV_CRITICAL, LOG_TYPE, "error : port is not digit");
	return ERROR_PORT;
    }

    if (portNum > 65535 || portNum < 1024) {
	Salog(LV_CRITICAL, LOG_TYPE, "error : port number is %s", rPort.c_str());
	return ERROR_PORT;
    }

    uint32_t coreNumber = GetCoreNumber();
    if (coreNumber > 16 || coreNumber < 4) {
	Salog(LV_CRITICAL, LOG_TYPE, "error : coreNumber number is %d", coreNumber);
	return ERROR_PORT;
    }

    uint32_t queueAmount = GetQueueAmount();
    if (queueAmount > 16 || queueAmount < 4) {
	Salog(LV_CRITICAL, LOG_TYPE, "error : queueAmount number is %d", queueAmount);
	return ERROR_PORT;
    }
   
    uint32_t msgrAmount = GetMsgrAmount();
    if (msgrAmount > 16 || msgrAmount < 4) {
	Salog(LV_CRITICAL, LOG_TYPE, "error : msgrAmount number is %d", msgrAmount);
 	return ERROR_PORT;
    }
    char szMsgrAmount[4] = {0};
    sprintf(szMsgrAmount, "%d", msgrAmount);
    Salog(LV_INFORMATION, LOG_TYPE, " Server adaptor init coreNumber=%d queueAmount=%d szMsgrAmount=%s", coreNumber, queueAmount, szMsgrAmount);
    vector<const char *> args;
    map<string, string> defaults = { { "ms_saync_op_threads", szMsgrAmount } };
    static auto cct = global_init(&defaults, args, 0xFF /* 0xFF CEPH_ENTITY_TYPE_ANY */,
    CODE_ENVIRONMENT_LIBRARY /*CODE_ENVIRONMENT_LIBRARY CODE_ENVIRONMENT_DAEMON */,
    CINIT_FLAG_NO_DEFAULT_CONFIG_FILE);
    
    int ret = 0;
    if (g_ptrNetwork == nullptr) {
        g_ptrNetwork = new NetworkModule((OphandlerModule *)ophandler);
	g_ptrNetwork->CreateWorkThread(ptNum, queueAmount, clusterTotalPtNum, localPtMap, coreNumber);
	
	char *confPath = GetConfPath();
	string filePath = confPath;
 	filePath += "config_sa.conf";
        Salog(LV_WARNING, LOG_TYPE, "OSA conf_file path is %s", filePath.c_str());
        CacheClusterConfigInit(filePath.c_str());
        string rAddr = GetListenIp();
        string rPort = GetListenPort();
        int portNum = atoi(rPort.c_str());
        if (IsDigit(rPort.c_str(), rPort.size()) == false ) {
            Salog(LV_CRITICAL, LOG_TYPE, "error : port is not digit");
            return ERROR_PORT;
	}
        if (portNum > 65535 || portNum < 1024) {
      	    Salog(LV_CRITICAL, LOG_TYPE, "error : port number is %s", rPort.c_str());
	    return ERROR_PORT;
        }

	string sAddr = rAddr;
        string sPort = rPort;
	string testMode = "0";
	Salog(LV_INFORMATION, LOG_TYPE, "Server adaptor init rAddr=%s rPort=%s sAddr=%s sPort==%s testMode =%s" ,
	rAddr.c_str(),rPort.c_str(), sAddr.c_str(), sPort.c_str(), testMode.c_str());
	if (rAddr == "" || rPort == "") {
	    Salog(LV_CRITICAL, LOG_TYPE, "error : Server adaptor Listen ip:port is empty.");
	    return 1;
	}
	ret = g_ptrNetwork->InitNetworkModule(rAddr, rPort, sAddr, sPort);

	rpc_handler = new ClassHandler(g_ceph_context);
	cls_initialize(rpc_handler);
	rpc_init();
	
	if (testMode == "1") {
            Salog(LV_INFORMATION, LOG_TYPE, "testMode is ping.");
	    OSA_DoTest(true, false);
	} else if (testMode == "2") {
            Salog(LV_INFORMATION, LOG_TYPE, "testMode is MOOSDOp.");
	    OSA_DoTest(false, true);
	}
    }
    return ret;
}

void OSA_DoTest(bool testPing, bool testMosdop)
{
    if (g_ptrNetwork) {
	sleep(1);
	g_ptrNetwork->TestSimulateClient(testPing, testMosdop);
    }
}
      
int OSA_Finish()
{
    Salog(LV_WARNING, LOG_TYPE, "SAO_Finish");
    int ret = 0;
    if( g_ptrNetwork == nullptr) {
	return 1;
    }
    ret = g_ptrNetwork->FinishNetworkModule();
    g_ptrNetwork->StopThread();
    delete g_ptrNetwork;
    g_ptrNetwork = nullptr;
    if (rpc_handler) {
	rpc_handler->shutdown();
	rpc_handler = nullptr;
    }
    FinishSalog("sa");
    Salog(LV_WARNING,LOG_TYPE, "SAO_Finish ret=%d",ret);
    return ret;
}

int OSA_FinishCacheOps(void *p, int r)
{
    int ret= 0;
    FinishCacheOps(p, r);
    return ret;
}

void OSA_ProcessBuf(const char *buf, unsigned int len, int cnt, void *p)
{
    ProcessBuf(buf, len, cnt, p);
}

void OSA_EncodeOmapGetkeys(const SaBatchKeys *batchKeys, int i, void *p)
{
    MOSDOp *ptr = (MOSDOp *)(p);
    EncodeOmapGetkeys(batchKeys, i , ptr);
}

void OSA_EncodeOmapGetvals(const SaBatchKv *KVs, int i,void *p)
{
    MOSDOp *ptr = (MOSDOp *)(p);
    EncodeOmapGetvals(KVs, i, ptr);
}

void OSA_EncodeOmapGetvalsbykeys(const SaBatchKv *keyValue, int i, void *p)
{
    MOSDOp *ptr = (MOSDOp *)(p);
    EncodeOmapGetvalsbykeys(keyValue, i, ptr);
}

void OSA_EncodeRead(uint64_t opType, unsigned int offset, unsigned int len, char *buf, unsigned int bufLen, int i, void *p)
{
    MOSDOp *ptr = (MOSDOp *)(p);
    EncodeRead(opType, offset, len, buf, bufLen, i, ptr);
}

void OSA_SetOpResult(int i, int32_t ret, void *p)
{
    MOSDOp *ptr = (MOSDOp *)(p);
    SetOpResult(i, ret, ptr);
}

void OSA_EncodeXattrGetxattr(const SaBatchKv *keyValue, int i, void *p)
{
    MOSDOp *ptr = (MOSDOp *)(p);
    EncodeXattrGetxattr(keyValue, i, ptr);
}

void OSA_EncodeXattrGetxattrs(const SaBatchKv *keyValue, int i, void *p)
{
    MOSDOp *ptr = (MOSDOp *)(p);
    EncodeXattrGetxattrs(keyValue, i, ptr);
}

void OSA_EncodeGetOpstat(uint64_t psize, time_t ptime, int i, void *p)
{
    MOSDOp *ptr = (MOSDOp *)(p);
    EncodeGetOpstat(psize, ptime, i, ptr);
}

int OSA_ExecClass(SaOpContext *pctx, PREFETCH_FUNC prefetch)
{
    struct SaOpReq * pOpReq = pctx->OpReq;
    MOSDOp *ptr = reinterpret_cast<MOSDOp *>(pOpReq->ptrMosdop);
    OSDOp &clientop = ptr->ops[pctx->opId];
    string cname, mname;
    bufferlist indata;
    auto bp = clientop.indata.cbegin();
    try {
	bp.copy(clientop.op.cls.class_len, cname);
	bp.copy(clientop.op.cls.method_len, mname);
	bp.copy(clientop.op.cls.indata_len, indata);
    } catch ( buffer::error &e) {
	Salog(LV_ERROR, LOG_TYPE, "unable to decode class [%s] + method[%s] + indata[%d]", cname, mname, clientop.op.cls.indata_len);
	return -EINVAL;
    }
    if (cname.compare("rpc") == 0 && mname.compare("das_prefetch") == 0) {
	uint64_t offset;
	uint64_t len;
	auto bp = indata.cbegin();
	decode(offset, bp);
	decode(len, bp);
	OpRequestOps &osdop = pOpReq->vecOps[pctx->opId];

	osdop.objOffset = offset;
	osdop.objLength = len'
	return prefetch(pOpReq, &osdop);
    }

    ClassHandler::ClassData *cls;
    int ret = rpc_handler->open_class(cname, &cls);
    if ( ret) {
	Salog(LV_ERROR,LOG_TYPE, "can't find class [%s] + method[%s]", cname, mname);
	return -EOPNOTSUPP;
    }
  
    bufferlist outdata;
    int result = method->exec(pctx, indata, outdata);
    if ( result == 0) {
	ptr->ops[pctx->opId].op.extent.length = outdata.length();
	ptr->ops[pctx->opId].outdata.claim_append(outdata);
    }
    return result;
}

