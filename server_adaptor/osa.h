
#ifndef SA_O_H
#define SA_O_H

#include "sa_def.h"

#include <map>

#ifdef __cplusplus
extern "C" {
#endif

int OSA_InitExt(void *ophandler, uint32_t ptNum, uint32_t clusterTotalPtNum, std::map<uint32_t, uint32_t> &localPtMap);
int OSA_Finish();
int OSA_FinishCacheOps(void *p, int r);
void OSA_ProcessBuf(const char *buf, unsigned int len, int cnt, void *p);

void OSA_EncodeOmapGetkeys(const SaBatchKeys *batchKeys, int i, void *p);
void OSA_EncodeOmapGetvals(const SaBatchKv *KVs, int i,void *p);
void OSA_EncodeOmapGetvalsbykeys(const SaBatchKv *keyValue, int i, void *p);
void OSA_EncodeRead(uint64_t opType, unsigned int offset, unsigned int len, char *buf, unsigned int bufLen, int i, void *p);
void OSA_SetOpResult(int i, int32_t ret, void *p);
void OSA_EncodeXattrGetxattr(const SaBatchKv *keyValue, int i, void *p);
void OSA_EncodeXattrGetxattrs(const SaBatchKv *keyValue, int i, void *p);
void OSA_EncodeGetOpstat(uint64_t psize, time_t ptime, int i, void *p);
int OSA_ExecClass(SaOpContext *pctx, PREFETCH_FUNC prefetch);

#ifdef __cplusplus
}
#endif

#endif
