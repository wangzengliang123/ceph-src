#include "CephProxyInterface.h"
#include "RadosWrapper.h"
#include "CephProxyOp.h"
#include "assert.h"

#include <cstddef>
#include <time.h>
#include <algorithm>
#include <string>
#include <list>
#include <map>

using namespace std;
using namespace librados;

int RadosClientInit(rados_client_t *client,const std::string &cephConf)
{
	int ret =0;
	librados::Rados *rados = new Rados();
	ret = rados->init("admin");
	if (ret<0) {
	return ret;
	}
	ret = rados->conf_read_file(cephConf.c_str());
	if (ret<0) {
	goto client_init_out;
	}
	ret = rados->connect();
	if(ret<0) {
	goto client_init_out;
	}

	*client = rados;
	return 0;
client_init_out:
	rados->shutdown();
	delete rados;
	*client = nullptr;
	return ret;
}

int RadosCreateIoCtx(rados_client_t client, const std::string &poolname,rados_ioctx_t *ctx)
{
	int ret = 0;
	librados::Rados *rados = reinterpret_cast<librados::Rados *>(client);
	librados::IoCtx *ioctx = new librados::IoCtx();
	ret = rados->ioctx_create(poolname.c_str(),*ioctx);
	if(ret<0){
	std::cout << "create ioctx failed." << std::endl;
	return ret;
}

	*ctx = ioctx;
	return 0;
}

int RadosCreateIoCtx2(rados_client_t client, const int64_t poolId,rados_ioctx_t *ctx)
{
	librados::Rados *rados = reinterpret_cast<librados::Rados *>(client);	
	librados::IoCtx *ioctx = new librados::IoCtx();
	int ret = rados->ioctx_create2(poolId,*ioctx);	
	if(ret<0){	
	std::cout << "create ioctx by poolId failed." << std::endl;
	return ret;
	}
	*ctx = ioctx;
	return 0;
}

void RadosReleaseIoCtx(rados_ioctx_t ctx)
{
	if(ctx != nullptr){
	librados::IoCtx *ioctx = reinterpret_cast<librados::IoCtx *>(ctx);
	delete ioctx;
	ctx = nullptr;
	}
}

void RadosClientShutdown(rados_client_t client)
{
	if(client != nullptr){
	librados::Rados *rados = reinterpret_cast<Rados *>(client);
	rados->shutdown();
	delete rados;
	client = nullptr;
	}
}

int RadosGetClusterStat(rados_client_t client,CephClusterStat *stat)
{	
	librados::Rados *rados = reinterpret_cast<librados::Rados *>(client);
	cluster_stat_t result;
	int ret = rados->cluster_stat(result);
	if(ret<0){
	std::cout << "get cluster stat failed: " << ret << std::endl;
	return ret;
	}

	stat->kb = result.kb;
	stat->kb_avail = result.kb_avail;
	stat->kb_used = result.kb_used;
	stat->num_objects = result.num_objects;

	return 0;
}

int RadosGetPoolStat(rados_client_t client,rados_ioctx_t ctx,CephPoolStat *stat)
{
	librados::IoCtx *ioctx = reinterpret_cast<librados::IoCtx *>(ctx);
	librados::Rados *rados = reinterpret_cast<librados::Rados *>(client);

	std::string pool_name = ioctx->get_pool_name();
	std::list<std::string> ls;
	ls.push_back(pool_name);

	std::map<std::string,pool_stat_t> rawresult;
	int ret =rados->get_pool_stats(ls,rawresult);
	if(ret !=0){
	std::cout << "get pool stat failed: " << ret << std::endl;
	return ret;
	}

	pool_stat_t &stats = rawresult[pool_name];
		
	stat->num_kb = stats.num_kb;
	stat->num_bytes = stats.num_bytes;
	stat->num_objects = stats.num_objects;
	stat->num_object_clones = stats.num_object_clones;
	stat->num_object_copies = stats.num_object_copies;
	stat->num_objects_missing_on_primary = stats.num_objects_missing_on_primary;
	stat->num_objects_unfound = stats.num_objects_unfound;
	stat->num_objects_degraded = stats.num_objects_degraded;
	stat->num_rd = stats.num_rd;
	stat->num_rd_kb = stats.num_rd_kb;
	stat->num_wr = stats.num_wr;
	stat->num_wr_kb = stats.num_wr_kb;
	stat->num_user_bytes = stats.num_user_bytes;
	stat->compressed_bytes_orig = stats.compressed_bytes_orig;
	stat->compressed_bytes = stats.compressed_bytes;
	stat->compressed_bytes_alloc = stats.compressed_bytes_alloc;

	return 0;
}

rados_op_t RadosWriteOpInit2(const string& pool, const string &oid)
{
	RadosObjectWriteOp *writeOp = new RadosObjectWriteOp(pool,oid);	
	rados_op_t op = reinterpret_cast<void *>(writeOp);
	return op;
}	

rados_op_t RadosWriteOpInit2(const int64_t poolId, const string &oid)
{
	RadosObjectOperation *writeOp = new RadosObjectWriteOp(poolId,oid);	
	rados_op_t op = reinterpret_cast<void *>(writeOp);
	return op;
}

void RadosWriteOpRelease(rados_op_t op)
{
	if(op != nullptr){
	RadosObjectWriteOp *writeOp = reinterpret_cast<RadosObjectWriteOp *>(op);
	delete writeOp;
	op = nullptr;
	}
}

void RadosWriteOpSetFlags(rados_op_t op,int flags)
{
	RadosObjectWriteOp *writeOp = reinterpret_cast<RadosObjectWriteOp*>(op);
	writeOp->op.set_op_flags2(flags);
}

void RadosWriteOpAssertExists(rados_op_t op)
{
	RadosObjectWriteOp*writeOp = reinterpret_cast<RadosObjectWriteOp*>(op);
	writeOp->op.assert_exists();
}

void RadosWriteOpAssertVersion(rados_op_t op,uint64_t ver)
{
	RadosObjectWriteOp*writeOp = reinterpret_cast<RadosObjectWriteOp*>(op);
	writeOp->op.assert_version(ver);
}

void RadosWriteOpCmpext(rados_op_t op,const char *cmpBuf,
			size_t cmpLen,uint64_t off,int *prval)
{
	RadosObjectWriteOp*writeOp = reinterpret_cast<RadosObjectWriteOp*>(op);
	bufferlist cmpBl;
	cmpBl.append(cmpBuf,cmpLen);
	writeOp->op.cmpext(off,cmpBl,prval);
}

void RadosWriteOpCmpXattr(rados_op_t op,const char *name,
			uint8_t compOperator,const char *value,size_t valLen)
{
	RadosObjectWriteOp*writeOp = reinterpret_cast<RadosObjectWriteOp*>(op);
	bufferlist valueBl;
	valueBl.append(value,valLen);
	writeOp->op.cmpxattr(name,compOperator,valueBl);
}

void RadosWriteOpOmapCmp(rados_op_t op,const char *key,uint8_t compOperator,
			const char *value,size_t valLen,int *prval)
{
	RadosObjectWriteOp*writeOp = reinterpret_cast<RadosObjectWriteOp*>(op);
	bufferlist bl;
	bl.append(value,valLen);
	std::map<std::string,pair<bufferlist,int>> assertions;
	std::string lkey = string(key,strlen(key));
	writeOp->op.omap_cmp(assertions,prval);
}

void RadosWriteOpSetXattr(rados_op_t op,const char *name,const char *value,size_t valLen)
{
	RadosObjectWriteOp*writeOp = reinterpret_cast<RadosObjectWriteOp*>(op);
	bufferlist bl;
	bl.append(value,valLen);
	writeOp->op.setxattr(name,bl);
}

void RadosWriteOpRemoveXattr(rados_op_t op,const char *name)
{
	RadosObjectWriteOp*writeOp = reinterpret_cast<RadosObjectWriteOp*>(op);
	writeOp->op.rmxattr(name);
}

void RadosWriteOpCreateObject(rados_op_t op, int exclusive, const char *category)
{
	RadosObjectWriteOp*writeOp = reinterpret_cast<RadosObjectWriteOp*>(op);
	writeOp->op.create(!!exclusive);
}

void RadosWriteOpWrite(rados_op_t op,const char *buffer,size_t len,uint64_t off)
{
	RadosObjectWriteOp*writeOp = reinterpret_cast<RadosObjectWriteOp*>(op);
	bufferlist bl;
	bl.append(buffer,len);	
	writeOp->op.write(off,bl);
}

void RadosWriteOpWriteSGL(rados_op_t op,SGL_S *sgl,size_t len,uint64_t off)
{
	RadosObjectWriteOp*writeOp = reinterpret_cast<RadosObjectWriteOp*>(op);
	bufferlist bl;
	uint32_t leftLen = len;
	uint32_t curSrcEntryIndex = 0;
	while(leftLen>0){
	size_t size = std::min(sgl->entrys[curSrcEntryIndex].len,leftLen);
	bl.append(sgl->entrys[curSrcEntryIndex].buf,size);
	leftLen -= size;
	curSrcEntryIndex++;
	if(curSrcEntryIndex >= sgl->entrySumInSgl) {
	curSrcEntryIndex = 0;
	sgl = sgl->nextSgl;
		}
	}
	
	writeOp->op.write(off,bl);
}	

void RadosWriteOpWriteFull(rados_op_t op,const char *buffer,size_t len)
{
	RadosObjectWriteOp*writeOp = reinterpret_cast<RadosObjectWriteOp*>(op);
	bufferlist bl;
	bl.append(buffer,len);						
	writeOp->op.write_full(bl);
}

void RadosWriteOpWriteFullSGL(rados_op_t op,const SGL_S *sgl,size_t len)
{
	RadosObjectWriteOp *writeOp = reinterpret_cast<RadosObjectWriteOp*>(op);
	bufferlist bl;
	uint32_t leftLen = len;
	uint32_t curSrcEntryIndex = 0;
	while(leftLen>0){
	size_t size = std::min(sgl->entrys[curSrcEntryIndex].len,leftLen);
	bl.append(sgl->entrys[curSrcEntryIndex].buf,size);
	leftLen -= size;
	curSrcEntryIndex++;	
	if(curSrcEntryIndex >= sgl->entrySumInSgl) {
	curSrcEntryIndex = 0;
	sgl = sgl->nextSgl;
		}
	}

	writeOp->op.write_full(bl);
}	

void RadosWriteOpWriteSame(rados_op_t op,const char *buffer,
			size_t dataLen,size_t writeLen,uint64_t off)
{
	RadosObjectWriteOp *writeOp = reinterpret_cast<RadosObjectWriteOp*>(op);
	bufferlist bl;	
	bl.append(buffer,dataLen);
	writeOp->op.writesame(off,writeLen,bl);	
}

void RadosWriteOpWriteSameSGL(rados_op_t op,const SGL_S *s,size_t dataLen,
			size_t writeLen,uint64_t off)
{
	RadosObjectWriteOp *writeOp = reinterpret_cast<RadosObjectWriteOp*>(op);
	bufferlist bl;
	uint32_t leftLen = dataLen;
	uint32_t curSrcEntryIndex = 0;
	while(leftLen>0){
	size_t size = std::min(s->entrys[curSrcEntryIndex].len,leftLen);
	bl.append(s->entrys[curSrcEntryIndex].buf,size);
	leftLen -= size;
	curSrcEntryIndex++;
	if(curSrcEntryIndex >= s->entrySumInSgl) {
	curSrcEntryIndex = 0;
	s = s->nextSgl;		
	}
    }
	writeOp->op.writesame(off,writeLen,bl);
}

void RadosWriteOpAppend(rados_op_t op,const char *buffer,size_t len)
{
	RadosObjectWriteOp *writeOp = reinterpret_cast<RadosObjectWriteOp*>(op);
	bufferlist bl;	
	bl.append(buffer,len);
	writeOp->op.append(bl);
}

void RadosWriteOpAppendSGL(rados_op_t op,const SGL_S *s,size_t len)
{
	RadosObjectWriteOp *writeOp = reinterpret_cast<RadosObjectWriteOp*>(op);
        bufferlist bl;
	uint32_t leftLen = len;
	uint32_t curSrcEntryIndex = 0;
	while(leftLen>0){
	size_t size = std::min(s->entrys[curSrcEntryIndex].len,leftLen);
	bl.append(s->entrys[curSrcEntryIndex].buf,size);
	leftLen -= size;
	curSrcEntryIndex++;
	if(curSrcEntryIndex >= s->entrySumInSgl) {
	curSrcEntryIndex = 0;
	s = s->nextSgl;
	}
   }
	writeOp->op.append(bl);
}

void RadosWriteOpRemove(rados_op_t op)
{
	RadosObjectWriteOp *writeOp = reinterpret_cast<RadosObjectWriteOp*>(op);
	writeOp->op.remove();
}

void RadosWriteOpTruncate(rados_op_t op,uint64_t off)	
{
	RadosObjectWriteOp *writeOp = reinterpret_cast<RadosObjectWriteOp*>(op);
	writeOp->op.truncate(off);
}

void RadosWriteOpZero(rados_op_t op,uint64_t off,uint64_t len)
{
	RadosObjectWriteOp *writeOp = reinterpret_cast<RadosObjectWriteOp*>(op);
	writeOp->op.zero(off,len);
}

void RadosWriteOpOmapSet(rados_op_t op,const char *const *keys,
		const char *const *vals,const size_t *lens,size_t num)
{
	RadosObjectWriteOp *writeOp = reinterpret_cast<RadosObjectWriteOp*>(op);
	std::map<std::string,bufferlist> entries;
	for (size_t i=0;i < num;i++){
	bufferlist bl(lens[i]);
	bl.append(vals[i],lens[i]);	
	entries[keys[i]] = bl;
	}
	
	writeOp->op.omap_set(entries);	
}

void RadosWriteOpOmapRmKeys(rados_op_t op,const char *const *keys,size_t keysLen)
{
	RadosObjectWriteOp *writeOp = reinterpret_cast<RadosObjectWriteOp*>(op);
	std::set<std::string> to_remove(keys,keys + keysLen);	
	writeOp->op.omap_rm_keys(to_remove);
}

void RadosWriteOpOmapClear(rados_op_t op)
{
	RadosObjectWriteOp *writeOp = reinterpret_cast<RadosObjectWriteOp*>(op);
	writeOp->op.omap_clear();
}

void RadosWriteOpSetAllocHint(rados_op_t op,uint64_t expectedObjSize,uint64_t expectedWriteSize,uint32_t flags)
{
	RadosObjectWriteOp *writeOp = reinterpret_cast<RadosObjectWriteOp*>(op);
	writeOp->op.set_alloc_hint2(expectedObjSize,expectedWriteSize,flags);
}

rados_op_t RadosReadOpInit(const string& pool,const string &oid)
{
	RadosObjectReadOp *readOp = new RadosObjectReadOp(pool,oid);
	rados_op_t op = reinterpret_cast<void *>(readOp);
	return op;
}

rados_op_t RadosReadOpInit2(const int64_t poolId,const string &oid)
{
	RadosObjectReadOp*readOp = new RadosObjectReadOp(poolId,oid);
	rados_op_t op = reinterpret_cast<void*>(readOp);
	return op;
}

void RadosReadOpRelease(rados_op_t op)
{
	if (op != nullptr){
	RadosObjectReadOp *readOp= reinterpret_cast<RadosObjectReadOp *>(op);
	delete readOp;
	op = nullptr;
	}
}

void RadosReadOpSetFlags(rados_op_t op,int flags)	
{
	RadosObjectReadOp *readOp=reinterpret_cast<RadosObjectReadOp*>(op);
	readOp->op.set_op_flags2(flags);
}

void RadosReadOpAssertExists(rados_op_t op)
{
	RadosObjectReadOp *readOp=reinterpret_cast<RadosObjectReadOp*>(op);
	readOp->op.assert_exists();
}

void RadosReadOpAssertVersion(rados_op_t op,uint64_t ver)
{
	RadosObjectReadOp *readOp=reinterpret_cast<RadosObjectReadOp*>(op);
	readOp->op.assert_version(ver);
}

void RadosReadOpCmpext(rados_op_t op,const char *cmpBuf,
			size_t cmpLen,uint64_t off,int *prval)
{
	RadosObjectReadOp *readOp=reinterpret_cast<RadosObjectReadOp*>(op);
	bufferlist bl;
	bl.append(cmpBuf,cmpLen);
	readOp->op.cmpext(off,bl,prval);
}

void RadosReadOpCmpXattr(rados_op_t op,const char *name,uint8_t compOperator,
			const char *value,size_t valueLen)
{
	RadosObjectReadOp *readOp=reinterpret_cast<RadosObjectReadOp*>(op);
	bufferlist bl;
	bl.append(value,valueLen);
	readOp->op.cmpxattr(name,compOperator,bl);
}

void RadosReadOpGetXattr(rados_op_t op,const char *name, char **val, int *prval)
{
	RadosObjectReadOp *readOp=reinterpret_cast<RadosObjectReadOp*>(op);
	readOp->reqCtx.xattr.vals = val;
	readOp->reqCtx.xattr.name = name;
	string key(name);
	readOp->op.getxattr(name,&(readOp->xattrs[name]),prval);
}

void RadosReadOpGetXattrs(rados_op_t op,proxy_xattrs_iter_t *iter,int *prval)
{
	RadosObjectReadOp *readOp=reinterpret_cast<RadosObjectReadOp*>(op);
	RadosXattrsIter *xIter = new RadosXattrsIter();
	readOp->op.getxattrs(&(xIter->attrset),prval);
	readOp->reqCtx.xattrs.iter = xIter;
	*iter = xIter;
}

int RadosGetXattrsNext(proxy_xattrs_iter_t iter,const char **name,const char **val,size_t *len)
{
	RadosXattrsIter *it = static_cast<RadosXattrsIter*>(iter);
	if(it->val){
	free(it->val);
	it->val = nullptr;
	}
	
	if (it->i == it->attrset.end()){
	*name = nullptr;
	*val = nullptr;
	*len = 0;
	return 0;
	}

	const std::string &s(it->i->first);
	*name = s.c_str();
	bufferlist &bl(it->i->second);
	size_t blLen = bl.length();
	if(!blLen){
	*val = (char *)NULL;
	}else{
	  it->val = (char *)malloc(blLen);
	if(!it->val){
		return -ENOMEM;
	}
	memcpy(it->val, bl.c_str(), blLen);
	*val = it->val;
	}
	*len = blLen;
	++it->i;
	return 0;	
}

void RadosGetXattrsEnd(proxy_xattrs_iter_t iter)
{
	RadosXattrsIter *it = static_cast<RadosXattrsIter *>(iter);
	delete it;
}

void RadosReadOpOmapGetVals(rados_op_t op, const char *startAfter,
	uint64_t maxReturn, rados_omap_iter_t *iter,
	unsigned char *pmore, int *prval)
{
	RadosObjectReadOp *readOp = reinterpret_cast<RadosObjectReadOp *>(op);
	RadosOmapIter *oIter = new RadosOmapIter();
	const char *start = startAfter ? startAfter : "";
	readOp->reqCtx.omap.iter = oIter;
	readOp->op.omap_get_vals2(start, maxReturn, &(oIter->values), (bool *)pmore, prval);
	*iter = oIter;
}

void RadosReadOpOmapGetKeys(rados_op_t op, const char *startAfter, uint64_t maxReturn,
				proxy_omap_iter_t *iter, unsigned char *pmore, int *prval)
{
	RadosObjectReadOp *readOp = reinterpret_cast<RadosObjectReadOp *>(op);
	RadosOmapIter *oIter = new RadosOmapIter();
	const char *start = startAfter ? startAfter : "";
	readOp->reqCtx.omap.iter = oIter;
	readOp->op.omap_get_keys2(start, maxReturn, &(oIter->values), (bool *)pmore, prval);
	*iter = oIter;
}
:w

int RadosOmapGetNext(proxy_omap_iter_t iter, char **key, char **val, size_t *keyLen, size_t *valLen)
{
    RadosOmapIter *it = static_cast<RadosOmapIter *>(iter);
    if (it->i == it->values.end()) {
	if (key) {
	   *key = nullptr;
	}

	if (val) {
	   *val = nullptr;
	}

	if (keyLen) {
	   *keyLen = 0;
	}

	if (valLen) {
	   *valLen = 0;
	}
        return 0 ;
    }

    if (key) {
	*key = (char *)it->i->first.c_str();
    }

    if (val) {
	*val = (char *)it->i->second.c_str();
    }

    if (keyLen) {
	*keyLen = it->i->first.length();
    }

    if (valLen) {
	*valLen = it->i->second.length();
    }
    ++it->i;
    return 0;
}
size_t RadosOmapIterSize(proxy_omap_iter_t iter) {
    RadosOmapIter *it = static_cast<RadosOmapIter *>(iter);
    return it->values.size();
}

void RadosOmapIterEnd(proxy_omap_iter_t iter)
{
    RadosOmapIter *it = static_cast<RadosOmapIter *>(iter);
    delete it;
}

void RadosReadOpOmapCmp(rados_op_t op, const char *key, uint8_t compOperator,
			const char *val, size_t valLen, int *prval)
{
    RadosObjectReadOp *readOp = reinterpret_cast<RadosObjectReadOp *>(op);
    bufferlist bl;
    bl.append(val, valLen);
    std::map<std::string, pair<bufferlist, int>> assertions;
    string lkey = string(key,strlen(key));

    assertions[lkey] = std::make_pair(bl, compOperator);
    readOp->op.omap_cmp(assertions, prval);
}

void RadosReadOpStat(rados_op_top, uint64_t *psize, time_t *pmtime, int *prval)
{
    RadosObjectReadOp *readOp = reinterpret_cast<RadosObjectReadOp *>(op);
    readOp->op.stat(psize, pmtime, prval);
}

void RadosReadOpRead(rados_op_t op, uint64_t offset, size_t len, char *buffer,
			size_t *bytesRead, int *prval)
{
    RadosObjectReadOp *readOp = reinterpret_cast<RadosObjectReadOp *>(op);
    readOp->reqCtx.read.buffer = buffer;
    readOp->reqCtx.read.bytesRead = bytesRead;

    readOp->op.read(offset, len, &(readOp->results), prval);
}

void RadosReadOpReadSGL(rados_op_t op, uint64_t offset,size_t len, SGL_S *sgl, int *prval)
{
    RadosObjectReadOp *readOp = reinterpret_cast<RadosObjectReadOp *>(op);
    readOp->reqCtx.readSgl.sgl = sgl;

    readOp->op.read(offset, len, &(readOp->results), prval);
}

void RadosReadOpCheckSum(rados_op_t op, proxy_checksum_type_t type,
			const char *initValue, size_t initValueLen,
			uint64_t offset, size_t len, size_t chunkSize,
			char *pCheckSum, size_t checkSumLen, int *prval)
{
    rados_checksum_type_t  rtype = (rados_checksum_type_t)type;
    RadosObjectReadOp *readOp = reinterpret_cast<RadosObjectReadOp *>(op);
    bufferlist bl;
    bl.append(initValue, initValueLen);
    readOp->reqCtx.checksum.pCheckSum = pCheckSum;
    readOp->reqCtx.checksum.chunkSumLen = checkSumLen;
    readOp->op.checksum(rtype, bl, offset, len, chunkSize, &(readOp->checksums), prval);
}

void RadosReadOpExec(rados_op_t op, const char *cls, const char *method,
			const char *inBuf, size_t inLen, char **outBuf,
			size_t *outLen, int *prval)
{
    RadosObjectReadOp *readOp = reinterpret_cast<RadosObjectReadOp *>(op);
    bufferlist inbl;
    inbl.append(inBuf, inLen);

    readOp->reqCtx.exec.outBuf = outBuf;
    readOp->reqCtx.exec.outLen = outLen;
    readOp->op.exec(cls, method, inbl, &(readOp->execOut),prval);
}

int RadosOperationOperate(rados_op_t op, rados_ioctx_t io)
{
    RadosObjectOperate *rop = reinterpret_cast<RadosObjectOperate *>(op);
    librados::IoCtx *ctx =  reinterpret_cast<librados::IoCtx *>(io);
    int ret = 0;
    switch(rop->opType) {
	case BATCH_READ_OP: {
        RadosObjectReadOp *readOp = dynamic_cast<RadosObjectReadOp *>(rop);
	bufferlist bl;
        ret = ctx->operate(readOp->objectId, &(readOp->op), &bl);
	}
        break;
	case BATCH_WRITE_OP: {
        RadosObjectWriteOp *writeOp = dynamic_cast<RadosobjectWriteOp *>(rop);
        ret = ctx->operate(writeOp->objectId, &(writeOp->op));
        }
	break;
	default:
	break;
    }
    
    return ret;
}

void ReadCallback(librados::completion_t comp, void *arg)
{
    RadosObjectReadOp *readOp = (RadosObjectReadOp *)arg;
    if (readOp_results.length() > 0) {
	if (readOp->reqCtx.read.buffer != nullptr) {   
	memcpy(readOp->reqCtx.read.buffer, readOp->results.c_str(), readOp->results.length());
	} else if (readOp->reqCtx.readSgl.sgl != nullptr) {
	    size_t len = readOp->results.length();
	    uint32_t leftLen = len;
	    int curEntryIndex = 0;
	    uint64_t offset = 0;
	    SGL_S *sgl = readOp->reqCtx.readSgl.sgl;
  
 	    while (leftLen > 0) {
		size_t size = std::min(leftLen, sgl->entrys[curEntryIndex].len);
		bufferlist bl;
		bl.substr_of(readOp->results, offset, size);
		memcpy(sgl->entrys[curEntryIndex].buf, bl.c_str(), size);
		leftLen -= size;
		curEntryIndex++;
		if (curEntryIndex >= ENTRY_PER_SGL) {
		    curEntryIndex = 0;
		    sgl = sgl->nextSgl;
		}

		offset += size;
	    }
	}
    }
    
    if (readOp->reqCtx.xattr.name != nullptr) {
	memcpy(*(readOp->reqCtx.xattr.vals),
		readOp->xattrs[readOp->reqCtx.xattr.name].c_str(),
		readOp->xattrs[readOp->reqCtx.xattr.name].length());
    }
   
    if (readOp->reqCtx.xattrs.iter != nullptr) {
	RadosXattrsIter *iter = static_cast<RadosXattrsIter*>(readOp->reqCtx.xattrs.iter);
	iter->i = iter->attrset.begin();
    }

    if (readOp->reqCtx.omap.iter != nullptr) {
	RadosOmapIter *iter = static_cast<RadosOmapIter*>(readOp->reqCtx.omap.iter);
	iter->i = iter->values.begin();
	if (!iter->keys.empty()) {
	    for (auto i : iter->keys) {
		iter->values[i];
	    }
        }
    }

    if (readOp->reqCtx.checksum.pCheckSum != nullptr) {
	memcpy(readOp->reqCtx.checksum.pCheckSum,
		readOp->checksums.c_str(),
		readOp->reqCtx.checksum.chunkSumLen);
    }

    int ret = rados_aio_get_return_value(comp);
    readOp->callback(ret, readOp->cbArg);
}
void WriteCallback(librados::completion_t comp, void *arg)
{
	RadosObjectWriteOp *writeOp = (RadosObjectWriteOp *)arg;
	int ret = rados_aio_get_return_value(comp);
	writeOp->callback(ret, writeOp->cbArg);
}

int RadosOperationAioOperate( rados_client_t client, rados_op_t op, rados_ioctx_t io, userCallback_t fn, void *cbArg)
{
	librados::Rados *rados = reinterpret_cast<librados::Rados *>(client);
	RadosObjectOperation *rop = reinterpret_cast<RadosObjectOperation *>(op);
	librados::IoCtx *ctx = reinterpret_cast<librados::IoCtx*>(io);
	int ret = 0;
	switch (rop->opType) {
	    case BATCH_READ_OP: {
	    RadosObjectReadOp *readOp = dynamic_cast< RadosObjectReadOp *>(rop);
	    readOp->callback = fn;
	    readOp->cbArg = cbArg;
	   librados::AioCompletion *completion = rados->aio_create_completion(readOp, NULL, ReadCallback);
	    ret = ctx->aio_operate(readOp->objectId, completion, &(readOp->op), &(readOp->bl));
	    if (ret !=0) {
	        std::cerr << "aio_operate failed: " << ret << std::endl;
		}
	    completion->release();
	}
	break;
	case BATCH_WRITE_OP: {
	    RadosObjectWriteOp *writeOp = dynamic_cast<RadosObjectWriteOp *>(rop);
	    writeOp->callback = fn;
	    writeOp->cbArg = cbArg;
	    librados::AioCompletion *completion = rados->aio_create_completion(writeOp, NULL, WriteCallback);

	    ret=ctx->aio_operate(writeOp->objectId, completion, &(writeOp->op));
	    if(ret!=0){
		std::cerr<<"aio_operate failed: "<< ret << std::endl;
	    }
	    completion->release();
	    }
	    break;
	    default:
	    break;
	}
	return ret;
}
	
