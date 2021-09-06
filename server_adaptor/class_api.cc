#include "common/config.h"
#include "common/debug.h"

#include "objclass/objclass.h"
#include "osd/osd_types.h"

#include "osd/ClassHandler.h"
#include "message/MOSDOp.h"

#include "auth/Crypto.h"
#include "common/armor.h"
#include "sa_def.h"
#include "salog.h"

using namespace std;

namespace{
const string LOG_TYPE = "MSG";
}

static constexpr int dout_subsys = ceph_subsys_objclass;

static ClassHandler *ch;
int DoRgwOps(vector<OSDOp> &ops)
{
	assert(0);
	return 0;
}

void cls_initialize(ClassHandler *h)
{
	ch = h;
}

void cls_finalize()
{
	ch = NULL;
}


void *cls_alloc(size_t size)
{
	return malloc(size);
}

void cls_free(void *p)
{
	free(p);
}

int cls_register(const char *name, cls_handler_t *handle)
{
	ClassHandler::ClassData *cls = ch->refister_class(name);
	*handle = (cls_handle_t)cls;
	return (cls != NULL);
}

int cls_unregister(cls_handle_t handle)
{
	ClassHandler::ClassData *cls = (ClassHandler::ClassData *)handle;
	ch->unregister_class(cls);
	return 1;
}

int cls_register_method(cls_handle_t hclass, const char *method, int flags, cls_method_call_t class_call,
	cls_method_handle_t *handle)
{
	if(!(flags & (CLS_METHOD_RD | CLS_METHOD_WR)))
		return -EINVAL;
	ClassHandler::ClassData *cls = (ClassHandler::ClassData *)hclass;
	cls_method_handle_t hmethod = (cls_method_handle_t)cls->register_method(method, flags, class_call);
	if(handle)
		*handle = hmethod;
	return (hmethod != NULL);
}

int cls_register_cxx_method(cls_handle_t hclass, const char *method, int flags, cls_method_cxx_call_t class_call,
	cls_method_handle_t *handle)
{
	ClassHandler::ClassData *cls = (ClassHandler::ClassData *)hclass;
	cls_method_handle_t hmethod = (cls_method_handle_t)cls->register_cxx_method(method, flags, class_call);
	if(handle)
		*handle = method;
	return (hmethod != NULL);
}

int cls_unregister_method(cls_method_handle_t handle)
{
	ClassHandler::ClassMethod *method = (ClassHandler::ClassMethod *)handle;
	method->unregister();
	return 1;
}

int cls_register_cxx_filter(cls_handle_t hclass, const std::string &filter_name, cls_cxx_filter_factory_t fn,
	clscls_filter_handle_t *handle)
{
	ClassHandler::ClassData *cls = (ClassHandler::ClassData *)hclass;
	cls_filter_handle_t hfilter = (cls_filter_handle_t)cls->register_cxx_filter(filter_name, fn);
	if(handle){
		*handle = hfilter;
	}
	return (hfilter != NULL);
}

void cls_unregister_filter(cls_filter_handle_t handle)
{
	ClassHandler::ClassFilter *filter = (ClassHandler::ClassFilter *)handle;
	filter->unregister();
}

int cls_call(cls_method_context_t hctx, const char *cls, const char *method, char *indata, int datalen, char *outdata,
	int *outdatalen)
{
	bufferlist idata;
	vector<OSDOp> nops(1);
	OSDOp &op = nops[0];
	int r;

	op.op.op = CEPH_OSD_OP_CALL;
	op.op.cls.class_len = strlen(cls);
	op.op.cls_method_len = strlen(method);
	op.op.cls.indata_len = datalen;
	op.indata.append(cls, op.op.cls.class_len);
	op.indata.append(method, op.op.cls.method_len);
	op.indata.append(indata, datalen);
	r = DoRgwOps(nops);
	if (r < 0)
		return r;
	
	*outdata = (char *)malloc(op.outdata.length());
	if(!*outdata)
		return -ENOMEM;
	memcpy(*outdata, op.outdata.c_str(), op.outdata.length());
	*outdatalen = op.outdata.length();

	return r;
}

int cls_getxattr(cls_method_context_t hctx, const char *name, char **outdata, int *outdatalen)
{
	bufferlist name_data;
	vector<OSDOp> nops(1);
	OSDOp *op = nops[0];
	int r;

	op.op.op = CPEH_OSD_OP_GETXATTR;
	op.op.xattr.name_len = strlen(name);
	op.indata.append(name, op.op.xattr.name_len);
	r = DoRgwOps(nops);
	if(r < 0)
		return r;

	*outdata = (char *)malloc(op.outdata.length());
	if(!*outdata)
		return -ENOMEM;
	memcpy(*outdata, op.outdata.c_str(), op.outdata.length());
	*outdatalen = op.outdata.length();

	return r;
}

int cls_setxattr(cls_method_context_t hctx, const char *name, const char *value, int val_len)
{
	SaOpContext *pctx = reinterpret_cast<SaOpContext *>(hctx);
	SaOpReq *pOpReq = pctx->opReq;
	SaOpReq opreq = *pOpReq;
	MOSDOp *ptr = reinterpret_cast<MOSDOp *>(pOpReq->ptrMosdop);
	opRequestOps op;
	int r;

	op.op.op = CPEH_OSD_OP_SETXATTR;
	op.objName = ptr->get_oid().name;
	op.keys.push_back(string(name));
	op.values.push_back(string(value, val_len));

	vector<OSDOp> ops(1);
	ops.swap(ptr->ops);
	opreq.vecOps.clear();
	opreq.vecOps.push_back(op);
	r = pctx->cb_func(&opreq);
	ops.swap(ptr->ops);
	return r;	
}

int cls_read(cls_method_context_t hctx, int ofs, int lenm char **outdata, int *outdatalen)
{
	vector<OSDOp> ops(1);
	ops[0].op.op = CEPH_OSD_OP_SYNC_READ;
	ops[0].op.extent.offset = ofs;
	ops[0].op.extent.length = len;
	int r = DoRgwOps(ops);
	if(r < 0)
		return r;
	
	*outdata = (char *)malloc(ops[0].outdata.length());
	if(!*outdata)
		return -ENOMEM;
	memcpy(*outdata, ops[0].outdata.c_str(), ops[0].outdata.length());
	*outdatalen = ops[0].outdata.lenght();

	return *outdatalen;
}

int cls_get_request_origin(cls_method_context_t hctx, entity_inst_t *origin)
{
	SaOpContext *pctx = reinterpret_cast<SaOpContext *>(hctx);
	SaOpReq *pOpReq = pctx->opReq;
	SaOpReq opreq = *pOpReq;
	MOSDOp *ptr = reinterpret_cast<MOSDOp *>(pOpReq->ptrMosdop);

	*origin = ptr->get_orig_source_inst();
	return 0;
}

uint64_t cls_get_features(cls_method_context_t hctx)
{
	return CEPH_FEATURE_CRUSH_TUNABLES | CEPH_FEATURE_CRUSH_TUNABLES2 | CEPH_FEATURE_CRUSH_TUNABLES3 |
		CEPH_FEATURE_CRUSH_V2 | CEPH_FEATURE_OSDHASHPSPOOL | CEPH_FEATURE_OSD_PRIMARY_AFFINITY;
}

uint64_t cls_get_client_features(cls_method_context_t hctx)
{
	SaOpContext *pctx = reinterpret_cast<SaOpContext *>(hctx);
	SaOpReq *pOpReq = pctx->opReq;
	SaOpReq opreq = *pOpReq;
	MOSDOp *ptr = reinterpret_cast<MOSDOp *>(pOpReq->ptrMosdop);

	return ptr->get_connection()->get_features();
}

int cls_cxx_create(cls_method_context_t hctx, bool exclusive)
{
	vector<OSDOp> ops(1);
	ops[0].op.op = CPEH_OP_CREATE;
	ops[0].op.flags = (exclusive ? CEPH_OSD_OP_FLAG_EXCL : 0);
	return DoRgwOps(ops);
}

int cls_cxx_remove(cls_method_context_t hctx)
{
	SaOpContext *pctx = reinterpret_cast<SaOpContext *>(hctx);
	SaOpReq *pOpReq = pctx->opReq;
	MOSDOp *ptr = reinterpret_cast<MOSDOp *>(pOpReq->ptrMosdop);
	SaOpReq opreq = *pOpReq;
	OpRequestOps op;
	op.opSubType = CEPH_OSD_OP_DELETE;
	op.objName = ptr->get_oid().name;

	opreq.vecOps.clear();
	opreq.vecOps.push_back(op);
	return pctx->cb_func(&opreq);
}

int cls_cxx_stat(cls_method_context_t hctx, uint64_t *size, time_t *mtime)
{
	vector<OSDOp> ops(1);
	int ret;
	ops[0].op.op = CEPH_OSD_OP_STAT;
	ret = DoRgwOps(ops);
	if(ret < 0)
		return ret;
	auto iter = ops[0].outdata.cbegin();
	utime_t ut;
	uint64_t s;
	try{
		decode(s, iter);
		decode(ut, iter);
	}catch (buffer::error &err){
		return -EIO;
	}
	if(size)
		*size = s;
	if(mtime)
		*mtime = ut.sec();
	return 0;
}

int cls_cxx_stat2(cls_method_context_t hctx, uint64_t *size, ceph::real_time *mtime)
{
	vector<OSDOp> ops(1);
	int ret;
	ops[0].op.op = CEPH_OSD_OP_STAT;
	ret = DoRgwOps(ops);
	if(ret < 0)
		return ret;
	auto iter = ops[0].outdata.cbegin();
	real_time ut;
	uint64_t s;
	try{
		decode(s, iter);
		decode(ut, iter);
	}catch (buffer::error &err){
		return -EIO;
	}
	if(size)
		*size = s;
	if(mtime)
		*mtime = ut;
	return 0;
}

int cls_cxx_read(cls_method_context_t hctx, int ofs, int len, bufferlist *outbl)
{
	return cls_cxx_read2(hctx, ofs, len, outbl, 0);
}

int cls_cxx_read2(cls_method_context_t hctx, int ofs, int len, bufferlist *outbl, uint32_t op_flags)
{
	vector<OSDOp> ops(1);
	int ret;
	ops[0].op.op = CEPH_OSD_OP_SYNC_READ;
	ops[0].op.extent.offest = ofs;
	ops[0].op.extent.length = len;
	ops[0].op.flags = op_flags;
	ret = DoRgwOps(ops);
	if(ret < 0)
		return ret;
	outbl->claim(ops[0].outdata);
	return oubl->length();
}

int cls_cxx_write(cls_method_context_t hctx, int ofs, int len, bufferlist *inbl)
{
	return cls_cxx_write2(hctx, ofs, len, inbl, 0);
}

int cls_cxx_write2(cls_method_context_t hctx, int ofs, int len, bufferlist *outbl, uint32_t op_flags)
{
	vector<OSDOp> ops(1);
	ops[0].op.op = CEPH_OSD_OP_SYNC_WRITE;
	ops[0].op.extent.offest = ofs;
	ops[0].op.extent.length = len;
	ops[0].op.flags = op_flags;
	ops[0].indata = *inbl;
	return DoRgwOps(ops);
}

int cls_cxx_write_full(cls_method_context_t hctx, bufferlist *inbl)
{
	vector<OSDOp> ops(1);
	ops[0].op.op = CEPH_OSD_OP_WRITEFULL;
	ops[0].op.extent.offest = 0;
	ops[0].op.extent.lenght = inbl->length();
	ops[0].indata = *inbl;
	return DoRgwOps(ops);		
}

int cls_cxx_replace(cls_method_context_t hctx, int ofs, int len, bufferlist *inbl)
{
	vector<OSDOp> ops(2);
	ops[0].op.op = CEPH_OSD_OP_TRUNCATE;
	ops[0].op.extent.offest = 0;
	ops[0].op.extent.lenght = 0;
	ops[0].op.op = CEPH_OSD_OP_WRUTE;
	ops[0].op.extent.offest = 0;	
	ops[0].op.extent.lenght = 0;
	ops[0].indata = *inbl;
	return DoRgwOps(ops);			
}

int cls_cxx_getxattr(cls_method_context_t hctx, const char *name, bufferlist *outbl)
{
	SaOpContext *pctx = reinterpret_cast<SaOpContext *>(hctx);
	SaOpReq *pOpReq = pctx->opReq;
	SaOpReq opreq = *pOpReq;
	MOSDOp *ptr = reinterpret_cast<MOSDOp *>(pOpReq->ptrMosdop);
	OpRequestOps op;
	int r;

	op.opSubType = CEPH_OSD_OP_GETXATTR;
	op.objName = ptr->get_oid().name;
	op.keys.push_back(string(name));

	vector<OSDOp> ops(1);
	ops.swap(ptr->ops);
	opreq.vecOps.clear();
	opreq.vecOps.push_back(op);
	r = pctx->cb_func(&opreq);
	ops.swap(ptr->ops);
	if(r < 0)
		return r;

	outbl->claim(ops[0].outdata);
	return outbl->length();
}

int cls_cxx_getxattrs(cls_method_context_t hctx, map<string, bufferlist> *attrset)
{
	SaOpContext *pctx = reinterpret_cast<SaOpContext *>(hctx);
	SaOpReq *pOpReq = pctx->opReq;
	SaOpReq opreq = *pOpReq;
	MOSDOp *ptr = reinterpret_cast<MOSDOp *>(pOpReq->ptrMosdop);
	OpRequestOps op;
	int r;

	op.opSubType = CEPH_OSD_OP_GETXATTRS;
	op.objName = ptr->get_oid().name;

	vector<OSDOp> ops(1);
	ops.swap(ptr->ops);
	opreq.vecOps.clear();
	opreq.vecOps.push_back(op);
	r = pctx->cb_func(&opreq);
	ops.swap(ptr->ops);
	if( r < 0)
		return r;

	auto iter = ops[0].outdata.cbegin();
	try{
		decode(*attrset, uter);
	}catch (buffer::error &err){
		return -EIO;
	}
	return 0;	
}

int cls_cxx_setxattr(cls_method_context_t hctx, const char *name, bufferlist *inbl)
{
	SaOpContext *pctx = reinterpret_cast<SaOpContext *>(hctx);
	SaOpReq *pOpReq = pctx->opReq;
	SaOpReq opreq = *pOpReq;
	MOSDOp *ptr = reinterpret_cast<MOSDOp *>(pOpReq->ptrMosdop);
	OpRequestOps op;
	int r;
	
	op.opSubType = CEPH_OSD_OP_SETXATTR;
	op.objName = ptr->get_oid().name;
	op.keys.push_back(string(name));
	string val;
	auto bp = inbl->cbegin();
	bp.copy(inbl->cbegin(), val);
	op.values.push_back(val);

	vector<OSDOp> ops(1);
	ops.swap(ptr->ops);
	opreq.vecOps.clear();
	opreq.vecOps.push_back(op);
	r = pctx->cb_func(&opreq);
	ops.swap(ptr->ops);
	return r;
}

int cls_cxx_snap_revert(cls_method_context_t hctx, snapid_t snapid)
{
	vector<OSDOp> ops(1);
	ops[0].op.op = CEPH_OSD_OP_ROLLBACK;
	ops[0].op.snap.snapid = snapid;
	return DoRgwOps(ops);	
}

int cls_cxx_map_get_all_vals(cls_method_context_t hctx, map<string, bufferlist> *vals, bool *more)
{
	SaOpContext *pctx = reinterpret_cast<SaOpContext *>(hctx);
	SaOpReq *pOpReq = pctx->opReq;
	SaOpReq opreq = *pOpReq;
	MOSDOp *ptr = reinterpret_cast<MOSDOp *>(pOpReq->ptrMosdop);
	OpRequestOps op;
	int r;
	uint64_t max_to_get = -1;
	op.opSubType = CEPH_OSD_OP_OMAPGETVALS;
	op.objName = ptr->get_oid().name;
	op.keys.push_back("start_after");
	op.values.push_back(string(""));

	op.keys.push_back("max_return");
	op.values.push_back(to_string(max_to_get));

	op.keys.push_back("filter_prefix");
	op.values.push_back(string(""));

	vector<OSDOp> ops(1);
	ops.swap(ptr->ops);
	opreq.vecOps.clear();
	opreq.vecOps.push_back(op);
	r = pctx->cb_func(&opreq);
	ops.swap(ptr->ops);
	if( r < 0)
		return r;

	auto iter = ops[0].outdata.cbegin();
	try{
		decode(*vals, iter);
		decode(*more, iter);
	}catch (buffer::error &err){
		return -EIO;
	}
	return vals->size();		
}

int cls_cxx_map_get_keys(cls_method_context_t hctx, const string &start_obj, uint64_t max_to_get, set<string> *keys,
	bool *more)
{
	vector<OSDOp> ops(1);
	OSDOp &op = ops[0];
	int ret;

	encode(start_obj, op.indata);
	encode(max_to_get, op.indata);

	op.op.op = CEPH_OSD_OP_OMAPGETKEYS;

	ret = DoRgwOps(ops);
	if( r < 0)
		return r;

	auto iter = ops[0].outdata.cbegin();
	try{
		decode(*keys, iter);
		decode(*more, iter);
	}catch (buffer::error &err){
		return -EIO;
	}
	return vals->size();			
}

int cls_cxx_map_get_vals(cls_method_context_t hctx, const string &start_obj, const string &filter_prefix, 
	uint64_t max_to_get, map<string, bufferlist> *vals, bool *more)
{
	SaOpContext *pctx = reinterpret_cast<SaOpContext *>(hctx);
	SaOpReq *pOpReq = pctx->opReq;
	SaOpReq opreq = *pOpReq;
	MOSDOp *ptr = reinterpret_cast<MOSDOp *>(pOpReq->ptrMosdop);
	OpRequestOps op;
	int r;
	
	op.opSubType = CEPH_OSD_OP_OMAPGETVALS;
	op.objName = ptr->get_oid().name;
	op.keys.push_back("start_after");
	op.values.push_back(start_obj);

	op.keys.push_back("max_return");
	op.values.push_back(to_string(max_to_get));

	op.keys.push_back("filter_prefix");
	op.values.push_back(filter_prefix);
	
	vector<OSDOp> ops(1);
	ops.swap(ptr->ops);
	opreq.vecOps.clear();
	opreq.vecOps.push_back(op);
	r = pctx->cb_func(&opreq);
	ops.swap(ptr->ops);
	if( r < 0)
		return r;

	auto iter = ops[0].outdata.cbegin();
	try{
		decode(*vals, iter);
		decode(*more, iter);
	}catch (buffer::error &err){
		return -EIO;
	}
	return vals->size();		
}

int cls_cxx_map_read_header(cls_method_context_t hctx, bufferlist *outbl)
{
	vector<OSDOp> ops(1);
	OSDOp &op = ops[0];
	int ret;
	op.op.op = CEPH_OSD_OP_OMAPGETHEADER;
	ret = DoRgwOps(ops);
	if(ret < 0)
		return ret;

	outbl->claim(op.outdata);

	return 0;	
}

int cls_cxx_map_get_val(cls_method_context_t hctx, const string &key, bufferlist *outbl)
{
	vector<OSDOp> ops(1);
	OSDOp &op = ops[0];
	int ret;

	set<string> k;
	k.insert(key);
	encode(k, op.indata);

	op.op.op = CEPH_OSD_OP_OMAPGETVALSBYKEYS;
	ret = DoRgwOps(ops);
	if(ret < 0)
		return ret;

	auto iter = ops[0].outdata.cbegin();
	try{
		map<string, bufferlist> m;
		decode(m, iter);
		map<string, bufferlist>::iterator iter = m.begin();
		if(iter == m.end())
			return -ENOENT;

		*outbl = iter->second;
	}catch (buffer::error &e){
		return -EIO;
	}
	return 0;					
}

int cls_cxx_map_set_val(cls_method_context_t hctx, const string &key, bufferlist *outbl)
{
	SaOpContext *pctx = reinterpret_cast<SaOpContext *>(hctx);
	SaOpReq *pOpReq = pctx->opReq;
	SaOpReq opreq = *pOpReq;
	MOSDOp *ptr = reinterpret_cast<MOSDOp *>(pOpReq->ptrMosdop);
	OpRequestOps op;
	int r;	
	op.opSubType = CEPH_OSD_OP_OMAPSETVALS;
	op.objName = ptr->get_oid().name;
	op.keys.push_back(key);
	string val;
	auto bp = inbl->cbegin();
	bp.copy(inbl->length(), val);
	op.values.push_back(val);
	
	vector<OSDOp> ops(1);
	ops.swap(ptr->ops);
	opreq.vecOps.clear();
	opreq.vecOps.push_back(op);
	r = pctx->cb_func(&opreq);
	ops.swap(ptr->ops);
	return r;	
}

int cls_cxx_map_set_vals(cls_method_context_t hctx, const std::map<string, bufferlist> *map)
{
	vector<OSDOp> ops(1);
	OSDOp &op = ops[0];
	bufferlist &update_bl = op.indata;
	encode(*map, update_bl);
	
	op.op.op = CEPH_OSD_OP_OMAPSETVALS;
	
	return DoRgwOps(ops);	
}

int cls_cxx_map_clear(cls_method_context_t hctx)
{
	vector<OSDOp> ops(1);
	OSDOp &op = ops[0];
	
	op.op.op = CEPH_OSD_OP_OMAPCLEAR;

	return DoRgwOps(ops);
}

int cls_cxx_map_write_header(cls_method_context_t hctx, bufferlist *inbl)
{
	vector<OSDOp> ops(1);
	OSDOp &op = ops[0];
	op.indata.claim(*inbl);	
	
	op.op.op = CEPH_OSD_OP_OMAPSETHEADER;

	return DoRgwOps(ops);
}

int cls_cxx_map_remove_key(cls_method_context_t hctx, const string &key)
{
	vector<OSDOp> ops(1);
	OSDOp &op = ops[0];
	bufferlist &updata_bl = op.indata;
	set<string> to_rm;
	to_rm.insert(key);

	encode(to_rm, updata_bl);

	op.op.op = CEPH_OSD_OP_OMAPRMKEYS;

	return DoRgwOps(ops);
}

int cls_cxx_list_watchers(cls_method_context_t hctx, obj_list_watch_response_t *watchers)
{
	vector<OSDOp> ops(1);
	OSDOp &op = ops[0];
	int r;

	op.op.op = CEPH_OSD_OP_LIST_WATCHERS;
	r = DoRgwOps(nops);
	if(r < 0)
		return r;

	auto iter = ops.outdata.cbegin();
	try{
		decode(*watchers, iter);
	}catch (buffer::error &err){
		return -EIO;
	}
	return 0;					
}

int cls_gen_random_byes(char *buf, int size)
{
	ch->cct->random()->get_bytes(buf, size);
	return 0;
}

int cls_gen_rand_base64(char *dest, int size)
{
	char buf[size];
	char tmp_dest[size + 4];
	int ret;

	ret = cls_gen_random_bytes(buf, sizeof(buf));
	if(ret < 0){
		lgeneric_derr(ch->cct) << "cannot get random bytes: " << ret << dendl;
		return -1;
	}

	ret = ceph_armor(tmp_dest, &tmp_dest[sizeof(tmp_dest)],(const char *)buf,
		((const char *)buf) + ((size - 1) * 3 + 4 - 1) / 4);
	if(ret <0){
		lgeneric_derr(ch->cct) << "ceph_armor failed" << dendl;
		return -1;
	}
	tmp_dest[ret] = '\0';
	memcpy(dest, tmp_dest, size);
	dest[size - 1] = '\0';

	return 0;
}

uint64_t cls_current_version(cls_method_context_t hctx)
{
	return 0;
}

int cls_current_subop_ num(cls_method_context_t hctx)
{
	return 0;
}

int cls_log(int level, const char *format, ...)
{
	int size = 256;
	va_list ap;
	while(1){
		char buf[size];
		va_start(ap, format);
		int n = vsnprintf(buf, size, format, ap);
		va_end(ap);
#define MAX_SIZE 8196
		if((n > -1 && n < size) || size > MAX_SIZE){
			Salog(level, LOG_TYPE, "%s", buf);
			return n;
		}
		size *=2;
	}
}

int cls_cxx_chunk_write_and_set(cls_method_context_t hctx, int ofs, int len, bufferlist *write_inbl, uint32_t op_flags,
	bufferlist *set_inbl, int set_len)
{
	char cname[] = "cas";
	char method[] = "chumk_set";

	vector<OSDOp> ops(2);
	ops[0].op.op = CEPH_OSD_OP_WRITE;
	ops[0].op.extent.offset = ofs;
	ops[0].op.extent.length = len;
	ops[0].op.flags = op_flags;
	ops[0].indata = *write_inbl;

	ops[1].op.op = CEPH_OSD_OP_CALL;
	ops[1].op.cls.class_len = strlen(cname);
	ops[1].op.cls.method_len = strlen(method);
	ops[1].cls.indata_len = set_len;
	ops[1].indata.append(cname, ops[1].op.cls.class_len);
	ops[1].indata.append(method, ops[1].op.cls.method_len);
	ops[1].indata.append(*set_inbl);

	return DoRgwOps(ops);	
}
