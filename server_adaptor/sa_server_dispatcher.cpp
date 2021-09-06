
#include "sa_server_dispatcher.h"
#include "salog.h"
#include "network_module.h"

#include "messages/MPing.h"
#include "messages/MDataPing.h"
#include "messages/MOSDOpReply.h"

using namespace std;

namespace {
const string LOG_TYPE = "SVR_Dispatcher";
}

SaServerDispatcher::SaServerDispatcher( Messenger *msgr, MsgModule *msgModule, NetworkModule *networkModule)
    : Dispatcher(msgr->cct),
      active(false),
      messenger(msgr),
      dcount(0),
      ptrMsgModule(msgModule),
      ptrNetworkModule(networkModule)
{}

SaServerDispatcher::~SaServerDispatcher() {}

bool SaServerDispatcher::ms_dispatch(Message *m) 
{
   uint64_t dc = dcount++;
   ConnectionRef con = m->get_connection();
   switch (m->get_type()) {
       case CEPH_MSG_PING: {
	   if (unlikely(dc % 65536) == 0) {
		struct timespec ts;
		clock_gettime(CLOCK_REALTIME_COARSE, &ts);
		Salog(LV_DEBUG, LOG_TYPE, "CEPH_MSG_PING nanos:%ld", ts.tv_nsec + (ts.tv_sec * 1000000000));
	   }
	   con->send_message(m);
       } break;
       case CEPH_MSG_OSD_OP: {
	    MOSDOp *osdOp = static_cast<MOSDOp *>(m);
	    ptrNetworkModule->EnqueueClientop(osdOp);
	} break;
       default: {
	   Salog(LV_DEBUG, LOG_TYPE, "Server dispatch unknown message type %d", m->get_type());
       }
   }
   return true;
}

bool SaServerDispatcher::ms_handle_reset(Connection *con) 
{
   return true;
}
 
void SaServerDispatcher::ms_handle_remote_reset(Connection *con) {}
