#ifndef CLIENT_OP_QUEUE_H
#define CLIENT_OP_QUEUE_H
#include <queue>
#include <mutex>
#include <condition_variable>
#include <message/MOSDOp.h>

class ClientOpQueue {
public:
    ClientOpQueue() {};
    ~ClientOpQueue() {};

    std::mutex opQueueMutex;
    std::queue<MOSDOp *> reqQueue;
    void EnQueue(MOSDOp *opReq)
    {
        reqQueue.push(opReq);
        condOpReq.notify_all();
    }
    void Dequeue();
    bool Empty()
    {
        return reqQueue.empty();
    }

    std::condition_variable condOpReq;
};
#endif

