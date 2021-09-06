/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description:Process many message.
 */
#ifndef MSG_MODULE_H
#define MSG_MODULE_H

#include <queue>
#include <mutex>

#include <messages/MOSDOp.h>
#include "osd/ClassHandler.h"

#include "sa_def.h"

using MSG_UNIQUE_LOCK = std::unique_lock<std::mutex>;

class MsgModule {
    std::queue<MOSDOp *> qClientopStore {};
    std::condition_variable condConvert {};

    std::queue<MOSDOpReply *> qReplyopStore {};
    std::condition_variable condSendToClient {};

    void ConvertObjRw(OSDOp &clientop, OpRequestOps &oneOp);
    void ConvertOmapOp(OSDOp &clientop, OpRequestOps &oneOp);
    void ConvertAttrOp(OSDOp &clientop, OpRequestOps &oneOp);

public:
    std::mutex clientopQueueMutex {};
    std::mutex replyopQueueMutex {};

    MsgModule() {}
    ~MsgModule() {}

    int ConvertClientopToOpreq(OSDOp &clientop, OpRequestOps &oneOp);

    void WaitSend(MSG_UNIQUE_LOCK &lock);
    void NotifySend();
};

#endif

