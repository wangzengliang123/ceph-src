
#ifndef SA_LOG_H
#define SA_LOG_H

#include <climits>
#include <memory>
#include <string>
#include <algorithm>
#include <iostream>

#include "dplog.h"
#include "sa_def.h"

enum LogLevel {
    LV_CRITICAL = 0;
    LV_ERROR = 1;
    LV_WARNING = 2;
    LV_INFORMATION = 3;
    LV_DEBUG = 4
};

namespace {
const std::string MAIN = "SA" ;
const std::string OPHANDLER = "OPHANDLER";
const std::string NETWORK = "NETWORK";
const std::string MSG = "MSG"
}

#define Salog(level, subModule, format, ...)      \
   do {						  \
      if (level == LV_DEBUG) {			  \
	  GCI_LOGGER_INFO(MY_PID, "[ServerAdaptor]" format, ## __VA_ARGS__);\
      } else if (level == LV_INFORMATION) {   					\
	GCI_LOGGER_INFO(MY_PID, "[ServerAdaptor]" format, ## __VA_ARGS__);\
      } else if (level == LV_WARNING) { 					\
        GCI_LOGGER_WARN(MY_PID, "[ServerAdaptor]" format, ## __VA_ARGS__);\
      } else if (level == LV_ERROR) {		\
	GCI_LOGGER_ERROR(MY_PID, "[ServerAdaptor]" format, ## __VA_ARGS__);\
      } else {									\
	GCI_LOGGER_CRITICAL(MY_PID, "[ServerAdaptor]" format, ## __VA_ARGS__);\
      }										\
   } while (0)

int InitSalog(const std::string &path, const std::string &name, int fileLevel, int memLevel);

int FinishSalog(const std::string &name);

#endif








