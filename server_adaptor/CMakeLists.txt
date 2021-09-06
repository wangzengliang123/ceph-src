cmake_minimum_required(VERSION 3.14)

message("Start server adaptor cmake job.")
set(OSA osa)
set(INSTALL_LIBDIR "lib64")
message("OSA COMPILE_FLAGS =${COMPILE_FLAGS}")
set(CMAKE_CXX_FLAGS "${COMPILE_FLAGS}")

if (NOT CEPH_DIR)
    set(CEPH_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../ceph)
endif()
message("CEPH_DIR=${CEPH_DIR}")
find_library(CEPH_COMMON_LIB
  NAMES
  libceph-common.so.0
  PATHS
  ${CEPH_DIR}/build/lib
)
find_library(GLOBAL
  NAMES
  libglobal.a
  PATHS
  ${CEPH_DIR}/build/lib
)
find_library(ERASURE_CODE
  NAMES
  liberasure_code.a
  PATHS
  ${CEPH_DIR}/build/lib
)

aux_source_directory(. SRCS_LIST_OSA)

add_library( ${OSA}
  SHARED
  ${SRCS_LIST_OSA} )

if (NOT GLOBAL_CACHE_DIR)
    set(GLOBAL_CACHE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../../../global_cache)
endif()
message("GLOBAL_CACHE_DIR=${GLOBAL_CACHE_DIR}")

target_include_directories(${OSA}
  PUBLIC
  .
  ${CEPH_DIR}/src
  ${CEPH_DIR}/build/include
  ${GLOBAL_CACHE_DIR}/src/include/infras/infrastructure/conf_parser
  ${GLOBAL_CACHE_DIR}/src/include/infras/
  ${GLOBAL_CACHE_DIR}/src/include/infras/infrastructure/osax
  ${GLOBAL_CACHE_DIR}/src/include/infras/infrastructure/log
  ${GLOBAL_CACHE_DIR}/src/adaptor/sa
)

target_compile_definitions(${OSA} PUBLIC -DCLASS_PATH="${CLASS_PATH}")

target_link_libraries(${OSA}
  ${CEPH_COMMON_LIB}
  ${GLOBAL}
  ${ERASURE_CODE}
)
set_target_properties(
  ${OSA}
  PROPERTIES
  VERSION 1.0.0
  SOVERSION 1
  INSTALL_RPATH "")
install(TARGETS ${OSA} LIBRARY DESTINATION ${INSTALL_LIBDIR})
