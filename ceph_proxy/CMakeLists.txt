
set(lib_rados_include_dir ${CMAKE_CURRENT_SOURCE_DIR}/../../../../ceph/src/include)
set(lib_rados_lib_dir ${CMAKE_CURRENT_SOURCE_DIR}/../../../../ceph/build/lib)

set(ceph_proxy_srcs CephProxyInterface.cc
                    CephProxy.cc
                    CephProxyOp.cc
                    RadosWorker.cc
                    RadosWrapper.cc)

add_library(proxy SHARED ${ceph_proxy_srcs})
target_compile_options(proxy PUBLIC -std=c++17 -g)
target_include_directories(proxy PUBLIC ${lib_rados_include_dir})
target_link_directories(proxy PUBLIC ${lib_rados_lib_dir})
target_link_libraries(proxy PUBLIC -lpthread -lrados)
