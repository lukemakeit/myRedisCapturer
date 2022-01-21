cmake_minimum_required(VERSION 3.13.0)
project (myRedisCapture)


set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -O0 -lpcap ")

find_path(GLOG_HEADER glog
	HINTS src/thirdparty/glog/src
)
message("GLOG_HEADER = ${GLOG_HEADER}")


SET(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
add_subdirectory(src/thirdparty/glog glog EXCLUDE_FROM_ALL)

file(GLOB SOURCE "src/capture/*.cpp")

add_executable(myRedisCapture ${SOURCE})
set_target_properties(myRedisCapture PROPERTIES LINK_FLAGS "-static-libgcc -static-libstdc++")
target_include_directories(myRedisCapture PUBLIC ${GLOG_HEADER})

target_link_libraries(myRedisCapture glog)