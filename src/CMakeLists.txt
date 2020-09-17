cmake_minimum_required (VERSION 3.18)
project (Wind)
# 版本号.
set (Wind_VERSION_MAJOR 0)
set (Wind_VERSION_MINOR 1)
#set(CMAKE_BUILD_TYPE debug)
IF(NOT CMAKE_BUILD_TYPE)
  SET(CMAKE_BUILD_TYPE Release)
ENDIF()
MESSAGE("Build type: " ${CMAKE_BUILD_TYPE})

set(LOCAL_SRCS
    buffer.c
    encrypt.c
    rc4.c
    socket_wrap.c
    socks.c
    xor.c
    local.c
)
set(REMOTE_SRCS
    buffer.c
    encrypt.c
    rc4.c
    socket_wrap.c
    socks.c
    xor.c
    remote.c
)
# 编译源码生成目标
add_executable(local ${LOCAL_SRCS})

add_executable(remote ${REMOTE_SRCS})