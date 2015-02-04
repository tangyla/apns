cmake_minimum_required (VERSION 2.6)
project (apns)

# 生成编译选项
set (COMPILE_OPTION "-Wall")
if(("${CMAKE_BUILD_TYPE}" STREQUAL "") 
    OR ("${CMAKE_BUILD_TYPE}" STREQUAL "Debug"))
    set(CMAKE_BUILD_TYPE "Debug" CACHE STRING "build version" FORCE)
    set (COMPILE_OPTION "${COMPILE_OPTION} -ggdb3")
else()
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "build version" FORCE)
    set (COMPILE_OPTION "${COMPILE_OPTION} -g -O2")
endif()

# 目标文件输出目录
set (BASEDIR ${CMAKE_SOURCE_DIR})
set (TARGETDIR "${BASEDIR}/${CMAKE_BUILD_TYPE}/")
set (CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${TARGETDIR})
set (CMAKE_RUNTIME_OUTPUT_DIRECTORY ${TARGETDIR})

add_definitions (${COMPILE_OPTION})
add_subdirectory("apns")
add_subdirectory("example")

#add_dependencies("apns" "libapns")
