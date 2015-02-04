# 加入源代码、设定编译所需选项
aux_source_directory (${CMAKE_CURRENT_SOURCE_DIR} SRCS)
include_directories ("${CMAKE_SOURCE_DIR}")

# 设置链接选项
set(LIBS "apns" "ssl")
link_directories ("/usr/lib64"
                  "${CMAKE_ARCHIVE_OUTPUT_DIRECTORY}")

# 生成目标
set (MODULENMAE "example")
add_executable (${MODULENMAE} ${SRCS})
target_link_libraries(${MODULENMAE} ${LIBS})
