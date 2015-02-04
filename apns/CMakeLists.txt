# 加入源代码、设定编译所需选项
aux_source_directory (${CMAKE_CURRENT_SOURCE_DIR} SRCS)

# 生成目标
set (MODULENMAE "apns")
add_library(${MODULENMAE} STATIC ${SRCS})
