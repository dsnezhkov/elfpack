cmake_minimum_required(VERSION 3.21)
project(elfpack)

set(CMAKE_CXX_STANDARD 17)
set(ELFPACK_EXE elfpack )
set(ELFLDR_EXE elfldr )
set(ELFPACK_SRC ${PROJECT_SOURCE_DIR}/src )

add_library(lsecutil STATIC ${ELFPACK_SRC}/lsecutil/lsecutil.c)
link_libraries(lsecutil)

include_directories(${ELFPACK_SRC}/include)
include_directories(${ELFPACK_SRC})
include_directories(${PROJECT_SOURCE_DIR}/vendor/include)

target_link_libraries(lsecutil)
add_executable(${ELFPACK_EXE} ${ELFPACK_SRC}/elfpack.cpp src/elfioutil.cpp)
add_executable(${ELFLDR_EXE} ${ELFPACK_SRC}/elfldr.cpp src/elfioutil.cpp)

set_target_properties(${ELFPACK_EXE} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY_DEBUG  ${PROJECT_SOURCE_DIR}/bin/${CMAKE_BUILD_TYPE}
        RUNTIME_OUTPUT_DIRECTORY_RELEASE ${PROJECT_SOURCE_DIR}/bin/${CMAKE_BUILD_TYPE}
        )
set_target_properties(${ELFLDR_EXE} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY_DEBUG  ${PROJECT_SOURCE_DIR}/bin/${CMAKE_BUILD_TYPE}
        RUNTIME_OUTPUT_DIRECTORY_RELEASE ${PROJECT_SOURCE_DIR}/bin/${CMAKE_BUILD_TYPE}
        )
