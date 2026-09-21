cmake_minimum_required(VERSION 3.22)
project(stas_crypto)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_compile_options(
  -Wall -Wextra -Wpedantic
  -fsanitize=address -fsanitize=undefined -fPIE
)

add_link_options(
  -fsanitize=address -fsanitize=undefined -fPIE
)

add_executable(${PROJECT_NAME}
    ${PROJECT_SOURCE_DIR}/main.c

    ${PROJECT_SOURCE_DIR}/src/stas_common.c
    ${PROJECT_SOURCE_DIR}/src/stas_sha256.c
    ${PROJECT_SOURCE_DIR}/src/stas_hmac.c
    ${PROJECT_SOURCE_DIR}/src/stas_hmac_drbg.c
    ${PROJECT_SOURCE_DIR}/src/stas_ifc_keygen.c
)

target_include_directories(${PROJECT_NAME} PRIVATE inc)
target_link_libraries(${PROJECT_NAME} -lgmp)
