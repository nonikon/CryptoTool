cmake_minimum_required(VERSION 3.4)
project(CryptoTool LANGUAGES C)

add_executable(CryptoTool WIN32
    mainWindow.c
    symmWindow.c
    digestWindow.c
    randomWindow.c
    common.c
    encode.c
    ini.c
    resource/CryptoTool.manifest
)

target_compile_definitions(CryptoTool PRIVATE
    INI_ALLOW_MULTILINE=0
    INI_MAX_LINE=4096)

target_sources(CryptoTool PRIVATE CryptoTool.rc)

target_link_libraries(CryptoTool libcrypto ComCtl32)

target_include_directories(CryptoTool PRIVATE openssl/include)
target_link_directories(CryptoTool PRIVATE openssl/lib)
