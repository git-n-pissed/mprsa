# Create an INTERFACE library for our C module.
add_library(usermod_mprsa INTERFACE)

# Add our source files to the lib
target_sources(usermod_mprsa INTERFACE
    ${CMAKE_CURRENT_LIST_DIR}/mprsa.c
    ${CMAKE_CURRENT_LIST_DIR}/tfm/tfm_mpi.c
)

# Add the current directory as an include directory.
target_include_directories(usermod_mprsa INTERFACE
    ${CMAKE_CURRENT_LIST_DIR}
)

target_compile_definitions(usermod_mprsa INTERFACE
    MICROPY_PY_MPRSA=1
)

# Link our INTERFACE library to the usermod target.
target_link_libraries(usermod INTERFACE usermod_mprsa)