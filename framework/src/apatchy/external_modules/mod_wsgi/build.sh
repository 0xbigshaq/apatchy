#!/usr/bin/env bash
#
# Build mod_wsgi as a shared object for the apatchy fuzzing harness.
#
# Environment variables (set by ModuleManager):
#   HTTPD_ROOT       - path to the Apache HTTPD source tree
#   CC               - C compiler to use
#   SANITIZER_FLAGS  - -fsanitize flags to propagate
#   OUTPUT_DIR       - directory to place the built .so
#   MODULE_DIR       - path to this wrapper directory
#
set -euo pipefail

VERSION="5.0.2"
REPO_URL="https://github.com/GrahamDumpleton/mod_wsgi.git"
SRC_DIR="${MODULE_DIR}/mod_wsgi-${VERSION}"

if [ ! -d "$SRC_DIR" ]; then
    echo "[*] Cloning mod_wsgi ${VERSION} ..."
    git clone --branch "${VERSION}" --depth 1 "$REPO_URL" "$SRC_DIR"
fi

PYTHON_INCLUDES=$(python3-config --includes)
PYTHON_LDFLAGS=$(python3-config --ldflags --embed 2>/dev/null || python3-config --ldflags)

HTTPD_INCLUDES=(
    "-I${HTTPD_ROOT}/include"
    "-I${HTTPD_ROOT}/srclib/apr/include"
    "-I${HTTPD_ROOT}/srclib/apr-util/include"
    "-I${HTTPD_ROOT}/os/unix"
    "-I${HTTPD_ROOT}/server"
)

# Add Apache module subdirectories as includes
if [ -d "${HTTPD_ROOT}/modules" ]; then
    for d in "${HTTPD_ROOT}/modules"/*/; do
        HTTPD_INCLUDES+=("-I${d}")
    done
fi

SERVER_DIR="${SRC_DIR}/src/server"
SOURCES=("${SERVER_DIR}"/*.c)

OBJ_DIR="${MODULE_DIR}/.build"
mkdir -p "$OBJ_DIR"

echo "[*] Compiling $(echo ${#SOURCES[@]}) source files ..."
OBJECTS=()
for src in "${SOURCES[@]}"; do
    obj="${OBJ_DIR}/$(basename "${src}" .c).o"
    $CC -fPIC -g -O0 \
        $SANITIZER_FLAGS \
        ${HTTPD_INCLUDES[@]} \
        $PYTHON_INCLUDES \
        -I"${SERVER_DIR}" \
        -DNDEBUG \
        -c "$src" \
        -o "$obj"
    OBJECTS+=("$obj")
done

echo "[*] Linking mod_wsgi.so ..."
$CC -fPIC -shared \
    $SANITIZER_FLAGS \
    "${OBJECTS[@]}" \
    $PYTHON_LDFLAGS \
    -o "${OUTPUT_DIR}/mod_wsgi.so"

echo "[+] Done"
