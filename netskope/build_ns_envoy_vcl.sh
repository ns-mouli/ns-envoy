#!/bin/bash
# Build minimal Envoy-VCL from ns-envoy repo with Qosmos DPI filter.
# Depends on: vpp23 (dynamic VCL libs at /opt/vpp23), ixe-sdk (Qosmos SDK at /opt/3p/binary/ixe), clang-18.
# Produces: /opt/envoy-vcl/bin/envoy (stripped ~184MB) + optional tarball
#
# Environment variables:
#   QOSMOS_LICENSE_PATH  — path to Qosmos license .bin file (default: /opt/3p/binary/ixe/license.bin)
#   ENVOY_PACKAGE_DIR    — if set, also create envoy-binary.tar.gz here for Artifactory upload
#
# Build time: ~2.5 hours (clean), ~30 min (cached deps)

set -eu

destination=/opt/envoy-vcl
wd=$(pwd)
QOSMOS_LICENSE_PATH="${QOSMOS_LICENSE_PATH:-/opt/3p/binary/ixe/license.bin}"

# --- 0. Install CI prerequisites (no-op if already present) ---
if ! command -v python3 &> /dev/null; then
    echo "[ns-envoy-vcl] Installing python3 ..."
    apt-get update -qq && apt-get install -qqy python3
fi
if ! command -v clang-18 &> /dev/null; then
    echo "[ns-envoy-vcl] Installing clang-18 ..."
    if ! apt-cache show clang-18 2>/dev/null | grep -q "^Package: clang-18"; then
        wget -qO- https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add - 2>/dev/null || true
        add-apt-repository -y "deb http://apt.llvm.org/focal/ llvm-toolchain-focal-18 main" 2>/dev/null || true
        apt-get update -qq
    fi
    apt-get install -qqy clang-18 lld-18 2>/dev/null || true
fi
if command -v clang-18 &> /dev/null; then
    sudo ln -sf $(which clang-18) /usr/local/bin/clang 2>/dev/null || ln -sf $(which clang-18) /usr/local/bin/clang 2>/dev/null || true
    sudo ln -sf $(which clang++-18) /usr/local/bin/clang++ 2>/dev/null || ln -sf $(which clang++-18) /usr/local/bin/clang++ 2>/dev/null || true
fi
if ! command -v ld.lld &> /dev/null; then
    echo "[ns-envoy-vcl] Installing lld ..."
    apt-get install -qqy lld 2>/dev/null || true
fi

# --- 1. Prepare Qosmos SDK (symbol localization) ---
QOSMOS_LOCAL=/tmp/qosmos_sdk_local
rm -rf $QOSMOS_LOCAL
mkdir -p $QOSMOS_LOCAL/lib $QOSMOS_LOCAL/include
cp -r /opt/3p/binary/ixe/include/* $QOSMOS_LOCAL/include/
cp /opt/3p/binary/ixe/lib/libqmengine.fpic.a $QOSMOS_LOCAL/lib/
cp /opt/3p/binary/ixe/lib/libqmbundle.fpic.a $QOSMOS_LOCAL/lib/
objcopy --localize-symbol=huff_sym_table \
        --localize-symbol=huff_decode_table \
        $QOSMOS_LOCAL/lib/libqmbundle.fpic.a

# Apply Qosmos license patch to libqmengine.fpic.a
if [ -f "$QOSMOS_LICENSE_PATH" ]; then
    echo "[ns-envoy-vcl] Applying Qosmos license patch from $QOSMOS_LICENSE_PATH ..."
    perl /opt/3p/binary/ixe/src/tools/license_patcher/license_patcher.pl \
        "$QOSMOS_LICENSE_PATH" \
        $QOSMOS_LOCAL/lib/libqmengine.fpic.a
else
    echo "[ns-envoy-vcl] WARNING: Qosmos license not found at $QOSMOS_LICENSE_PATH — skipping license patch"
fi

# --- 2. Set up Clang/LLD ---
if [ -L /usr/local/bin/clang ]; then
    export PATH="/usr/local/bin:$PATH"
elif [ -d /opt/llvm-22 ]; then
    export PATH="/opt/llvm-22/bin:$PATH"
elif [ -d /opt/llvm-21 ]; then
    export PATH="/opt/llvm-21/bin:$PATH"
elif [ -d /opt/llvm-20 ]; then
    export PATH="/opt/llvm-20/bin:$PATH"
elif [ -d /opt/llvm-19 ]; then
    export PATH="/opt/llvm-19/bin:$PATH"
fi

if ! command -v ld.lld &> /dev/null; then
    if command -v ld.lld-18 &> /dev/null; then
        ln -sf $(which ld.lld-18) /usr/local/bin/ld.lld
    else
        LLD_BIN=$(find /opt/llvm-*/bin /usr/bin /usr/local/bin -name 'ld.lld' -o -name 'lld-*' 2>/dev/null | head -1)
        if [ -n "$LLD_BIN" ]; then
            ln -sf "$LLD_BIN" /usr/local/bin/ld.lld
        fi
    fi
fi

# --- 3. Install bazelisk (if not already in PATH) ---
if ! command -v bazelisk &> /dev/null; then
    echo "[ns-envoy-vcl] Installing bazelisk ..."
    BAZELISK_VERSION=v1.19.0
    BAZELISK_URL="https://github.com/bazelbuild/bazelisk/releases/download/${BAZELISK_VERSION}/bazelisk-linux-amd64"
    curl -sL "$BAZELISK_URL" -o /usr/local/bin/bazelisk
    chmod +x /usr/local/bin/bazelisk
fi
export PATH="/usr/local/bin:$PATH"

# --- 4. Build with Bazel ---
# Uses ns-envoy's trimmed extensions config (--override_repository) and
# ns-clang-trim config from netskope.bazelrc.
CPUS=$(grep -c ^processor /proc/cpuinfo)

echo "[ns-envoy-vcl] Starting Bazel build ($CPUS jobs) ..."
bazelisk build //source/exe:envoy-vcl \
    --config=ns-clang-trim \
    --define=admin_html=disabled \
    --define=hot_restart=disabled \
    --define=google_grpc=disabled \
    --@envoy//bazel:http3=False \
    --features=-use_header_modules \
    --features=-layering_check \
    --linkopt=-lvppcom \
    --linkopt=-lvppinfra \
    --linkopt=-lsvm \
    --linkopt=-lvlibapi \
    --linkopt=-lvlibmemoryclient \
    --linkopt=-lpthread \
    --linkopt=-lm \
    --linkopt=-lrt \
    --linkopt=-ldl \
    -c opt --jobs=$CPUS --local_ram_resources=12000

# --- 5. Install ---
echo "[ns-envoy-vcl] Installing to $destination ..."
sudo rm -rf $destination
sudo mkdir -p $destination/bin $destination/etc $destination/lib

sudo cp bazel-bin/source/exe/envoy-vcl $destination/bin/envoy
sudo strip $destination/bin/envoy
sudo chmod 755 $destination/bin/envoy

# Copy VPP shared libs (ns-envoy binary dynamically links these at runtime)
sudo cp /opt/vpp23/lib/x86_64-linux-gnu/libvppcom.so.23.02         $destination/lib/
sudo cp /opt/vpp23/lib/x86_64-linux-gnu/libvppinfra.so.23.02        $destination/lib/
sudo cp /opt/vpp23/lib/x86_64-linux-gnu/libsvm.so.23.02             $destination/lib/
sudo cp /opt/vpp23/lib/x86_64-linux-gnu/libvlibapi.so.23.02         $destination/lib/
sudo cp /opt/vpp23/lib/x86_64-linux-gnu/libvlibmemoryclient.so.23.02 $destination/lib/

# Copy Qosmos protocol table and VCL config
sudo cp netskope/vcl_config/qosmos_protocols.json $destination/etc/ 2>/dev/null || true
sudo cp netskope/vcl_config/vcl.conf $destination/etc/ 2>/dev/null || true
sudo cp netskope/vcl_config/envoy.yaml $destination/etc/ 2>/dev/null || true

echo "[ns-envoy-vcl] Binary: $(ls -lh $destination/bin/envoy | awk '{print $5}')"
$destination/bin/envoy --version || true

# --- 6. Package binary tarball for Artifactory (if requested) ---
if [ -n "${ENVOY_PACKAGE_DIR:-}" ]; then
    echo "[ns-envoy-vcl] Creating envoy-binary.tar.gz in $ENVOY_PACKAGE_DIR ..."
    mkdir -p "$ENVOY_PACKAGE_DIR"
    # Tarball contains just the stripped envoy binary (named "envoy" inside).
    # VPP .so files come from /opt/vpp23 in the service repo's nsenvoyvcl image
    # build (already on the CI runner via the tooling fetch step). Config files
    # (envoy.yaml, vcl.conf) come from the Helm ConfigMap, not bundled here.
    pkg_stage=$(mktemp -d)
    cp $destination/bin/envoy "$pkg_stage/envoy" 2>/dev/null || sudo cp $destination/bin/envoy "$pkg_stage/envoy"
    tar -czf "$ENVOY_PACKAGE_DIR/envoy-binary.tar.gz" -C "$pkg_stage" envoy
    rm -rf "$pkg_stage"
    echo "[ns-envoy-vcl] Created: $(ls -lh $ENVOY_PACKAGE_DIR/envoy-binary.tar.gz | awk '{print $5}') $ENVOY_PACKAGE_DIR/envoy-binary.tar.gz"
fi

# --- 7. File list for local packaging (tooling compatibility) ---
cd /opt
find envoy-vcl -type f > "$wd/../file-list" 2>/dev/null || true
find envoy-vcl -type l >> "$wd/../file-list" 2>/dev/null || true

echo "[ns-envoy-vcl] Done."
