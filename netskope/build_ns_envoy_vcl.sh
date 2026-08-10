#!/bin/bash
# Build minimal Envoy-VCL from ns-envoy repo with Qosmos DPI filter.
# Depends on: vpp23 (static VCL libs), ixe-sdk (Qosmos SDK), clang-18.
# Produces: /opt/envoy-vcl/bin/envoy (stripped ~184MB)
#
# Key differences from envoy-vcl.sh:
#   - Uses ns-envoy repo (no patches needed — changes are committed)
#   - Uses ns-envoy's trimmed extensions config via --override_repository
#   - Uses ns-envoy's netskope.bazelrc for --config=ns-clang-trim
#
# Build time: ~2.5 hours (clean), ~30 min (cached deps)

set -eu

destination=/opt/envoy-vcl
wd=$(pwd)

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
    ln -sf $(which clang-18) /usr/local/bin/clang
    ln -sf $(which clang++-18) /usr/local/bin/clang++
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
if [ -f /home/rkumark/ws/cfw-demux-svc/envoy-qosmos/docs/Q1800801-20181221.bin ]; then
    echo "[ns-envoy-vcl] Applying Qosmos license patch ..."
    perl /opt/3p/binary/ixe/src/tools/license_patcher/license_patcher.pl \
        /home/rkumark/ws/cfw-demux-svc/envoy-qosmos/docs/Q1800801-20181221.bin \
        $QOSMOS_LOCAL/lib/libqmengine.fpic.a
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
rm -rf $destination
mkdir -p $destination/bin $destination/etc $destination/lib

cp bazel-bin/source/exe/envoy-vcl $destination/bin/envoy
strip $destination/bin/envoy
chmod 755 $destination/bin/envoy

# Copy VPP shared libs (ns-envoy binary dynamically links these at runtime)
cp /opt/vpp23/lib/x86_64-linux-gnu/libvppcom.so.23.02         $destination/lib/
cp /opt/vpp23/lib/x86_64-linux-gnu/libvppinfra.so.23.02        $destination/lib/
cp /opt/vpp23/lib/x86_64-linux-gnu/libsvm.so.23.02             $destination/lib/
cp /opt/vpp23/lib/x86_64-linux-gnu/libvlibapi.so.23.02         $destination/lib/
cp /opt/vpp23/lib/x86_64-linux-gnu/libvlibmemoryclient.so.23.02 $destination/lib/

# Copy Qosmos protocol table and VCL config
cp netskope/vcl_config/qosmos_protocols.json $destination/etc/ 2>/dev/null || true
cp netskope/vcl_config/vcl.conf $destination/etc/ 2>/dev/null || true
cp netskope/vcl_config/envoy.yaml $destination/etc/ 2>/dev/null || true

echo "[ns-envoy-vcl] Binary: $(ls -lh $destination/bin/envoy | awk '{print $5}')"
$destination/bin/envoy --version

# --- 6. File list for packaging ---
cd /opt
find envoy-vcl -type f > "$wd/../file-list"
find envoy-vcl -type l >> "$wd/../file-list"

echo "[ns-envoy-vcl] Done."
