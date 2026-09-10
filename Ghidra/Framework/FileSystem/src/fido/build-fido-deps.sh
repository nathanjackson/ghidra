#!/bin/sh
## ###
# IP: GHIDRA
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##
#
# Build static libcbor + libfido2 (and static OpenSSL on macOS) into PREFIX.
# Usage: build-fido-deps.sh <prefix> <src_dir> <ghidra_platform>
#
# src_dir contains unpacked tarballs:
#   libfido2-1.17.0/  libcbor-0.12.0/  openssl-3.5.8/
#

set -eu

if [ "$#" -ne 3 ]; then
	echo "usage: $0 <prefix> <src_dir> <ghidra_platform>" >&2
	exit 2
fi

PREFIX=$1
SRC=$2
PLATFORM=$3

LIBFIDO2_VER=1.17.0
LIBCBOR_VER=0.12.0
OPENSSL_VER=3.5.8

case "$PLATFORM" in
	mac_arm_64)
		OS=mac
		CMAKE_OSX_ARCH=arm64
		OPENSSL_TARGET=darwin64-arm64-cc
		;;
	mac_x86_64)
		OS=mac
		CMAKE_OSX_ARCH=x86_64
		OPENSSL_TARGET=darwin64-x86_64-cc
		;;
	linux_*|freebsd_*|openbsd_*)
		OS=unix
		CMAKE_OSX_ARCH=
		OPENSSL_TARGET=
		;;
	*)
		echo "unsupported platform for vendored libfido2: $PLATFORM" >&2
		exit 1
		;;
esac

if ! command -v cmake >/dev/null 2>&1; then
	echo "cmake is required to build vendored libfido2 (not found on PATH)" >&2
	exit 1
fi

NPROC=4
if command -v nproc >/dev/null 2>&1; then
	NPROC=$(nproc)
elif command -v sysctl >/dev/null 2>&1; then
	NPROC=$(sysctl -n hw.ncpu 2>/dev/null || echo 4)
fi

CBOR_SRC="$SRC/libcbor-${LIBCBOR_VER}"
FIDO_SRC="$SRC/libfido2-${LIBFIDO2_VER}"
SSL_SRC="$SRC/openssl-${OPENSSL_VER}"

if [ ! -d "$CBOR_SRC" ] || [ ! -d "$FIDO_SRC" ]; then
	echo "unpacked fido sources not found under $SRC" >&2
	echo "expected $CBOR_SRC and $FIDO_SRC" >&2
	exit 1
fi

if [ "$OS" = mac ] && [ ! -d "$SSL_SRC" ]; then
	echo "unpacked OpenSSL sources not found: $SSL_SRC" >&2
	exit 1
fi

if [ -f "$PREFIX/lib/libfido2.a" ] && [ -f "$PREFIX/lib/libcbor.a" ]; then
	if [ "$OS" != mac ] || [ -f "$PREFIX/lib/libcrypto.a" ]; then
		echo "vendored fido deps already present in $PREFIX"
		exit 0
	fi
fi

mkdir -p "$PREFIX/lib/pkgconfig" "$PREFIX/include"
BUILD="$PREFIX/tmp-build"
mkdir -p "$BUILD"

cmake_osx=""
if [ -n "$CMAKE_OSX_ARCH" ]; then
	cmake_osx="-DCMAKE_OSX_ARCHITECTURES=${CMAKE_OSX_ARCH} -DCMAKE_OSX_DEPLOYMENT_TARGET=11.0"
fi

if [ "$OS" = mac ] && [ ! -f "$PREFIX/lib/libcrypto.a" ]; then
	echo "building OpenSSL ${OPENSSL_VER} ($OPENSSL_TARGET) ..."
	SSL_BUILD="$BUILD/openssl"
	rm -rf "$SSL_BUILD"
	mkdir -p "$SSL_BUILD"
	# OpenSSL Configure writes into the source tree; copy first.
	cp -R "$SSL_SRC/." "$SSL_BUILD/"
	(
		cd "$SSL_BUILD"
		./Configure "$OPENSSL_TARGET" no-shared no-apps no-docs no-tests \
			--prefix="$PREFIX" --libdir=lib
		make -j"$NPROC"
		make install_sw
	)
fi

echo "building libcbor ${LIBCBOR_VER} ..."
CBOR_BUILD="$BUILD/libcbor"
cmake -S "$CBOR_SRC" -B "$CBOR_BUILD" \
	-DCMAKE_BUILD_TYPE=Release \
	-DCMAKE_INSTALL_PREFIX="$PREFIX" \
	-DCMAKE_INSTALL_LIBDIR=lib \
	-DBUILD_SHARED_LIBS=OFF \
	-DWITH_EXAMPLES=OFF \
	-DWITH_TESTS=OFF \
	-DSANITIZE=OFF \
	-DCMAKE_INTERPROCEDURAL_OPTIMIZATION=OFF \
	-DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
	$cmake_osx
cmake --build "$CBOR_BUILD" -j "$NPROC"
cmake --install "$CBOR_BUILD"

# Prefer the prefix for libcbor and (on macOS) libcrypto. Keep the rest of
# PKG_CONFIG_PATH so macOS can still resolve system/Homebrew zlib.pc.
ORIG_PKG=${PKG_CONFIG_PATH:-}
export PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig${ORIG_PKG:+:$ORIG_PKG}"

echo "building libfido2 ${LIBFIDO2_VER} ..."
FIDO_BUILD="$BUILD/libfido2"
cmake -S "$FIDO_SRC" -B "$FIDO_BUILD" \
	-DCMAKE_BUILD_TYPE=Release \
	-DCMAKE_INSTALL_PREFIX="$PREFIX" \
	-DCMAKE_INSTALL_LIBDIR=lib \
	-DCMAKE_PREFIX_PATH="$PREFIX" \
	-DBUILD_SHARED_LIBS=OFF \
	-DBUILD_STATIC_LIBS=ON \
	-DBUILD_EXAMPLES=OFF \
	-DBUILD_TOOLS=OFF \
	-DBUILD_MANPAGES=OFF \
	-DBUILD_TESTS=OFF \
	-DUSE_HIDAPI=OFF \
	-DUSE_PCSC=OFF \
	-DNFC_LINUX=OFF \
	-DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
	$cmake_osx
cmake --build "$FIDO_BUILD" -j "$NPROC"
cmake --install "$FIDO_BUILD"

if [ ! -f "$PREFIX/lib/libfido2.a" ]; then
	echo "libfido2.a was not installed into $PREFIX/lib" >&2
	ls -la "$PREFIX/lib" >&2 || true
	exit 1
fi

echo "vendored fido deps installed into $PREFIX"
