#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "${SCRIPT_DIR}")"
ANDROID_DIR="${SCRIPT_DIR}/android"
JNI_DIR="${ANDROID_DIR}/app/src/main/jniLibs"
OUTPUT_DIR="${OUTPUT_DIR:-${SCRIPT_DIR}/build/local-apk}"
SYMBOL_DIR="${SYMBOL_DIR:-${SCRIPT_DIR}/build/split-debug-info}"
TEMP_SOURCE_BACKUP=""
export ORG_GRADLE_PROJECT_managedStorage=true

require_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "ERROR: required command not found: $1" >&2
        exit 1
    fi
}

require_directory() {
    if [[ ! -d "$1" ]]; then
        echo "ERROR: required directory not found: $1" >&2
        exit 1
    fi
}

validate_provisioning_config() {
    local configured=0
    local name

    for name in \
        RUD_CFG_URL \
        RUD_CFG_SECRETBOX_KEY_B64 \
        RUD_CFG_VERIFY_PUBLIC_KEY_B64 \
        RUD_DEVICE_ENROLLMENT_KEY_B64; do
        if [[ -v "${name}" && -n "${!name}" ]]; then
            configured=$((configured + 1))
        fi
    done
    if [[ "${configured}" -ne 0 && "${configured}" -ne 4 ]]; then
        echo "ERROR: Android provisioning variables must be configured together" >&2
        exit 1
    fi
}

read_property() {
    local key="$1"
    local file="$2"
    awk -F= -v key="${key}" '
        $1 == key {
            value = substr($0, index($0, "=") + 1)
            sub(/\r$/, "", value)
            print value
            exit
        }
    ' "${file}"
}

find_android_tool() {
    local tool="$1"
    local candidate

    if command -v "${tool}" >/dev/null 2>&1; then
        command -v "${tool}"
        return
    fi

    candidate="$({ find "${ANDROID_HOME}/build-tools" -mindepth 2 -maxdepth 2 \
        -type f -name "${tool}" -print 2>/dev/null || true; } | sort -V | tail -n 1)"
    if [[ -z "${candidate}" ]]; then
        echo "ERROR: Android build tool not found: ${tool}" >&2
        exit 1
    fi
    printf '%s\n' "${candidate}"
}

resolve_ndk_host_dir() {
    local prebuilt_root="${ANDROID_NDK_HOME}/toolchains/llvm/prebuilt"
    local expected
    local candidates=()

    case "$(uname -s)-$(uname -m)" in
        Linux-x86_64) expected="linux-x86_64" ;;
        Darwin-x86_64) expected="darwin-x86_64" ;;
        Darwin-arm64) expected="darwin-arm64" ;;
        *) expected="" ;;
    esac

    if [[ -n "${expected}" && -d "${prebuilt_root}/${expected}" ]]; then
        printf '%s\n' "${prebuilt_root}/${expected}"
        return
    fi

    shopt -s nullglob
    candidates=("${prebuilt_root}"/*)
    shopt -u nullglob
    if [[ ${#candidates[@]} -ne 1 ]]; then
        echo "ERROR: unable to select an NDK host toolchain under ${prebuilt_root}" >&2
        exit 1
    fi
    printf '%s\n' "${candidates[0]}"
}

restore_flutter_sources() {
    local relative_path

    if [[ -z "${TEMP_SOURCE_BACKUP}" || ! -d "${TEMP_SOURCE_BACKUP}" ]]; then
        return
    fi

    for relative_path in \
        flutter/android/app/build.gradle \
        flutter/android/gradle.properties \
        flutter/lib/common.dart \
        flutter/pubspec.yaml \
        flutter/pubspec.lock; do
        cp -p "${TEMP_SOURCE_BACKUP}/${relative_path}" \
            "${REPO_ROOT}/${relative_path}"
    done
    rm -rf "${TEMP_SOURCE_BACKUP}"
    TEMP_SOURCE_BACKUP=""
    echo "INFO: restored Flutter source and lock files"
}

backup_flutter_sources() {
    local relative_path

    require_command git
    for relative_path in \
        flutter/android/app/build.gradle \
        flutter/android/gradle.properties \
        flutter/lib/common.dart \
        flutter/pubspec.yaml \
        flutter/pubspec.lock; do
        if ! git -C "${REPO_ROOT}" diff --quiet -- "${relative_path}" || \
            ! git -C "${REPO_ROOT}" diff --cached --quiet -- "${relative_path}"; then
            echo "ERROR: refusing to temporarily patch modified file: ${relative_path}" >&2
            exit 1
        fi
    done

    TEMP_SOURCE_BACKUP="$(mktemp -d)"
    for relative_path in \
        flutter/android/app/build.gradle \
        flutter/android/gradle.properties \
        flutter/lib/common.dart \
        flutter/pubspec.yaml \
        flutter/pubspec.lock; do
        install -D -m 0644 "${REPO_ROOT}/${relative_path}" \
            "${TEMP_SOURCE_BACKUP}/${relative_path}"
    done
    trap restore_flutter_sources EXIT
}

prepare_uni_links_plugin() {
    local package_config="${SCRIPT_DIR}/.dart_tool/package_config.json"
    local root_uri
    local source_dir
    local compat_dir="${SCRIPT_DIR}/build/compat-plugins/uni_links"
    local java_file="${compat_dir}/android/src/main/java/name/avioli/unilinks/UniLinksPlugin.java"

    root_uri="$(awk '
        /"name": "uni_links"/ { found = 1; next }
        found && /"rootUri":/ {
            value = $0
            sub(/^[^:]*:[[:space:]]*"/, "", value)
            sub(/",?[[:space:]]*$/, "", value)
            print value
            exit
        }
    ' "${package_config}")"
    if [[ "${root_uri}" != file://* || "${root_uri}" == *%* ]]; then
        echo "ERROR: unable to resolve the uni_links package path" >&2
        exit 1
    fi
    source_dir="${root_uri#file://}"
    require_directory "${source_dir}"

    rm -rf "${compat_dir}"
    install -d "$(dirname "${compat_dir}")"
    cp -a "${source_dir}" "${compat_dir}"
    sed -i \
        '/^    \/\*\* Plugin registration\. \*\/$/,/^    @Override$/ { /^    @Override$/!d; }' \
        "${java_file}"
    if grep -F 'PluginRegistry.Registrar' "${java_file}" >/dev/null; then
        echo "ERROR: failed to remove the uni_links v1 Android registration" >&2
        exit 1
    fi
    sed -i '/^  flutter_plugin_android_lifecycle: 2\.0\.20$/a\
  uni_links:\
    path: build/compat-plugins/uni_links' "${SCRIPT_DIR}/pubspec.yaml"
    if ! grep -Fx '    path: build/compat-plugins/uni_links' \
        "${SCRIPT_DIR}/pubspec.yaml" >/dev/null; then
        echo "ERROR: failed to configure the patched uni_links package" >&2
        exit 1
    fi
}

prepare_flutter_sources() {
    local flutter_version
    local gradle_heap="${GRADLE_MAX_HEAP:-4096M}"
    local needs_flutter_344_patch=0

    backup_flutter_sources
    if [[ ! "${gradle_heap}" =~ ^[1-9][0-9]*[mMgG]$ ]]; then
        echo "ERROR: invalid GRADLE_MAX_HEAP: ${gradle_heap}" >&2
        exit 1
    fi
    sed -i -E \
        "s/^org\.gradle\.jvmargs=.*/org.gradle.jvmargs=-Xmx${gradle_heap}/" \
        "${ANDROID_DIR}/gradle.properties"
    if ! grep -Fx "org.gradle.jvmargs=-Xmx${gradle_heap}" \
        "${ANDROID_DIR}/gradle.properties" >/dev/null; then
        echo "ERROR: failed to configure the Gradle heap" >&2
        exit 1
    fi
    flutter_version="$(flutter --version | sed -n '1s/^Flutter \([0-9.]*\).*/\1/p')"
    if [[ -z "${flutter_version}" ]]; then
        echo "ERROR: unable to determine Flutter version" >&2
        exit 1
    fi

    if [[ "$(printf '%s\n' "3.44.0" "${flutter_version}" | sort -V | head -n 1)" == "3.44.0" ]]; then
        needs_flutter_344_patch=1
        echo "INFO: applying the upstream Flutter 3.44 compatibility patch temporarily"
        (
            cd "${REPO_ROOT}"
            bash .github/patches/apply_flutter_3.44_source_patches.sh
        )
        sed -i \
            -e 's/^  file_picker: \^5\.1\.0$/  file_picker: 8.0.4/' \
            -e 's/^  sqflite: 2\.2\.0$/  sqflite: 2.3.3+2/' \
            -e 's/^  flutter_plugin_android_lifecycle: 2\.0\.17$/  flutter_plugin_android_lifecycle: 2.0.20/' \
            "${SCRIPT_DIR}/pubspec.yaml"
        for dependency in \
            '  file_picker: 8.0.4' \
            '  sqflite: 2.3.3+2' \
            '  flutter_plugin_android_lifecycle: 2.0.20'; do
            if ! grep -Fx "${dependency}" "${SCRIPT_DIR}/pubspec.yaml" >/dev/null; then
                echo "ERROR: failed to apply Android dependency patch: ${dependency}" >&2
                exit 1
            fi
        done
    fi

    if [[ "${SKIP_FLUTTER_PUB_GET:-0}" != "1" ]]; then
        (
            cd "${SCRIPT_DIR}"
            flutter pub get
        )
    fi

    if [[ "${needs_flutter_344_patch}" == "1" ]]; then
        if [[ ! -f "${SCRIPT_DIR}/.dart_tool/package_config.json" ]]; then
            echo "ERROR: Flutter 3.44 compatibility requires flutter pub get" >&2
            exit 1
        fi
        prepare_uni_links_plugin
        (
            cd "${SCRIPT_DIR}"
            flutter pub get
        )
    fi

    if [[ "${SKIP_BRIDGE_GENERATION:-0}" != "1" ]]; then
        require_command flutter_rust_bridge_codegen
        (
            cd "${REPO_ROOT}"
            flutter_rust_bridge_codegen \
                --rust-input ./src/flutter_ffi.rs \
                --dart-output ./flutter/lib/generated_bridge.dart
        )
    fi
}

copy_native_library() {
    local rust_target="$1"
    local android_abi="$2"
    local ndk_lib_dir="$3"
    local rust_lib="${REPO_ROOT}/target/${rust_target}/release/liblibrustdesk.so"
    local cxx_lib="${NDK_HOST_DIR}/sysroot/usr/lib/${ndk_lib_dir}/libc++_shared.so"
    local destination="${JNI_DIR}/${android_abi}"

    if [[ ! -f "${rust_lib}" ]]; then
        echo "ERROR: Rust library not found: ${rust_lib}" >&2
        exit 1
    fi
    if [[ ! -f "${cxx_lib}" ]]; then
        echo "ERROR: NDK C++ runtime not found: ${cxx_lib}" >&2
        exit 1
    fi

    install -d "${destination}"
    install -m 0644 "${rust_lib}" "${destination}/librustdesk.so"
    install -m 0644 "${cxx_lib}" "${destination}/libc++_shared.so"
    "${LLVM_STRIP}" "${destination}/librustdesk.so" "${destination}/libc++_shared.so"

    sha256sum "${destination}/librustdesk.so" "${destination}/libc++_shared.so"
}

validate_signing_config() {
    local properties_file="${ANDROID_DIR}/key.properties"
    local property
    local value
    local store_file

    if [[ ! -f "${properties_file}" ]]; then
        echo "ERROR: signing properties not found: ${properties_file}" >&2
        exit 1
    fi

    for property in storeFile storePassword keyAlias keyPassword; do
        value="$(read_property "${property}" "${properties_file}")"
        if [[ -z "${value}" ]]; then
            echo "ERROR: signing property is missing: ${property}" >&2
            exit 1
        fi
    done

    store_file="$(read_property storeFile "${properties_file}")"
    if [[ "${store_file}" != /* ]]; then
        store_file="${ANDROID_DIR}/app/${store_file}"
    fi
    if [[ ! -f "${store_file}" ]]; then
        echo "ERROR: signing keystore referenced by key.properties does not exist" >&2
        exit 1
    fi

    echo "INFO: release signing configuration is present"
}

validate_apk() {
    local apk="$1"
    local abi="$2"
    local report="$3"
    local rust_entry="lib/${abi}/librustdesk.so"
    local cxx_entry="lib/${abi}/libc++_shared.so"

    if ! unzip -Z1 "${apk}" | grep -Fx "${rust_entry}" >/dev/null; then
        echo "ERROR: ${apk} does not contain ${rust_entry}" >&2
        exit 1
    fi
    if ! unzip -Z1 "${apk}" | grep -Fx "${cxx_entry}" >/dev/null; then
        echo "ERROR: ${apk} does not contain ${cxx_entry}" >&2
        exit 1
    fi
    if ! "${AAPT}" dump badging "${apk}" | \
        grep -Fx "native-code: '${abi}'" >/dev/null; then
        echo "ERROR: ${apk} does not contain only the expected ABI: ${abi}" >&2
        exit 1
    fi

    {
        echo "APK: $(basename "${apk}")"
        sha256sum "${apk}"
        "${APKSIGNER}" verify --verbose --print-certs "${apk}"
        "${AAPT}" dump badging "${apk}" | sed -n '1,4p'
    } >"${report}"

    "${APKSIGNER}" verify "${apk}"
    echo "INFO: verified $(basename "${apk}")"
}

build_android_target() {
    local android_abi="$1"
    local rust_target="$2"
    local ndk_lib_dir="$3"

    if [[ "${SKIP_ANDROID_DEPS:-0}" != "1" ]]; then
        "${SCRIPT_DIR}/build_android_deps.sh" "${android_abi}"
    fi

    if [[ "${SKIP_RUST_BUILD:-0}" != "1" ]]; then
        (
            cd "${REPO_ROOT}"
            if [[ "${android_abi}" == "armeabi-v7a" ]]; then
                export VCPKGRS_TRIPLET=arm-neon-android
            fi
            cargo ndk --platform 21 --target "${rust_target}" \
                build --locked --release --features flutter,hwcodec
        )
    fi

    copy_native_library "${rust_target}" "${android_abi}" "${ndk_lib_dir}"
}

require_command awk
require_command cargo
require_command cargo-ndk
require_command flutter
require_command java
require_command sha256sum
require_command unzip

: "${ANDROID_HOME:?ERROR: ANDROID_HOME is not set}"
: "${ANDROID_NDK_HOME:?ERROR: ANDROID_NDK_HOME is not set}"
: "${VCPKG_ROOT:?ERROR: VCPKG_ROOT is not set}"

require_directory "${ANDROID_HOME}"
require_directory "${ANDROID_NDK_HOME}"
require_directory "${VCPKG_ROOT}"
validate_provisioning_config
validate_signing_config

export ANDROID_NDK_ROOT="${ANDROID_NDK_HOME}"
NDK_HOST_DIR="$(resolve_ndk_host_dir)"
LLVM_STRIP="${NDK_HOST_DIR}/bin/llvm-strip"
if [[ ! -x "${LLVM_STRIP}" ]]; then
    echo "ERROR: llvm-strip not found: ${LLVM_STRIP}" >&2
    exit 1
fi

APKSIGNER="$(find_android_tool apksigner)"
AAPT="$(find_android_tool aapt)"
prepare_flutter_sources

BUILD_ANDROID_ARM64="${BUILD_ANDROID_ARM64:-1}"
BUILD_ANDROID_ARMV7="${BUILD_ANDROID_ARMV7:-1}"
if [[ "${BUILD_ANDROID_ARM64}" != "0" && "${BUILD_ANDROID_ARM64}" != "1" ]] || \
    [[ "${BUILD_ANDROID_ARMV7}" != "0" && "${BUILD_ANDROID_ARMV7}" != "1" ]]; then
    echo "ERROR: BUILD_ANDROID_ARM64 and BUILD_ANDROID_ARMV7 must be 0 or 1" >&2
    exit 1
fi
if [[ "${BUILD_ANDROID_ARM64}" == "0" && "${BUILD_ANDROID_ARMV7}" == "0" ]]; then
    echo "ERROR: at least one Android ABI must be enabled" >&2
    exit 1
fi

TARGET_PLATFORMS=()
if [[ "${BUILD_ANDROID_ARM64}" == "1" ]]; then
    build_android_target arm64-v8a aarch64-linux-android aarch64-linux-android
    TARGET_PLATFORMS+=(android-arm64)
fi
if [[ "${BUILD_ANDROID_ARMV7}" == "1" ]]; then
    build_android_target armeabi-v7a armv7-linux-androideabi arm-linux-androideabi
    TARGET_PLATFORMS+=(android-arm)
fi
TARGET_PLATFORM="$(IFS=,; echo "${TARGET_PLATFORMS[*]}")"

install -d "${OUTPUT_DIR}" "${SYMBOL_DIR}"
(
    cd "${SCRIPT_DIR}"
    flutter build apk --release --split-per-abi \
        --target-platform "${TARGET_PLATFORM}" \
        --obfuscate --split-debug-info "${SYMBOL_DIR}"
)

VERSION="$(awk '/^version:/ { print $2; exit }' "${SCRIPT_DIR}/pubspec.yaml")"
VERSION="${VERSION%%+*}"
OUTPUT_NAMES=()
if [[ "${BUILD_ANDROID_ARM64}" == "1" ]]; then
    ARM64_SOURCE="${SCRIPT_DIR}/build/app/outputs/flutter-apk/app-arm64-v8a-release.apk"
    ARM64_APK="${OUTPUT_DIR}/rustdesk-${VERSION}-arm64-v8a-signed.apk"
    install -m 0644 "${ARM64_SOURCE}" "${ARM64_APK}"
    validate_apk "${ARM64_APK}" arm64-v8a "${ARM64_APK%.apk}.txt"
    OUTPUT_NAMES+=("$(basename "${ARM64_APK}")")
fi
if [[ "${BUILD_ANDROID_ARMV7}" == "1" ]]; then
    ARMV7_SOURCE="${SCRIPT_DIR}/build/app/outputs/flutter-apk/app-armeabi-v7a-release.apk"
    ARMV7_APK="${OUTPUT_DIR}/rustdesk-${VERSION}-armeabi-v7a-signed.apk"
    install -m 0644 "${ARMV7_SOURCE}" "${ARMV7_APK}"
    validate_apk "${ARMV7_APK}" armeabi-v7a "${ARMV7_APK%.apk}.txt"
    OUTPUT_NAMES+=("$(basename "${ARMV7_APK}")")
fi

(
    cd "${OUTPUT_DIR}"
    sha256sum "${OUTPUT_NAMES[@]}" >SHA256SUMS
)

echo "INFO: signed APKs are available in ${OUTPUT_DIR}"
