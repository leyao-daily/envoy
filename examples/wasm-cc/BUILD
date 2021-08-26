load("@bazel_skylib//lib:selects.bzl", "selects")
load(
    "//bazel:envoy_build_system.bzl",
    "envoy_proto_library",
    "envoy_package",
)
load("//bazel/wasm:wasm.bzl", "envoy_wasm_cc_binary")

licenses(["notice"])  # Apache 2

envoy_package()

selects.config_setting_group(
    name = "include_wasm_config",
    match_all = [
        "//bazel:x86",
        "//bazel:wasm_v8",
    ],
)

filegroup(
    name = "configs",
    srcs = glob([
        "**/*.wasm",
    ]) + select({
        ":include_wasm_config": glob(
            [
                "**/*.yaml",
            ],
            exclude = [
                "**/*docker-compose*.yaml",
            ],
        ),
        "//conditions:default": [],
    }),
)

proto_library(
    name = "app_config",
    srcs = ["app_config.proto"],
    visibility = ["//visibility:public"],
)

cc_proto_library(
    name = "app_config_cc_proto",
    visibility = ["//visibility:public"],
    deps = [":app_config"],
)


envoy_wasm_cc_binary(
    name = "envoy_filter_http_wasm_example.wasm",
    srcs = ["envoy_filter_http_wasm_example.cc"],
)

envoy_wasm_cc_binary(
    name = "envoy_filter_http_wasm_updated_example.wasm",
    srcs = ["envoy_filter_http_wasm_updated_example.cc"],
)


envoy_wasm_cc_binary(
    name = "ms.wasm",
    srcs = ["ms.cc", "utils.cc", "utils.h"],
    deps = [
        "@modsecurity//:lib",
	"//examples/wasm-cc:app_config_cc_proto",
    ],
)

filegroup(
    name = "files",
    srcs = glob(["**/*"]),
)
