package(licenses = ["notice"])

load("//tools/go_stateify:defs.bzl", "go_library")

go_library(
    name = "abi",
    srcs = [
        "abi.go",
        "abi_linux.go",
        "flag.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/abi",
    visibility = ["//:sandbox"],
)
