const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const mod = b.addModule("securemilter_crypto", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Link OpenSSL libcrypto for RSA operations
    mod.linkSystemLibrary("crypto", .{});

    const test_step = b.step("test", "Run unit tests");

    const tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/root.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    tests.root_module.linkSystemLibrary("crypto", .{});

    const run_tests = b.addRunArtifact(tests);
    test_step.dependOn(&run_tests.step);

    // The one canonical line-limit checker lives in securemilter-lib. This package
    // deliberately declares no dependencies -- it is the leaf crypto layer -- so it
    // cannot reach the script through the dependency graph and uses the sibling
    // checkout instead. That layout is already load-bearing: four repos resolve
    // this library through `.path = "../securemilter-crypto"` in build.zig.zon.
    // Copying the script here instead would put the shared rule in two places,
    // which is the exact defect shape this audit spent its time on.
    const lint = b.addSystemCommand(&.{"sh"});
    lint.addArg("../securemilter-lib/tools/check-line-limit.sh");
    lint.addArg("src");
    lint.addArg(".line-limit-allow");
    if (b.args) |args| lint.addArgs(args);
    lint.has_side_effects = true;
    const lint_step = b.step("lint", "Fail on source files over the 400-line limit");
    lint_step.dependOn(&lint.step);
}
