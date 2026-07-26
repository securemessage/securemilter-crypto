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
}
