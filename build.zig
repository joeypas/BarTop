const std = @import("std");

// Although this function looks imperative, note that its job is to
// declaratively construct a build graph that will be executed by an external
// runner.
pub fn build(b: *std.Build) void {
    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});

    // Standard optimization options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall. Here we do not
    // set a preferred release mode, allowing the user to decide how to optimize.
    const optimize = b.standardOptimizeOption(.{});

    const clap = b.dependency("clap", .{
        .target = target,
        .optimize = optimize,
    });
    const xev = b.dependency("libxev", .{
        .target = target,
        .optimize = optimize,
    });
    const openssl = b.dependency("openssl", .{
        .target = target,
        .optimize = optimize,
    });

    var list: [3]*std.Build.Step.Compile = undefined;

    const dns = b.addModule("dns", .{
        .target = target,
        .optimize = optimize,
        .root_source_file = b.path("src/root.zig"),
    });

    dns.addImport("xev", xev.module("xev"));

    dns.linkLibrary(openssl.artifact("crypto"));
    //dns.linkLibrary(openssl.artifact("ssl"));
    dns.addIncludePath(openssl.artifact("crypto").getEmittedIncludeTree());
    dns.addIncludePath(openssl.artifact("ssl").getEmittedIncludeTree());

    list[0] = b.addLibrary(.{
        .name = "dns",
        .root_module = dns,
    });

    const docs_step = b.step("doc", "Emit documentation");

    const docs_install = b.addInstallDirectory(.{
        .install_dir = .prefix,
        .install_subdir = "docs",
        .source_dir = list[0].getEmittedDocs(),
    });

    docs_step.dependOn(&docs_install.step);
    b.getInstallStep().dependOn(docs_step);

    list[1] = b.addExecutable(.{
        .name = "StubResolver",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    //list[1].root_module.addImport("xev", xev.module("xev"));
    list[1].root_module.addImport("dns", dns);

    list[2] = b.addExecutable(.{
        .name = "Client",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/client.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    list[2].root_module.addImport("clap", clap.module("clap"));
    list[2].root_module.addImport("dns", dns);

    // This declares intent for the executable to be installed into the
    // standard location when the user invokes the "install" step (the default
    // step when running `zig build`).
    for (list) |exe| {
        b.installArtifact(exe);
    }

    // This *creates* a Run step in the build graph, to be executed when another
    // step is evaluated that depends on it. The next line below will establish
    // such a dependency.
    const run_cmd = b.addRunArtifact(list[0]);

    // By making the run step depend on the install step, it will be run from the
    // installation directory rather than directly from within the cache directory.
    // This is not necessary, however, if the application depends on other installed
    // files, this ensures they will be present and in the expected location.
    run_cmd.step.dependOn(b.getInstallStep());

    // This allows the user to pass arguments to the application in the build
    // command itself, like this: `zig build run -- arg1 arg2 etc`
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    // This creates a build step. It will be visible in the `zig build --help` menu,
    // and can be selected like this: `zig build run`
    // This will evaluate the `run` step rather than the default, which is "install".
    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    const lib_unit_tests = b.addTest(.{
        .root_module = dns,
    });

    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);

    // Similar to creating the run step earlier, this exposes a `test` step to
    // the `zig build --help` menu, providing a way for the user to request
    // running the unit tests.
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_lib_unit_tests.step);
}
