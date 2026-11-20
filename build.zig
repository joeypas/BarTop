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
    const libxev = b.dependency("libxev", .{
        .target = target,
        .optimize = optimize,
    });

    var list: [2]*std.Build.Step.Compile = undefined;

    const dns = b.addModule("dns", .{
        .target = target,
        .optimize = optimize,
        .root_source_file = b.path("src/root.zig"),
    });
    dns.addImport("xev", libxev.module("xev"));

    const transport = b.addModule("transport", .{
        .target = target,
        .optimize = optimize,
        .root_source_file = b.path("src/transport.zig"),
    });
    transport.addImport("xev", libxev.module("xev"));

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
        .name = "Client",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/client.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    list[1].root_module.addImport("clap", clap.module("clap"));
    list[1].root_module.addImport("dns", dns);

    // This declares intent for the executable to be installed into the
    // standard location when the user invokes the "install" step (the default
    // step when running `zig build`).
    for (list) |exe| {
        b.installArtifact(exe);
    }

    // const client_step = b.step("client", "Build the client executable");
    // client_step.dependOn(&list[1].step);
    //
    // const run_client_cmd = b.addRunArtifact(list[1]);
    // run_client_cmd.step.dependOn(b.getInstallStep());
    // if (b.args) |args| {
    //     run_client_cmd.addArgs(args);
    // }
    //
    // const run_client_step = b.step("client-run", "Run the client executable");
    // run_client_step.dependOn(&run_client_cmd.step);
    //
    // const lib_unit_tests = b.addTest(.{
    //     .root_module = dns,
    // });
    //
    // const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);
    //
    // const fetch_tests = b.addTest(.{
    //     .root_module = b.createModule(.{
    //         .root_source_file = b.path("src/fetch.zig"),
    //         .target = target,
    //         .optimize = optimize,
    //     }),
    // });
    // fetch_tests.root_module.addImport("xev", libxev.module("xev"));
    //
    // const run_fetch_tests = b.addRunArtifact(fetch_tests);
    //
    // const fetch_manager_tests = b.addTest(.{
    //     .root_module = b.createModule(.{
    //         .root_source_file = b.path("src/fetch_manager.zig"),
    //         .target = target,
    //         .optimize = optimize,
    //     }),
    // });
    // fetch_manager_tests.root_module.addImport("xev", libxev.module("xev"));
    //
    // const run_fetch_manager_tests = b.addRunArtifact(fetch_manager_tests);
    //
    // const transport_tests = b.addTest(.{
    //     .root_module = b.createModule(.{
    //         .root_source_file = b.path("src/transport.zig"),
    //         .target = target,
    //         .optimize = optimize,
    //     }),
    // });
    // transport_tests.root_module.addImport("xev", libxev.module("xev"));
    //
    // const run_transport_tests = b.addRunArtifact(transport_tests);

    // Similar to creating the run step earlier, this exposes a `test` step to
    // the `zig build --help` menu, providing a way for the user to request
    // running the unit tests.
    // const test_step = b.step("test", "Run unit tests");
    // test_step.dependOn(&run_lib_unit_tests.step);
    // test_step.dependOn(&run_fetch_tests.step);
    // test_step.dependOn(&run_fetch_manager_tests.step);
    // test_step.dependOn(&run_transport_tests.step);
}
