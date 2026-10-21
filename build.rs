const PROTOS: &[&str] = &[
    "proto/modal_proto/api.proto",
    "proto/modal_proto/task_command_router.proto",
];

fn main() -> Result<(), Box<dyn std::error::Error>> {
    unsafe {
        std::env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path()?);
    }

    // The client the library uses.
    tonic_prost_build::configure()
        .build_server(false)
        .compile_protos(PROTOS, &["proto"])?;

    // Server stubs for the in-process fake Modal used by the unit tests. They go
    // to their own directory and are only compiled under cfg(test).
    let server_out = std::path::PathBuf::from(std::env::var("OUT_DIR")?).join("server");
    std::fs::create_dir_all(&server_out)?;
    tonic_prost_build::configure()
        .build_client(false)
        .build_server(true)
        .generate_default_stubs(true)
        .out_dir(server_out)
        .compile_protos(PROTOS, &["proto"])?;
    Ok(())
}
