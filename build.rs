const INCLUDES: &[&str; 5] = &[
    "./external/googleapis",
    "./external/envoy/api",
    "./external/udpa",
    "./external/protoc-gen-validate",
    "./external/k8s-pki/proto",
];

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // TODO: copy the needed protos over to a proto dir.
    println!(
        "cargo:rerun-if-changed=./external/envoy/api/envoy/service/auth/v3/external_auth.proto"
    );
    println!("cargo:rerun-if-changed=./external/k8s-pki/proto/pki.proto");

    tonic_build::configure()
        .build_server(true)
        .build_client(false)
        .compile(
            &["./external/envoy/api/envoy/service/auth/v3/external_auth.proto"],
            INCLUDES,
        )?;

    tonic_build::configure()
        .build_server(false)
        .build_client(true)
        .compile(&["./external/k8s-pki/proto/pki.proto"], INCLUDES)?;

    Ok(())
}
