fn main() {
    tonic_build::configure()
        .build_server(true)
        .compile(&["src/protos/sandbox.proto"], &["src/protos"])
        .unwrap();

    tonic_build::configure()
        .build_server(true)
        .type_attribute(".", "#[derive(serde::Deserialize, serde::Serialize)]")
        .compile(&["src/protos/cri-api/api.proto"], &["src/protos"])
        .unwrap();
}
