// Note: needs a c++ and protbuf compiler to work:
// dnf install -y gcc-c++ protobuf-compiler

fn main() {
    // If you want to compile *.proto files to rust modules, un-comment and adjust the lines below
    // for each .proto file and add these folders:
    // ./proto
    // ./src/proto
    // Put the *.proto files in ./proto and the module will then compiled to ./src/proto

    // tonic_build::configure()
    //     .build_client(false)
    //     .build_server(true)
    //     .out_dir("src/proto/")
    //     .compile(&["proto/meteo_notifications.proto"], &["proto"])
    //     .expect("Failed to compile meteo_notifications.proto");
}
