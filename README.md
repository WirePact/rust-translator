# Rust Translator

This is a base package for [WirePact](https://github.com/WirePact) translators written in Rust.
It allows developers to write translators for WirePact with minimal effort.

A translator is created via a struct that implements the
[`Translator`](./src/translator/mod.rs) trait. To start a translator, use
the `run_translator()` function that takes a config to run the translator.
One may configure the port of both servers (inbound and outbound gRPC server)
as well as the common name and the address for the [PKI](https://github.com/WirePact/k8s-pki).

A translator must return ingress and egress results to signal to the translator
which action is shall take. An example (base structure) of a translator can
be found in [examples/translator_base](./examples/translator_base.rs).

Essentially, a translator can be started as follows:

```rust
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    run_translator(&TranslatorConfig {
        pki_address: "http://pki:8080".to_string(),
        common_name: "demo translator".to_string(),
        ingress_port: 50051,
        egress_port: 50052,
        translator: Arc::new(TestTranslator {}),
    })
    .await?;

    Ok(())
}
```
