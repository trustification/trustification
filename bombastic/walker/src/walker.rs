use url::Url;
use crate::BombasticClient;

pub async fn run(client: &BombasticClient, path: &Url) -> Result<(), anyhow::Error> {

    println!("download files");

    //
    // wget -nv "$1" && \
    // wget -nv "$1".asc && \
    // wget -nv "$1".sha256

    println!("verify files signature and checksum");

    println!("upload to bombastic");
    //client.upload(path);

    Ok(())
}