use std::process::ExitCode;

#[derive(clap::Args, Debug)]
pub struct Command {
    #[arg(long = "bombastic-api-disabled", default_value_t = false)]
    pub(crate) bombastic_api_disabled: bool,

    #[arg(long = "bombastic-api-port", default_value_t = 8082)]
    pub(crate) bombastic_api_port: u16,

    #[arg(long = "bombastic-indexer-disabled", default_value_t = false)]
    pub(crate) bombastic_indexer_disabled: bool,

    #[arg(long = "vexination-api-disabled", default_value_t = false)]
    pub(crate) vexination_api_disabled: bool,

    #[arg(long = "vexination-api-port", default_value_t = 8081)]
    pub(crate) vexination_api_port: u16,

    #[arg(long = "vexination-indexer-disabled", default_value_t = false)]
    pub(crate) vexination_indexer_disabled: bool,

    #[arg(long = "spog-disabled", default_value_t = false)]
    pub(crate) spog_disabled: bool,

    #[arg(long = "spog-port", default_value_t = 8083)]
    pub(crate) spog_port: u16,
}

impl Command {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        tokio::select! {
            bapi = bombastic_api::Run::default().run(None), if !self.bombastic_api_disabled  => match bapi {
                Err(e) => {
                    panic!("Error running bombastic API: {:?}", e);
                }
                Ok(code) => {
                    println!("Bombastic API exited with code {:?}", code);
                }
            },
            bindex = bombastic_indexer::Run::default().run(), if !self.bombastic_indexer_disabled  => match bindex {
                Err(e) => {
                    panic!("Error running bombastic Indexer: {:?}", e);
                }
                Ok(code) => {
                    println!("Bombastic Indexer exited with code {:?}", code);
                }
            },
            vapi = vexination_api::Run::default().run(None), if !self.vexination_api_disabled => match vapi {
                Err(e) => {
                   panic!("Error running vexination API: {:?}", e);
                }
                Ok(code) => {
                    println!("Vexination API exited with code {:?}", code);
                }
            },
            vindex = vexination_indexer::Run::default().run(), if !self.vexination_indexer_disabled  => match vindex {
                Err(e) => {
                    panic!("Error running vexination Indexer: {:?}", e);
                }
                Ok(code) => {
                    println!("Vexination Indexer exited with code {:?}", code);
                }
            },
            spog = spog_api::Run::default().run(), if !self.spog_disabled => match spog {
                Err(e) => {
                    panic!("Error running SPOG: {:?}", e);
                }
                Ok(code) => {
                    println!("SPOG exited with code {:?}", code);
                 }
             },
        }

        Ok(ExitCode::SUCCESS)
    }
}
