use std::process::ExitCode;

#[derive(clap::Args, Debug)]
pub struct Command {
    #[arg(long = "bombastic-api-disabled", default_value_t = false)]
    pub(crate) bombastic_api_disabled: bool,

    #[arg(long = "bombastic-api-port", default_value_t = 8082)]
    pub(crate) bombastic_api_port: u16,

    #[arg(long = "vexination-api-disabled", default_value_t = false)]
    pub(crate) vexination_api_disabled: bool,

    #[arg(long = "vexination-api-port", default_value_t = 8081)]
    pub(crate) vexination_api_port: u16,

    #[arg(long = "spog-disabled", default_value_t = false)]
    pub(crate) spog_disabled: bool,

    #[arg(long = "spog-port", default_value_t = 8083)]
    pub(crate) spog_port: u16,
}

impl Command {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        tokio::select! {
            bapi = bombastic_api::Run::default().run(None) => match bapi {
               Err(e) => {
                    panic!("Error running bombastic API: {:?}", e);
                }
              Ok(code) => {
                println!("Bombastic API exited with code {:?}", code);
              }
           },
           vapi = vexination_api::Run::default().run(None) => match vapi {
               Err(e) => {
                   panic!("Error running vexination API: {:?}", e);
               }
               Ok(code) => {
                    println!("Vexination API exited with code {:?}", code);
                }
            },
        }

        // let mut tasks = Vec::new();

        // if !self.bombastic_api_disabled {
        //     tasks.push(tokio::spawn(async move {
        //         let bom = bombastic_api::Run::new(self.bombastic_api_port).run();
        //         bom.await.unwrap();
        //     }));
        // }

        // if !self.vexination_api_disabled {
        //     tasks.push(tokio::task::spawn(async move {
        //         let vex = vexination_api::Run::new(self.vexination_api_port).run();
        //         vex.await.unwrap();
        //     }));
        // }

        // if !self.spog_disabled {
        //     tasks.push(tokio::task::spawn(async move {
        //         let spog = spog_search::Run::new(self.spog_port).run();
        //         spog.await.unwrap();
        //     }));
        // }

        // tasks.push(tokio::spawn(async move {
        //     let bom = bombastic_indexer::Run::new().run();
        //     bom.await.unwrap();
        // }));

        // tasks.push(tokio::task::spawn({
        //     async move {
        //         let vex = vexination_indexer::Run::new().run();
        //         vex.await.unwrap();
        //     }
        // }));

        // futures::future::join_all(tasks).await;
        Ok(ExitCode::SUCCESS)
    }
}
