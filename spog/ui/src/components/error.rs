use patternfly_yew::prelude::*;
use yew::prelude::*;

#[derive(PartialEq, Properties)]
pub struct ErrorProperties {
    #[prop_or("Failure".into())]
    pub title: AttrValue,

    #[prop_or_default]
    pub message: Option<String>,

    #[prop_or_default]
    pub err: String,
}

#[function_component(Error)]
pub fn error(props: &ErrorProperties) -> Html {
    html!(
        <Bullseye>
            <Grid gutter=true>
                <GridItem offset={[2]} cols={[2]}>
                    <img src="assets/images/chicken-svgrepo-com.svg" style="transform: scaleY(-1);"/>
                </GridItem>
                <GridItem cols={[6]}>
                    <Title>{&props.title}</Title>
                    if let Some(message)  = &props.message {
                        { &message } {": "}
                    }
                    { &props.err }
                </GridItem>
            </Grid>
        </Bullseye>
    )
}
