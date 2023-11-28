use crate::config::use_config;
use crate::error::{ApiErrorDetails, ApiErrorKind};
use patternfly_yew::prelude::*;
use yew::prelude::*;

#[derive(PartialEq, Properties)]
pub struct ApiErrorProperties {
    #[prop_or("Failure".into())]
    pub title: AttrValue,
    pub error: super::ApiError,
}

#[function_component(ApiError)]
pub fn api_error(props: &ApiErrorProperties) -> Html {
    match &*props.error.0 {
        ApiErrorKind::Api {
            status: _,
            details: ApiErrorDetails::Information(info),
        } => {
            html!(
                <Error title={props.title.clone()} message={info.message.clone()} err={info.details.clone()}/>
            )
        }
        _ => {
            html!(<Error title={props.title.clone()} message="Error processing request" err={props.error.to_string()} />)
        }
    }
}

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
    let config = use_config();

    html!(
        <Bullseye>
            <Grid gutter=true>
                <GridItem offset={[2]} cols={[2]}>
                    <img src={config.global.error_image_src()} style="transform: scaleY(-1);" alt="Error" />
                </GridItem>
                <GridItem cols={[6]}>
                    <Title>{props.title.clone()}</Title>
                    <Content>
                        if let Some(message)  = &props.message {
                            <p>{ &message }</p>
                            <ExpandableSection>
                                <p>{ &props.err }</p>
                            </ExpandableSection>
                        } else {
                            <p>{ &props.err }</p>
                        }
                    </Content>
                </GridItem>
            </Grid>
        </Bullseye>
    )
}
