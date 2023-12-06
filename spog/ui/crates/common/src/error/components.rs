use crate::error::{ApiErrorDetails, ApiErrorKind};
use patternfly_yew::prelude::*;
use spog_model::prelude::{Configuration, DEFAULT_ERROR_IMAGE_SRC};
use std::rc::Rc;
use yew::prelude::*;

#[derive(PartialEq, Properties)]
pub struct ApiErrorProperties {
    #[prop_or("Failure".into())]
    pub title: AttrValue,
    pub error: super::ApiError,
    #[prop_or_default]
    pub message: Option<AttrValue>,
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
            html!(<Error title={props.title.clone()} message={props.message.clone().unwrap_or_else(|| "Error processing request".into() )} err={props.error.to_string()} />)
        }
    }
}

#[derive(PartialEq, Properties)]
pub struct ErrorProperties {
    #[prop_or("Failure".into())]
    pub title: AttrValue,

    #[prop_or_default]
    pub message: Option<AttrValue>,

    #[prop_or_default]
    pub err: String,
}

#[function_component(Error)]
pub fn error(props: &ErrorProperties) -> Html {
    let error_image_src = use_context::<Rc<Configuration>>()
        .and_then(|config| config.global.error_image_src.as_ref().map(|s| s.to_string()))
        .unwrap_or_else(|| DEFAULT_ERROR_IMAGE_SRC.to_string());

    html!(
        <Bullseye>
            <Grid gutter=true>
                <GridItem cols={[2]}>
                    <div style="text-align: center;">
                        <img src={error_image_src} alt="Error" />
                    </div>
                </GridItem>
                <GridItem cols={[10]}>
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
