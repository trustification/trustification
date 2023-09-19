use gloo_net::http::Response;

// if the response is [`Response::ok`], then return `Ok`, otherwise return `Err`.
pub fn check_status(response: Response) -> Result<Response, Response> {
    if response.ok() {
        Ok(response)
    } else {
        Err(response)
    }
}

pub trait CheckStatus: Sized {
    fn check_status(self) -> Result<Self, String>;
}

impl CheckStatus for Response {
    fn check_status(self) -> Result<Self, String> {
        check_status(self).map_err(|err| format!("{}: {}", err.status(), err.status_text()))
    }
}
