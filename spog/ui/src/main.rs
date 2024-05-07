#![recursion_limit = "1024"]

mod about;
mod analytics;
mod app;
mod common;
mod console;
mod export;
mod hooks;
mod model;
mod pages;

use browser_panic_hook::{CustomBody, IntoPanicHook};
use wasm_bindgen::prelude::*;

#[cfg(not(debug_assertions))]
const LOG_LEVEL: log::Level = log::Level::Info;
#[cfg(debug_assertions)]
const LOG_LEVEL: log::Level = log::Level::Trace;

fn set_panic_hook() {
    yew::set_custom_panic_hook(
        CustomBody(Box::new(|details| {
            format!(
                r#"
<div class="pf-v5-l-bullseye">
  <div class="pf-v5-l-bullseye__item">
    <div class="pf-v5-c-alert pf-m-danger" aria-label="Application panicked">
      <div class="pf-v5-c-alert__icon">
        <i class="fas fa-fw fa-exclamation-circle" aria-hidden="true"></i>
      </div>
      <p class="pf-v5-c-alert__title">
        <span class="pf-v5-screen-reader">Panic alert:</span>
        Application panicked
      </p>
      <div class="pf-v5-c-alert__description">
        <p>The application failed critically and cannot recover.</p>
        <p>Reason: {message}</p>
      </div>
    </div>
  </div>
</div>
"#,
                message = details.message()
            )
        }))
        .into_panic_hook(),
    );
}

pub fn main() -> Result<(), JsValue> {
    wasm_logger::init(wasm_logger::Config::new(LOG_LEVEL));
    set_panic_hook();
    yew::Renderer::<app::Application>::new().render();
    Ok(())
}
