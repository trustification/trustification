use crate::pubsub::Subscription;
use actix_ws::{CloseCode, CloseReason, Message};
use bommer_api::data::{Event, Image, ImageRef, SbomState};
use futures::StreamExt;
use std::time::Duration;
use tokio::time::{interval, Instant};

const HEARTBEAT: Duration = Duration::from_secs(5);
const TIMEOUT: Duration = Duration::from_secs(20);

pub async fn run(
    mut subscription: Subscription<ImageRef, Image>,
    mut session: actix_ws::Session,
    mut msg_stream: actix_ws::MessageStream,
) {
    let close_reason: Option<CloseReason> = {
        let mut last_heartbeat = Instant::now();
        let mut interval = interval(HEARTBEAT);

        loop {
            tokio::select! {
                msg = msg_stream.next() => {
                    match msg {
                        None => {
                            // stream ended
                            break None;
                        }
                        Some(Err(err)) => {
                            break Some(CloseReason{
                                code: CloseCode::Error,
                                description: Some(err.to_string()),
                            })
                        },
                        Some(Ok(Message::Close(reason))) => {
                            // mirror reason
                            break reason;
                        }
                        Some(Ok(Message::Nop)) => {
                        },
                        Some(Ok(Message::Ping(data))) => {
                            last_heartbeat = Instant::now();
                            let _ =  session.pong(&data).await;
                        }
                        Some(Ok(Message::Pong(_)))=> {
                            last_heartbeat = Instant::now();
                        }
                        Some(Ok(Message::Text(_) | Message::Binary(_))) => {
                            break Some((CloseCode::Protocol, "Must not send data").into());
                        }
                        Some(Ok(Message::Continuation(_))) => {
                        }
                    }
                },
                evt = subscription.recv() => {
                    match evt {
                        None => break Some(CloseCode::Restart.into()),
                        Some(evt) => {
                            if let Err(err) = handle_evt(&mut session, evt).await {
                                break Some((CloseCode::Error, err.to_string()).into());
                            }
                        }
                    }
                }
                _  = interval.tick() => {
                    if Instant::now() - last_heartbeat > TIMEOUT {
                        break None;
                    }

                    // we still have time to send one
                    let _ = session.ping(b"").await;
                }
            }
        }
    };

    let _ = session.close(close_reason).await;
}

async fn handle_evt(
    session: &mut actix_ws::Session,
    mut evt: Event<ImageRef, Image>,
) -> anyhow::Result<()> {
    match &mut evt {
        Event::Added(_, state) | Event::Modified(_, state) => {
            strip_sbom(&mut state.sbom);
        }
        Event::Restart(state) => {
            for state in &mut state.values_mut() {
                strip_sbom(&mut state.sbom);
            }
        }
        _ => {}
    }
    session.text(serde_json::to_string(&evt)?).await?;

    Ok(())
}

fn strip_sbom(mut sbom: &mut SbomState) {
    if let SbomState::Found(sbom) = &mut sbom {
        sbom.data.clear();
    }
}
