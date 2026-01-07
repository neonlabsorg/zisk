use std::thread::JoinHandle;

use serde::{Deserialize, Serialize};

use crate::{ServerConfig, ZiskBaseResponse, ZiskResponse};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ZiskShutdownRequest;

#[derive(Serialize, Deserialize, Debug)]
pub struct ZiskShutdownResponse {
    #[serde(flatten)]
    pub base: ZiskBaseResponse,
}

pub struct ZiskServiceShutdownHandler;

impl ZiskServiceShutdownHandler {
    pub fn handle(
        config: &ServerConfig,
        _payload: ZiskShutdownRequest,
    ) -> (ZiskResponse, Option<JoinHandle<()>>) {
        (
            ZiskResponse::ZiskShutdownResponse(ZiskShutdownResponse {
                base: ZiskBaseResponse {
                    cmd: "shutdown".to_string(),
                    result: crate::ZiskCmdResult::Ok,
                    code: crate::ZiskResultCode::Ok,
                    msg: None,
                    node: config.world_rank,
                },
            }),
            None,
        )
    }
}
