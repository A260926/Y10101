//! 结构化日志：白名单字段，绝不记录请求体/私钥信封。
//! 同时保留环形缓冲供 /api/logs 查看（只含 kid 等公开标识）。

use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct Journal {
    buffer: Arc<Mutex<Vec<String>>>,
}

impl Journal {
    pub fn new() -> Self {
        Self {
            buffer: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn log(&self, level: &str, event: &str, detail: &str) {
        // 只允许 kid/seq/批 id 等公开标识进入 detail；调用方负责。
        let line = format!("[{level}] {event} {detail}");
        eprintln!("{line}");
        let mut buf = self.buffer.lock().unwrap();
        buf.push(line);
        if buf.len() > 500 {
            buf.remove(0);
        }
    }

    pub fn snapshot(&self) -> Vec<String> {
        self.buffer.lock().unwrap().clone()
    }
}

impl Default for Journal {
    fn default() -> Self {
        Self::new()
    }
}
