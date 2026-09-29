use serde::Serialize;

#[derive(Debug)]
pub enum Error {
    Db(rusqlite::Error),
    BadRequest(String),
    NotFound(String),
    Conflict(String),
    Crypto(String),
    Internal(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Db(e) => write!(f, "数据库错误: {e}"),
            Error::BadRequest(m) => write!(f, "{m}"),
            Error::NotFound(m) => write!(f, "{m}"),
            Error::Conflict(m) => write!(f, "{m}"),
            Error::Crypto(m) => write!(f, "{m}"),
            Error::Internal(m) => write!(f, "{m}"),
        }
    }
}
impl std::error::Error for Error {}

impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        // SQLite 唯一约束 -> 冲突；忙等 -> 版本冲突
        match &e {
            rusqlite::Error::SqliteFailure(inner, _) => {
                if inner.extended_code == 2067
                    || inner.code == rusqlite::ErrorCode::ConstraintViolation
                {
                    Error::Conflict("幂等键或内容冲突".into())
                } else if inner.code == rusqlite::ErrorCode::DatabaseBusy {
                    Error::Conflict("并发版本冲突，请重试".into())
                } else {
                    Error::Db(e)
                }
            }
            _ => Error::Db(e),
        }
    }
}

#[derive(Serialize)]
pub struct ApiError {
    pub error: String,
    pub code: &'static str,
}

impl Error {
    pub fn status_and_body(&self) -> (u16, ApiError) {
        match self {
            Error::BadRequest(m) => (
                400,
                ApiError {
                    error: m.clone(),
                    code: "bad_request",
                },
            ),
            Error::NotFound(m) => (
                404,
                ApiError {
                    error: m.clone(),
                    code: "not_found",
                },
            ),
            Error::Conflict(m) => (
                409,
                ApiError {
                    error: m.clone(),
                    code: "conflict",
                },
            ),
            Error::Crypto(m) => (
                400,
                ApiError {
                    error: m.clone(),
                    code: "crypto",
                },
            ),
            Error::Db(_) | Error::Internal(_) => (
                500,
                ApiError {
                    error: "内部错误".into(),
                    code: "internal",
                },
            ),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
