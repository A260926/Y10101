use std::sync::Arc;
use trustpath_lab::log::Journal;
use trustpath_lab::seed;
use trustpath_lab::store::Store;
use trustpath_lab::types::SystemClock;
use trustpath_lab::web::{serve, AppState};

struct Args {
    listen: String,
    db: String,
    passphrase: String,
    no_seed: bool,
}

fn parse_args() -> Args {
    let mut args = Args {
        listen: "127.0.0.1:5231".into(),
        db: "trustpath-lab.db".into(),
        passphrase: "local-demo-passphrase".into(),
        no_seed: false,
    };
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--listen" => args.listen = it.next().unwrap_or(args.listen),
            "--db" => args.db = it.next().unwrap_or(args.db),
            "--passphrase" => args.passphrase = it.next().unwrap_or(args.passphrase),
            "--no-seed" => args.no_seed = true,
            "-h" | "--help" => {
                println!(
                    "签名信任路径实验台\n\
                     USAGE: trustpath-lab [--listen 127.0.0.1:5231] [--db trustpath-lab.db] \
                     [--passphrase <本地演示口令>] [--no-seed]"
                );
                std::process::exit(0);
            }
            other => eprintln!("忽略未知参数: {other}"),
        }
    }
    args
}

fn main() {
    let args = parse_args();
    let store =
        Store::open(&args.db, &args.passphrase, Box::new(SystemClock)).expect("打开 SQLite 失败");
    if !args.no_seed && !seed::is_seeded(&store) {
        seed::seed(&store).expect("预置演示数据失败");
        println!("已预置演示场景（制品 A 在 T9 与 T8 给出不同但可解释的结论）");
    }
    let state = Arc::new(AppState {
        store,
        log: Journal::new(),
    });
    state.log.log("info", "startup", &format!("db={}", args.db));
    println!("签名信任路径实验台已启动： http://{}/", args.listen);
    serve(&args.listen, state).expect("HTTP 服务退出");
}
