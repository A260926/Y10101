//! 崩溃恢复测试的子进程入口：不是 #[test]，而是一个独立可执行程序。
//! 在“结果计算完成、游标提交之前”被 abort，模拟进程硬退出。
use trustpath_lab::batch;
use trustpath_lab::store::Store;
use trustpath_lab::types::FakeClock;

fn main() {
    let Ok(db) = std::env::var("TRUSTPATH_RESUME_DB") else {
        // `cargo test` 会以 harness=false 拉起本程序；无环境变量时静默退出。
        return;
    };
    let batch_id = std::env::var("TRUSTPATH_RESUME_BATCH").expect("batch");
    std::env::set_var("TRUSTPATH_CRASH_AT_COMMIT", "1");
    let st = Store::open(&db, "test-pass", Box::new(FakeClock::new(1))).unwrap();
    let _ = batch::run_batch(&st, &batch_id);
    // 钩子会在首条结果提交前 abort；走到这里说明钩子失效
    std::process::exit(2);
}
