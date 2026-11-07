-- 0036: 记录上一次检测「跳过了多少文件、有多少基准过期」（台账 C13 / C7）。
--
-- 为什么必须落库而不是只在检测响应里返回：在途 PR 期间文件被预约占用，判定
-- 按层 4 整批跳过——页面于是显示 0 条发现，与「刚检过、确实干净」无法区分；
-- 而检测响应是一次性的，刷新页面就看不见了。把两个计数写进账号心跳，才能
-- 让「这轮跳过了 337 个文件」和「这轮查了 337 个文件、没问题」在页面上永远
-- 是两句话。
--
-- 默认 0 而不是 NULL：老账号从没跑过检测时 0 与「没有跳过」同义；页面另有
-- last_drift_check_at 为空来表达「从未检测」，两个事实分开存。
ALTER TABLE aws_account_config
    ADD COLUMN IF NOT EXISTS last_drift_skipped_files INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS last_drift_stale_files INTEGER NOT NULL DEFAULT 0;
