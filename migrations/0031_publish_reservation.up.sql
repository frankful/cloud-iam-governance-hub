-- 0031: 文件级发布预约（phase4-drift-design.md §2 / §4）。
-- 每账号每文件至多一个开放 PR 源：工单与基线发布前把要写的文件集合
-- 原子预约，DB 部分唯一索引兜住并发抢锁（应用层 check-then-write 的
-- 竞态窗口由 ON CONFLICT 消除）。
--   channel: 'ticket' | 'baseline'
--   ref:     ticket_no | publication_id::text
--   status:  OPEN（PR 在途）→ MERGED（已合并，等同步确认后释放）
--            → RELEASED；REJECTED/CLOSED/PUBLISH_FAILED 直接 RELEASED。
-- 工单侧无 TTL（拍板：挂死走管理员手动释放）；基线侧由 SweepStale 按
-- TTL 回收。file_key 是不含 .tf 的 bundle 内文件名（role-foo），加
-- account_id 后跨账号天然唯一，两边发布方都能直接推导，不依赖仓库
-- 路径模板。
CREATE TABLE publish_reservation (
    id          BIGSERIAL PRIMARY KEY,
    account_id  BIGINT NOT NULL,
    file_key    TEXT NOT NULL,
    channel     VARCHAR(16) NOT NULL CHECK (channel IN ('ticket', 'baseline')),
    ref         TEXT NOT NULL,
    status      VARCHAR(16) NOT NULL DEFAULT 'OPEN'
                CHECK (status IN ('OPEN', 'MERGED', 'RELEASED')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    released_at TIMESTAMPTZ,
    -- RELEASED 必须有释放时间；OPEN（在途）与 MERGED（已合并、等同步确认）
    -- 都还没释放，保持 NULL。注意不能写成 (status='OPEN') = (released_at IS
    -- NULL)：MERGED 态会因 released_at 为 NULL 而违反约束。
    CHECK ((status = 'RELEASED') = (released_at IS NOT NULL))
);

-- 同一账号同一文件至多一条开放预约；ON CONFLICT 推断用。
CREATE UNIQUE INDEX publish_reservation_open_unique
    ON publish_reservation (account_id, file_key)
    WHERE status = 'OPEN';

-- 按持有者（工单号 / 台账 ID）释放与查询。
CREATE INDEX publish_reservation_ref_idx
    ON publish_reservation (channel, ref)
    WHERE status <> 'RELEASED';
