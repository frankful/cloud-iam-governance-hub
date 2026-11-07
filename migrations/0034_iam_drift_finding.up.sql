-- 0034: 语义漂移发现（phase4-drift-design.md §2 / §3）。
-- 一条记录 = 某个「已声明资源」与线上实态的一处不一致（或一条基准过期）。
-- 判定基准是 iam_baseline_declaration（已声明的意图），不是上次库存，也不是
-- main 上的文件内容。
--
--   status:  SUSPECT（首轮出现，等确认）
--            OPEN（连续两轮仍在，人工处理）
--            PENDING（变更可能尚未 apply）
--            PENDING_REBASELINE（工单已获批改了该文件，基线该更新）
--            IGNORED（人工忽略）
--   解决不设 status：resolved_at 非空即已解决（自动恢复或人工关闭），
--   避免「状态列」与「时间列」两套事实互相矛盾。
--
-- 唯一索引只约束「未解决」的行：同一账号同一来源同一资源同时只有一条
-- 未解决发现；解决后再次漂移会新开一条，历史自然保留。
CREATE TABLE iam_drift_finding (
    id              BIGSERIAL PRIMARY KEY,
    account_id      BIGINT NOT NULL REFERENCES aws_account(id) ON DELETE CASCADE,
    aws_account_id  TEXT NOT NULL,
    source          TEXT NOT NULL CHECK (source IN ('inventory', 'ci', 'publish')),
    resource_key    TEXT,
    resource_address TEXT,
    kind            TEXT,
    file_key        TEXT,
    change_type     TEXT NOT NULL CHECK (change_type IN (
                        'attribute', 'declared_missing', 'undeclared_extra',
                        'file_conflict', 'baseline_stale')),
    -- [{field, declared, live}]：字段级差异，页面直接渲染，不用再调库存。
    fields          JSONB NOT NULL DEFAULT '[]'::jsonb,
    severity        TEXT NOT NULL DEFAULT 'MEDIUM'
                    CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    status          TEXT NOT NULL DEFAULT 'SUSPECT'
                    CHECK (status IN ('SUSPECT', 'OPEN', 'PENDING',
                                      'PENDING_REBASELINE', 'IGNORED')),
    -- 判定时用的基准发布：追责要能回答「拿哪一版声明比出来的」。
    baseline_publication_id BIGINT,
    summary         TEXT,
    ci_url          TEXT,
    commit_sha      TEXT,
    first_seen_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    occurrences     INT NOT NULL DEFAULT 1,
    resolved_at     TIMESTAMPTZ,
    resolved_by     TEXT,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ON CONFLICT 推断用：表达式必须与这里逐字一致。
CREATE UNIQUE INDEX iam_drift_finding_open_unique
    ON iam_drift_finding (account_id, source,
        COALESCE(resource_key, ''), COALESCE(resource_address, ''))
    WHERE resolved_at IS NULL;

CREATE INDEX iam_drift_finding_account_status_idx
    ON iam_drift_finding (account_id, status)
    WHERE resolved_at IS NULL;

CREATE INDEX iam_drift_finding_file_idx
    ON iam_drift_finding (account_id, file_key)
    WHERE resolved_at IS NULL;

-- 心跳（§8）：没有记录 ≠ 检测在跑。这两个时间戳让页面能区分「干净」与
-- 「根本没检测」——静默失败是最容易被当成健康的故障。
ALTER TABLE aws_account_config
    ADD COLUMN last_drift_check_at TIMESTAMPTZ,
    ADD COLUMN last_drift_clean_at TIMESTAMPTZ;
