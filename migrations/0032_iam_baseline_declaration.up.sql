-- 0032: 声明快照（phase4-drift-design.md §2 / §5）。
-- 漂移判定的基准是「上次声明的意图」，不是「上次库存」，也不是「main 上
-- 的文件内容」：前者会把自己 apply 的变更算成漂移，后者隔着 state 和
-- apply 两层，看不到线上实态。发布基线时把归一化后的资源属性落库，同步
-- 结束后与库存比对即为语义漂移。
--
--   resource_key: role:foo / policy:bar / role:foo:inline:baz /
--                 attachment:role:foo:arn / membership:group:g
--   file_key:     role-foo（与 publish_reservation.file_key 同源，不含 .tf）
--   attributes:   归一化属性 JSON（键序固定、策略文档语义归一）
--   content_blob_sha: 声明落库时该文件的 git blob SHA；检测时用
--                 TerraformFileMeta 比对 main 现文件，不一致即
--                 baseline_stale（有人绕过基线改了 tf 文件），而不是漂移。
--
-- 当前生效的声明用部分唯一索引保证一资源一条；被新发布取代的行保留
-- （superseded_at 非空）用于追责与回溯，不参与比对。
CREATE TABLE iam_baseline_declaration (
    id               BIGSERIAL PRIMARY KEY,
    account_id       BIGINT NOT NULL,
    aws_account_id   TEXT NOT NULL,
    publication_id   BIGINT,
    ticket_id        BIGINT,
    sync_run_id      BIGINT,
    resource_key     TEXT NOT NULL,
    file_key         TEXT NOT NULL,
    kind             TEXT NOT NULL,
    name             TEXT NOT NULL,
    attributes       JSONB NOT NULL DEFAULT '{}'::jsonb,
    content_blob_sha TEXT NOT NULL DEFAULT '',
    declared_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    superseded_at    TIMESTAMPTZ
);

-- 同一账号同一资源只有一条「当前」声明。
CREATE UNIQUE INDEX iam_baseline_declaration_current
    ON iam_baseline_declaration (account_id, resource_key)
    WHERE superseded_at IS NULL;

-- 按发布/工单回溯：某次发布声明了哪些资源。
CREATE INDEX iam_baseline_declaration_publication_idx
    ON iam_baseline_declaration (publication_id)
    WHERE publication_id IS NOT NULL;

CREATE INDEX iam_baseline_declaration_file_idx
    ON iam_baseline_declaration (account_id, file_key)
    WHERE superseded_at IS NULL;
