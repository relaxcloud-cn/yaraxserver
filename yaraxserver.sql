CREATE TYPE source AS ENUM ('official', 'local');
CREATE TYPE sharing AS ENUM ('TLP:Red', 'TLP:Amber+Strict', 'TLP:Amber', 'TLP:Green', 'TLP:Clear');
CREATE TYPE attribute AS ENUM ('white', 'black');

CREATE TABLE yara_file (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    last_modified_time TIMESTAMPTZ NOT NULL,
    version INTEGER DEFAULT 1,
    compiled_data BYTEA,
    description TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

COMMENT ON COLUMN yara_file.id IS '规则文件唯一id';
COMMENT ON COLUMN yara_file.name IS '规则文件名称';
COMMENT ON COLUMN yara_file.last_modified_time IS '规则文件最后修改时间，当包含的规则有修改时，规则文件时间会对应更新';
COMMENT ON COLUMN yara_file.version IS '规则文件版本，每次规则文件包含的规则修改后会自增1';
COMMENT ON COLUMN yara_file.compiled_data IS '编译后的YARA规则二进制数据';
COMMENT ON COLUMN yara_file.description IS '规则文件描述';
COMMENT ON COLUMN yara_file.created_at IS '规则文件创建时间';
COMMENT ON COLUMN yara_file.updated_at IS '规则文件更新时间';

CREATE TABLE yara_rules (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    private BOOL DEFAULT FALSE,
    global BOOL DEFAULT FALSE,
    auth TEXT,
    description TEXT,
    tag TEXT[],
    strings TEXT[],
    condition TEXT,
    last_modified_time TIMESTAMPTZ NOT NULL,
    loading_time TIMESTAMPTZ,
    belonging INTEGER NOT NULL REFERENCES yara_file(id) ON DELETE CASCADE,
    verification BOOL DEFAULT FALSE,
    source source DEFAULT 'local',
    version INTEGER DEFAULT 1,
    sharing sharing DEFAULT 'TLP:Clear',
    grayscale BOOL DEFAULT FALSE,
    attribute attribute DEFAULT 'black',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

COMMENT ON COLUMN yara_rules.id IS '规则id，自增id防止重复';
COMMENT ON COLUMN yara_rules.name IS '规则名称，全局禁止重复';
COMMENT ON COLUMN yara_rules.private IS '是否为 private 规则';
COMMENT ON COLUMN yara_rules.global IS '是否为 global 规则';
COMMENT ON COLUMN yara_rules.auth IS '作者';
COMMENT ON COLUMN yara_rules.description IS '规则描述，用于规则最终展示';
COMMENT ON COLUMN yara_rules.tag IS '标签';
COMMENT ON COLUMN yara_rules.strings IS 'YARA规则的 Strings 部分，换行为切换元素，例如 ["$a = { 63 6f 6e 6e 65 63 74 54 6f 50 72 6f 78 79 4d 61 6e 61 67 65 72 }","$b = { 63 6f 6e 6e 65 63 74 54 6f 44 65 73 74 69 6e 61 74 69 6f 6e }"]';
COMMENT ON COLUMN yara_rules.condition IS 'YARA规则的 condition 部分，例如 Macho and 3 of them';
COMMENT ON COLUMN yara_rules.last_modified_time IS '规则最新修改时间';
COMMENT ON COLUMN yara_rules.loading_time IS '规则加载时间，每次规则重新热加载时需要更新';
COMMENT ON COLUMN yara_rules.belonging IS '规则归属的规则文件ID';
COMMENT ON COLUMN yara_rules.verification IS '校验规则是否合法';
COMMENT ON COLUMN yara_rules.source IS '规则来源，官方或本地';
COMMENT ON COLUMN yara_rules.version IS '规则版本，每次修改后会自增1';
COMMENT ON COLUMN yara_rules.sharing IS 'Traffic Light Protocol (TLP)';
COMMENT ON COLUMN yara_rules.grayscale IS '是否为灰度测试规则，默认为 false';
COMMENT ON COLUMN yara_rules.attribute IS '规则类型，黑名单\白名单';
COMMENT ON COLUMN yara_rules.created_at IS '规则创建时间';
COMMENT ON COLUMN yara_rules.updated_at IS '规则更新时间';

CREATE TABLE yara_rule_history (
    history_id SERIAL PRIMARY KEY,
    rule_id INTEGER NOT NULL REFERENCES yara_rules(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    private BOOL,
    global BOOL,
    auth TEXT,
    description TEXT,
    tag TEXT[],
    strings TEXT[],
    condition TEXT,
    last_modified_time TIMESTAMPTZ NOT NULL,
    loading_time TIMESTAMPTZ,
    belonging INTEGER NOT NULL REFERENCES yara_file(id) ON DELETE CASCADE,
    verification BOOL,
    source source,
    version INTEGER,
    sharing sharing,
    grayscale BOOL,
    attribute attribute,
    changed_at TIMESTAMPTZ DEFAULT NOW(),
    changed_by TEXT
);

COMMENT ON COLUMN yara_rule_history.history_id IS '历史记录ID，自增主键';
COMMENT ON COLUMN yara_rule_history.rule_id IS '对应的规则ID';
COMMENT ON COLUMN yara_rule_history.name IS '规则名称';
COMMENT ON COLUMN yara_rule_history.private IS '是否为 private 规则';
COMMENT ON COLUMN yara_rule_history.global IS '是否为 global 规则';
COMMENT ON COLUMN yara_rule_history.auth IS '作者';
COMMENT ON COLUMN yara_rule_history.description IS '规则描述';
COMMENT ON COLUMN yara_rule_history.tag IS '标签';
COMMENT ON COLUMN yara_rule_history.strings IS 'YARA规则的 Strings 部分';
COMMENT ON COLUMN yara_rule_history.condition IS 'YARA规则的 condition 部分';
COMMENT ON COLUMN yara_rule_history.last_modified_time IS '规则最新修改时间';
COMMENT ON COLUMN yara_rule_history.loading_time IS '规则加载时间';
COMMENT ON COLUMN yara_rule_history.belonging IS '规则归属的规则文件ID';
COMMENT ON COLUMN yara_rule_history.verification IS '校验规则是否合法';
COMMENT ON COLUMN yara_rule_history.source IS '规则来源';
COMMENT ON COLUMN yara_rule_history.version IS '规则版本';
COMMENT ON COLUMN yara_rule_history.sharing IS 'Traffic Light Protocol (TLP)';
COMMENT ON COLUMN yara_rule_history.grayscale IS '是否为灰度测试规则';
COMMENT ON COLUMN yara_rule_history.attribute IS '规则类型，黑名单\白名单';
COMMENT ON COLUMN yara_rule_history.changed_at IS '记录更改时间';
COMMENT ON COLUMN yara_rule_history.changed_by IS '记录更改人';

CREATE OR REPLACE FUNCTION log_yara_rule_history()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO yara_rule_history (
        rule_id, name, private, global, auth, description, tag, strings, condition,
        last_modified_time, loading_time, belonging, verification, source, version,
        sharing, grayscale, attribute, changed_at, changed_by
    ) VALUES (
        NEW.id, NEW.name, NEW.private, NEW.global, NEW.auth, NEW.description, NEW.tag,
        NEW.strings, NEW.condition, NEW.last_modified_time, NEW.loading_time,
        NEW.belonging, NEW.verification, NEW.source, NEW.version, NEW.sharing,
        NEW.grayscale, NEW.attribute, NOW(), 'system'
    );
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_yara_rules_history
BEFORE UPDATE ON yara_rules
FOR EACH ROW
EXECUTE FUNCTION log_yara_rule_history();