CREATE TABLE IF NOT EXISTS secrets
(
    id         TEXT   NOT NULL,
    vgid       TEXT   NOT NULL,
    name       TEXT   NOT NULL,
    digits     INT    NOT NULL,
    counter    INT    NOT NULL,
    algorithm  TEXT   NOT NULL,
    period     INT    NOT NULL,
    issuer     TEXT   NOT NULL,
    deleted    INT    NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    PRIMARY KEY (id)
);

CREATE INDEX idx_vgid_deleted_created_at ON secrets (vgid, deleted, created_at);

CREATE TABLE IF NOT EXISTS secrets_history
(
    id         TEXT   NOT NULL,
    secret_id  TEXT   NOT NULL,
    name       TEXT   NOT NULL,
    digits     INT    NOT NULL,
    counter    INT    NOT NULL,
    algorithm  TEXT   NOT NULL,
    period     INT    NOT NULL,
    issuer     TEXT   NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    PRIMARY KEY (id)
);

CREATE INDEX idx_secret_id_created_at ON secrets_history (secret_id, created_at);

CREATE TABLE IF NOT EXISTS secrets_origin_data
(
    secret_id   TEXT   NOT NULL,
    name        TEXT   NOT NULL,
    origin_data TEXT   NOT NULL,
    created_at  BIGINT NOT NULL,
    PRIMARY KEY (secret_id)
);

CREATE TABLE IF NOT EXISTS vgroup
(
    id         TEXT   NOT NULL,
    name       TEXT   NOT NULL,
    parent     TEXT   NOT NULL,
    gtype      INT    NOT NULL,
    deleted    INT    NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    PRIMARY KEY (id)
);
