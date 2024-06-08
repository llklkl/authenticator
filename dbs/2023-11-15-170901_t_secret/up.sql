CREATE TABLE secrets
(
    id          TEXT   NOT NULL,
    wid         TEXT   NOT NULL,
    name        TEXT   NOT NULL,
    digits      INT    NOT NULL,
    counter     INT    NOT NULL,
    algorithm   TEXT   NOT NULL,
    period      INT    NOT NULL,
    issuer      TEXT   NOT NULL,
    origin_url  TEXT   NOT NULL,
    create_at   BIGINT NOT NULL,
    update_at   BIGINT NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE secrets_recycle
(
    id          TEXT   NOT NULL,
    secret_id   TEXT   NOT NULL,
    name        TEXT   NOT NULL,
    origin_url  TEXT   NOT NULL,
    create_at   BIGINT NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE workspace
(
    id          TEXT   NOT NULL,
    name        TEXT   NOT NULL,
    create_at   BIGINT NOT NULL,
    update_at   BIGINT NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE preference
(
    id         INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    db_version BIGINT NOT NULL
);
