-- Purpose metadata: what an application uses a host for, and what denying it
-- would break. This is shown in policy and decision views; it is not used to
-- allow or deny anything.
CREATE TABLE app_purposes (
    id               INTEGER PRIMARY KEY,
    application      TEXT    NOT NULL,
    developer        TEXT    NOT NULL DEFAULT '',
    website          TEXT    NOT NULL DEFAULT '',
    host             TEXT    NOT NULL,
    purpose          TEXT    NOT NULL DEFAULT '',
    deny_consequences TEXT   NOT NULL DEFAULT '',
    source           TEXT    NOT NULL DEFAULT '',
    updated          INTEGER NOT NULL,
    UNIQUE (application, host)
);

CREATE INDEX app_purposes_host ON app_purposes (host);
CREATE INDEX app_purposes_app ON app_purposes (application);
