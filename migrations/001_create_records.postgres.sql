-- v1: the API's eight collections are stored as typed records in one table.
CREATE TABLE IF NOT EXISTS records (
    record_order BIGSERIAL NOT NULL UNIQUE,
    kind TEXT NOT NULL,
    id TEXT NOT NULL,
    body TEXT NOT NULL,
    PRIMARY KEY (kind, id)
);
CREATE INDEX IF NOT EXISTS records_kind_order_idx ON records (kind, record_order);
