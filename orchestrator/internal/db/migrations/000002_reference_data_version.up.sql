-- Reference-data (seed) version, kept separate from schema_migrations (H1 spec 3).
CREATE TABLE reference_data_version (
    id int PRIMARY KEY CHECK (id = 1),
    version int NOT NULL,
    applied_at timestamptz NOT NULL
);
