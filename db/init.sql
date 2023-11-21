CREATE DATABASE pyauth;
\c pyauth

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE users (
    id uuid DEFAULT uuid_generate_v4 (),
    email varchar(128) UNIQUE NOT NULL,
    password bytea NOT NULL,

    PRIMARY KEY (id)
);
