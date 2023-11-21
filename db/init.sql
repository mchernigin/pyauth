CREATE DATABASE pyauth;
\c pyauth

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE users (
    id uuid DEFAULT uuid_generate_v4 (),
    email varchar(128) NOT NULL,
    password_hash varchar(128) NOT NULL,

    PRIMARY KEY (id)
);
