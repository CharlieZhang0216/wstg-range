CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    password_md5 TEXT NOT NULL
);

INSERT INTO users (email, role, password_md5) VALUES
    ('admin@acme.internal', 'admin', '5f4dcc3b5aa765d61d8327deb882cf99'),
    ('alice@acme.internal', 'user',  'e10adc3949ba59abbe56e057f20f883e'),
    ('bob@acme.internal',   'user',  '25d55ad283aa400af464c76d713c07ad');

CREATE TABLE IF NOT EXISTS api_keys (
    id SERIAL PRIMARY KEY,
    owner TEXT,
    key TEXT
);

INSERT INTO api_keys (owner, key) VALUES
    ('portal', 'ak_live_7f3c9d21e8b44a0f9c6d5e2b1a09f8e7');