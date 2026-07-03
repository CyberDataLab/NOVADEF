-- NOVADEF Auth Schema
CREATE TABLE IF NOT EXISTS organizations (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    slug TEXT UNIQUE NOT NULL,
    allowed_email_domains TEXT[] NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'ANALYST',
    organization_id TEXT REFERENCES organizations(id),
    created_at TIMESTAMPTZ DEFAULT now()
);

-- Default organization: accepts any @novadef.local email
INSERT INTO organizations (id, name, slug, allowed_email_domains)
VALUES ('org-novadef', 'NOVADEF Lab', 'novadef', ARRAY['novadef.local'])
ON CONFLICT (id) DO NOTHING;

-- Default admin user: admin@novadef.local / novadef2024
-- bcrypt hash of "novadef2024" (cost 12) — generated offline
INSERT INTO users (id, name, email, password_hash, role, organization_id)
VALUES (
    'usr-admin-default',
    'NOVADEF Admin',
    'admin@novadef.local',
    '$2b$12$uTV9AHwVYo2xB49eaHmz8u2sLyo/.eQIF.jPH5bTZOj8zKQoE/oPq',
    'ADMIN',
    'org-novadef'
)
ON CONFLICT (email) DO NOTHING;
