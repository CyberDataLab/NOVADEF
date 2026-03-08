INSERT IGNORE INTO organisations
    (id, name, date_created, date_modified, description, type, nationality, sector, created_by, uuid, local)
VALUES
    (1, 'ADMIN', NOW(), NOW(), 'Default admin organisation', 'ADMIN',
     'Not specified', 'Not specified', 0, '57f2a56a-0018-4f64-96f6-3916a3724253', 1);

INSERT IGNORE INTO users
    (id, password, org_id, server_id, email, autoalert, authkey,
     invited_by, nids_sid, termsaccepted, newsread, role_id,
     change_pw, contactalert, disabled, current_login, last_login,
     date_created, date_modified)
VALUES
    (1,
     '$2y$10$8Yi1l7.K5fdWZobW5DGEne3UdxVBE5HqyDfkMHSXGQTH3Svc5LkKC',
     1, 0, 'admin@admin.test', 0, 'tempkey1234567890tempkey1234567890tempk',
     0, 4000000, 1, 0, 1, 0, 0, 0, 0, 0, NOW(), NOW());
