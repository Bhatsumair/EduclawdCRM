-- Educlawd CRM · MySQL schema (Railway)
-- Run once against your Railway MySQL database.

SET NAMES utf8mb4;

-- Team accounts (admin + members)
CREATE TABLE IF NOT EXISTS crm_users (
  id             VARCHAR(40)  NOT NULL,
  username       VARCHAR(64)  NOT NULL,
  name           VARCHAR(150) NOT NULL,
  role           ENUM('admin','member') NOT NULL DEFAULT 'member',
  active         TINYINT(1)   NOT NULL DEFAULT 1,
  password_hash  VARCHAR(255) NOT NULL,          -- bcrypt hash, never plain text
  created_at     DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  created_by     VARCHAR(150) NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_crm_users_username (username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Login sessions (token sent by the app as p_token)
CREATE TABLE IF NOT EXISTS crm_sessions (
  token          CHAR(48)    NOT NULL,
  user_id        VARCHAR(40) NOT NULL,
  created_at     DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_used_at   DATETIME    NULL,
  PRIMARY KEY (token),
  KEY idx_crm_sessions_user (user_id),
  CONSTRAINT fk_crm_sessions_user
    FOREIGN KEY (user_id) REFERENCES crm_users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- One row per school. The whole school object (contacts, timeline, tasks,
-- deal, stage, etc.) is stored as JSON, exactly as the app produces it.
CREATE TABLE IF NOT EXISTS crm_docs (
  id             VARCHAR(64) NOT NULL,
  owner_id       VARCHAR(40) NOT NULL,
  data           JSON        NOT NULL,
  created_at     DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at     DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_crm_docs_owner (owner_id),
  CONSTRAINT fk_crm_docs_owner
    FOREIGN KEY (owner_id) REFERENCES crm_users (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- First admin account. Replace the hash with a real bcrypt hash first:
--   node -e "console.log(require('bcryptjs').hashSync('YOUR_PASSWORD',10))"
-- (install once with: npm i bcryptjs)
-- INSERT INTO crm_users (id, username, name, role, active, password_hash, created_by)
-- VALUES ('u-admin', 'educlawdcrm', 'Auqib Bhat', 'admin', 1, 'PASTE_BCRYPT_HASH_HERE', 'setup');
