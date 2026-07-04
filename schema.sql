-- =====================================================================
-- SECR4483 SECURE PROGRAMMING: ALTERNATIVE ASSESSMENT
-- MIGRATED (POST-REMEDIATION) DB SCHEMA: medic_vault_db
--
-- Change vs. the audited legacy schema:
--   staff_credentials.auth_key_hash  (VARCHAR, legacy MD5)
--     -->  staff_credentials.password_hash (VARCHAR(255), Argon2id)
--   Seed credentials re-hashed with PASSWORD_ARGON2ID.
-- patient_records is preserved (repeating-term rows retained for the
-- crypto-analysis narrative).
-- =====================================================================
CREATE DATABASE IF NOT EXISTS `medic_vault_db`
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;
USE `medic_vault_db`;

-- ---------------------------------------------------------------------
-- TABLE: patient_records  (used by search.php)
-- ---------------------------------------------------------------------
DROP TABLE IF EXISTS `patient_records`;
CREATE TABLE `patient_records` (
    `id`               INT AUTO_INCREMENT PRIMARY KEY,
    `name`             VARCHAR(255) NOT NULL,
    `illness_history`  TEXT NOT NULL,
    `created_at`       TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- TABLE: staff_credentials  (used by auth.php)  -- MIGRATED to Argon2id
-- ---------------------------------------------------------------------
DROP TABLE IF EXISTS `staff_credentials`;
CREATE TABLE `staff_credentials` (
    `id`             INT AUTO_INCREMENT PRIMARY KEY,
    `username`       VARCHAR(100) NOT NULL UNIQUE,
    `password_hash`  VARCHAR(255) NOT NULL,   -- Argon2id PHC string (~97 chars)
    `role`           VARCHAR(50)  NOT NULL,
    `updated_at`     TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =====================================================================
-- SEED DATA
-- =====================================================================
INSERT INTO `patient_records` (`name`, `illness_history`) VALUES
('John Doe',      'DIAGNOSIS: Stage-2 Carcinoma. TREATMENT: Chemotherapy cycle 1. STATUS: Critical.'),
('Jane Smith',    'DIAGNOSIS: Stage-2 Carcinoma. TREATMENT: Radiation therapy. STATUS: Stable.'),
('Robert Thorne', 'DIAGNOSIS: Acute Type-2 Diabetes. TREATMENT: Insulin regimen. STATUS: Managed.'),
('Siti Aminah',   'DIAGNOSIS: Acute Type-2 Diabetes. TREATMENT: Metformin regimen. STATUS: Monitored.');

-- Argon2id-hashed staff credentials (plaintext shown for lab/demo only):
--   dr_faizal   : 'testkey123'
--   dr_sharifah : 'doctorsecret'
INSERT INTO `staff_credentials` (`username`, `password_hash`, `role`) VALUES
('dr_faizal',   '$argon2id$v=19$m=65536,t=4,p=1$UmFnY0NBWERvNE5LTjV5bQ$2KL2Y+jcH1WxvJkxwLpcLz/ttOi1k1prfufNTrKrs28', 'Consultant Physician'),
('dr_sharifah', '$argon2id$v=19$m=65536,t=4,p=1$cHVkNzNUZjNLSWR2R0hmWA$+VJ6HtmrrRr4sSVhM8XOIiE+l3pPptNHgyguOiTEXCQ', 'Chief Medical Officer');

-- =====================================================================
-- END OF SCRIPT
-- =====================================================================
