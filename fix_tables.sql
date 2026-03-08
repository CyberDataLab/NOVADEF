-- Tablas faltantes de migraciones MISP 2.4.177

CREATE TABLE IF NOT EXISTS `no_acl_correlations` (
  `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT,
  `attribute_id` int(10) UNSIGNED NOT NULL,
  `a_attribute_id` int(10) UNSIGNED NOT NULL,
  `event_id` int(10) UNSIGNED NOT NULL,
  `a_event_id` int(10) UNSIGNED NOT NULL,
  `value_id` int(10) UNSIGNED NOT NULL,
  PRIMARY KEY (`id`),
  INDEX `event_id` (`event_id`),
  INDEX `a_event_id` (`a_event_id`),
  INDEX `attribute_id` (`attribute_id`),
  INDEX `a_attribute_id` (`a_attribute_id`),
  INDEX `value_id` (`value_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `default_correlations` (
  `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT,
  `attribute_id` int(10) UNSIGNED NOT NULL,
  `object_id` int(10) UNSIGNED NOT NULL,
  `event_id` int(10) UNSIGNED NOT NULL,
  `org_id` int(10) UNSIGNED NOT NULL,
  `distribution` tinyint(4) NOT NULL,
  `object_distribution` tinyint(4) NOT NULL,
  `event_distribution` tinyint(4) NOT NULL,
  `sharing_group_id` int(10) UNSIGNED NOT NULL DEFAULT 0,
  `object_sharing_group_id` int(10) UNSIGNED NOT NULL DEFAULT 0,
  `event_sharing_group_id` int(10) UNSIGNED NOT NULL DEFAULT 0,
  `a_attribute_id` int(10) UNSIGNED NOT NULL,
  `a_object_id` int(10) UNSIGNED NOT NULL,
  `a_event_id` int(10) UNSIGNED NOT NULL,
  `a_org_id` int(10) UNSIGNED NOT NULL,
  `a_distribution` tinyint(4) NOT NULL,
  `a_object_distribution` tinyint(4) NOT NULL,
  `a_event_distribution` tinyint(4) NOT NULL,
  `a_sharing_group_id` int(10) UNSIGNED NOT NULL DEFAULT 0,
  `a_object_sharing_group_id` int(10) UNSIGNED NOT NULL DEFAULT 0,
  `a_event_sharing_group_id` int(10) UNSIGNED NOT NULL DEFAULT 0,
  `value_id` int(10) UNSIGNED NOT NULL,
  PRIMARY KEY (`id`),
  INDEX `event_id` (`event_id`),
  INDEX `attribute_id` (`attribute_id`),
  INDEX `object_id` (`object_id`),
  INDEX `org_id` (`org_id`),
  INDEX `a_event_id` (`a_event_id`),
  INDEX `a_attribute_id` (`a_attribute_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `correlation_values` (
  `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT,
  `value` text NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `correlation_exclusions` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `value` text NOT NULL,
  `from_org` int(11) DEFAULT NULL,
  `comment` text,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `over_correlating_values` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `value` text NOT NULL,
  `occurrence` int(11) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `cryptographic_keys` (
  `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT,
  `parent_type` varchar(255) NOT NULL DEFAULT '',
  `parent_id` int(10) UNSIGNED NOT NULL DEFAULT 0,
  `type` varchar(255) NOT NULL DEFAULT '',
  `fingerprint` varchar(255) NOT NULL DEFAULT '',
  `data` longtext DEFAULT NULL,
  `revoked` tinyint(1) NOT NULL DEFAULT 0,
  `expires_at` int(10) UNSIGNED DEFAULT NULL,
  `created_at` int(10) UNSIGNED NOT NULL DEFAULT 0,
  `updated_at` int(10) UNSIGNED NOT NULL DEFAULT 0,
  `uuid` varchar(36) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `access_logs` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) NOT NULL,
  `org_id` int(11) NOT NULL,
  `authkey_id` int(11) DEFAULT NULL,
  `ip` varchar(45) DEFAULT NULL,
  `request_method` varchar(10) DEFAULT NULL,
  `target_org_id` int(11) DEFAULT NULL,
  `action` varchar(20) DEFAULT NULL,
  `model` varchar(80) DEFAULT NULL,
  `model_id` int(11) DEFAULT NULL,
  `model_title` varchar(255) DEFAULT NULL,
  `target_id` int(11) DEFAULT NULL,
  `request_id` varchar(36) DEFAULT NULL,
  `ip_src` varchar(45) DEFAULT NULL,
  `returncode` int(11) DEFAULT NULL,
  `request` text,
  `response` longtext,
  `saved` tinyint(1) NOT NULL DEFAULT 0,
  `created` datetime NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `audit_logs` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) NOT NULL,
  `org_id` int(11) NOT NULL,
  `authkey_id` int(11) DEFAULT NULL,
  `ip` varchar(45) DEFAULT NULL,
  `action` varchar(20) DEFAULT NULL,
  `model` varchar(80) DEFAULT NULL,
  `model_id` int(11) DEFAULT NULL,
  `model_title` varchar(255) DEFAULT NULL,
  `event_id` int(11) DEFAULT NULL,
  `change` longtext DEFAULT NULL,
  `created` datetime NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `workflow_blueprints` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `uuid` varchar(36) NOT NULL,
  `name` varchar(191) NOT NULL DEFAULT '',
  `description` text NOT NULL,
  `timestamp` int(11) NOT NULL DEFAULT 0,
  `data` longtext DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uuid` (`uuid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `workflows` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `uuid` varchar(36) NOT NULL,
  `name` varchar(191) NOT NULL DEFAULT '',
  `description` text NOT NULL,
  `timestamp` int(11) NOT NULL DEFAULT 0,
  `enabled` tinyint(1) NOT NULL DEFAULT 0,
  `trigger_id` varchar(128) NOT NULL DEFAULT '',
  `debug_enabled` tinyint(1) NOT NULL DEFAULT 0,
  `data` longtext DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uuid` (`uuid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `sharing_group_blueprints` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `uuid` varchar(36) NOT NULL,
  `name` varchar(191) NOT NULL DEFAULT '',
  `description` text NOT NULL,
  `timestamp` int(11) NOT NULL DEFAULT 0,
  `conditions` longtext NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uuid` (`uuid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Actualizar db_version para que MISP no intente re-ejecutar migraciones ya aplicadas
INSERT INTO `system_settings` (`setting`, `value`) VALUES ('db_version', '88')
  ON DUPLICATE KEY UPDATE `value` = '88';

SELECT COUNT(*) AS total_tables FROM information_schema.tables WHERE table_schema = 'misp';
SELECT `setting`, `value` FROM `system_settings` WHERE `setting` = 'db_version';
