-- correlations: solo 2 columnas con prefijo 1_
ALTER TABLE `correlations`
  CHANGE `1_event_id`     `a_event_id`     int(10) unsigned NOT NULL DEFAULT 0,
  CHANGE `1_attribute_id` `a_attribute_id` int(10) unsigned NOT NULL DEFAULT 0;

-- default_correlations: 10 columnas con prefijo 1_
ALTER TABLE `default_correlations`
  CHANGE `1_attribute_id`            `a_attribute_id`            int(10) unsigned NOT NULL DEFAULT 0,
  CHANGE `1_object_id`               `a_object_id`               int(10) unsigned NOT NULL DEFAULT 0,
  CHANGE `1_event_id`                `a_event_id`                int(10) unsigned NOT NULL DEFAULT 0,
  CHANGE `1_org_id`                  `a_org_id`                  int(10) unsigned NOT NULL DEFAULT 0,
  CHANGE `1_distribution`            `a_distribution`            tinyint(4) NOT NULL DEFAULT 0,
  CHANGE `1_object_distribution`     `a_object_distribution`     tinyint(4) NOT NULL DEFAULT 0,
  CHANGE `1_event_distribution`      `a_event_distribution`      tinyint(4) NOT NULL DEFAULT 0,
  CHANGE `1_sharing_group_id`        `a_sharing_group_id`        int(10) unsigned NOT NULL DEFAULT 0,
  CHANGE `1_object_sharing_group_id` `a_object_sharing_group_id` int(10) unsigned NOT NULL DEFAULT 0,
  CHANGE `1_event_sharing_group_id`  `a_event_sharing_group_id`  int(10) unsigned NOT NULL DEFAULT 0;
