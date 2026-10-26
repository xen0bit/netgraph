-- New-device alerts fire the first time a device uses an address on the LAN,
-- recorded as the device's "joined" attribute. Mark every device that already
-- has an address as joined, so an upgrade does not alert on the whole network.
UPDATE entities
SET attrs = json_set(CASE WHEN json_valid(attrs) THEN attrs ELSE '{}' END, '$.joined', CAST(first_seen AS TEXT))
WHERE kind = 'device' AND id IN (SELECT src FROM facts WHERE rel = 'has_ip');
