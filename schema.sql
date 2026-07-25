-- Install counters for the custom store. The catalogs are regenerated from
-- scratch on every deploy, so counts cannot live in the JSON; the Pages Function
-- folds these rows into the response at request time.
CREATE TABLE IF NOT EXISTS counts (
  plugin    TEXT    NOT NULL,
  version   TEXT    NOT NULL,
  downloads INTEGER NOT NULL DEFAULT 0,
  updates   INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (plugin, version)
);
