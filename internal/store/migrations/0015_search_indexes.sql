-- Search compares lower(key) and DNS filters glob lower(qname); these
-- expression indexes let SQLite use an index for the prefix side instead of
-- scanning every entity or lookup.
CREATE INDEX entities_kind_lower_key ON entities (kind, lower(key));
CREATE INDEX dns_lower_qname ON dns (lower(qname), ts);
