-- A peer-range approval for a hostname is not an approval to bypass that
-- hostname with a literal IP. Direct IP/CIDR use requires a separate intent.
ALTER TABLE campaign_network_rules
    ADD COLUMN IF NOT EXISTS allow_direct BOOLEAN NOT NULL DEFAULT FALSE;
