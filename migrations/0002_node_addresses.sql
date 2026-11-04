ALTER TABLE nodes ADD COLUMN ipv4 TEXT;
ALTER TABLE nodes ADD COLUMN ipv6 TEXT;

-- Preserve addresses already observed by older clients and Workers.
UPDATE nodes SET ipv4=ip WHERE ip IS NOT NULL AND instr(ip, ':')=0;
UPDATE nodes SET ipv6=ip WHERE ip IS NOT NULL AND instr(ip, ':')>0;
