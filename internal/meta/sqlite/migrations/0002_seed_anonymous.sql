-- 0002_seed_anonymous: the built-in anonymous subject (ADR 0001, ADR 0004).
--
-- Every request with no credentials resolves to this row, so it is seeded
-- rather than created on demand: there is exactly one authorization path, and
-- a missing row would force a special case into it. It holds no bindings, so
-- anonymous access is off until an operator grants it -- off because nothing
-- was granted, not because a branch skipped the check.
--
-- The identifier is a fixed word rather than a generated one because bindings
-- reference it: a value that differed between deployments would make an
-- anonymous grant unportable.
--
-- The store refuses to delete this subject; disabling it is how an operator
-- turns anonymous access off wholesale.
INSERT INTO subjects (id, name, kind, disabled, created_at)
VALUES ('anonymous', 'anonymous', 'anonymous', 0, NULL)
ON CONFLICT (name) DO NOTHING;
