DELETE FROM sessions;

ALTER TABLE sessions
    ALTER COLUMN xsrf TYPE bytea USING xsrf::bytea;
