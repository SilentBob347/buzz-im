-- Durable proof that an authorized audio attempt became peer-visible.
-- `active` remains authorization for an attempt, never proof of presence.

ALTER TABLE audio_session_admissions
    ADD COLUMN visibility_observed_at TIMESTAMPTZ;

ALTER TABLE audio_session_admissions
    DROP CONSTRAINT audio_session_admissions_state,
    DROP CONSTRAINT audio_session_admissions_claim;

ALTER TABLE audio_session_admissions
    ADD CONSTRAINT audio_session_admissions_state
        CHECK (state IN ('reserved', 'active', 'visible', 'aborted', 'finished')),
    ADD CONSTRAINT audio_session_admissions_claim CHECK (
        (state = 'reserved'
            AND claimant_id IS NOT NULL
            AND attachment_generation = 0
            AND claim_expires_at IS NOT NULL)
        OR
        (state IN ('active', 'visible', 'finished')
            AND claimant_id IS NOT NULL
            AND attachment_generation > 0
            AND claim_expires_at IS NOT NULL)
        OR
        (state = 'aborted')
    ),
    ADD CONSTRAINT audio_session_admissions_visibility CHECK (
        state <> 'visible' OR visibility_observed_at IS NOT NULL
    );

DROP INDEX idx_audio_session_admissions_cleanup_requested;
CREATE INDEX idx_audio_session_admissions_cleanup_requested
    ON audio_session_admissions (community_id, cleanup_requested_at)
    WHERE cleanup_requested_at IS NOT NULL
      AND state IN ('reserved', 'active', 'visible');

-- Mixed-version relays must not retain the former active -> finished path.
-- An older binary consequently fails closed after this migration instead of
-- treating an authorization receipt as proof that visibility occurred.
CREATE FUNCTION audio_admission_visibility_transition_guard()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.state = OLD.state THEN
        RETURN NEW;
    END IF;
    IF (OLD.state = 'reserved' AND NEW.state IN ('active', 'aborted'))
       OR (OLD.state = 'active' AND NEW.state IN ('visible', 'aborted'))
       OR (OLD.state = 'visible' AND NEW.state IN ('finished', 'aborted')) THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'invalid audio admission state transition';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audio_admission_visibility_transition_guard
    BEFORE UPDATE OF state ON audio_session_admissions
    FOR EACH ROW EXECUTE FUNCTION audio_admission_visibility_transition_guard();
