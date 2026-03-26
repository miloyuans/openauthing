CREATE TABLE cas_tickets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ticket VARCHAR(64) NOT NULL,
    type VARCHAR(8) NOT NULL,
    service VARCHAR(2048),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_id UUID NOT NULL REFERENCES auth_sessions(id) ON DELETE CASCADE,
    parent_ticket_id UUID REFERENCES cas_tickets(id) ON DELETE SET NULL,
    consumed_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT cas_tickets_type_check CHECK (type IN ('TGT', 'ST', 'PT', 'PGT'))
);

CREATE UNIQUE INDEX cas_tickets_ticket_uidx ON cas_tickets (ticket);
CREATE INDEX cas_tickets_session_id_type_idx ON cas_tickets (session_id, type, created_at DESC);
CREATE INDEX cas_tickets_parent_ticket_id_idx ON cas_tickets (parent_ticket_id);
CREATE INDEX cas_tickets_user_id_type_idx ON cas_tickets (user_id, type, created_at DESC);
