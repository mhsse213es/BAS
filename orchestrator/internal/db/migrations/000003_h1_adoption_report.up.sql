-- Objects found outside the baseline when a pre-H1 install was adopted (H1
-- spec 4.3). Kept, never dropped automatically; empty on fresh installs.
CREATE TABLE h1_adoption_report (
    object text NOT NULL,
    kind text NOT NULL,
    detail text NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT now()
);
