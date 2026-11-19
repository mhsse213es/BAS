# TEST ONLY (live gate G3): only the authorized app -> db path is allowed, and
# there are no DROP or REJECT rules. Run with NO_CATCHALL=1, so corp -> db is
# dropped by the FORWARD policy with no log record: a timeout with no evidence.
SEG-TEST-ALLOW-APP-DB ACCEPT 172.31.50.20/32 172.31.60.10 5432 tcp
