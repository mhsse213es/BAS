# TEST ONLY (live gate G1): deliberately opens corp -> db:5432 so the lab can
# prove that an opened prohibited path is graded FAIL. Never used in normal runs.
SEG-TEST-OPEN-CORP-DB ACCEPT 172.31.10.10/32 172.31.60.10 5432 tcp
