# Core banking tiering: only the app tier reaches the database, and only on 5432.
SEG-DENY-DB-1 DROP 172.31.10.10/32 172.31.60.10 5432 tcp
SEG-ALLOW-DB-1 ACCEPT 172.31.50.20/32 172.31.60.10 5432 tcp
SEG-DENY-DB-2 DROP 172.31.50.20/32 172.31.60.10 3306 tcp
