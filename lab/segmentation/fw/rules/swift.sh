# SWIFT isolation: corporate IT and SWIFT must not reach each other.
SEG-DENY-SWIFT-1 DROP 172.31.10.10/32 172.31.20.10 8443 tcp
SEG-DENY-SWIFT-2 DROP 172.31.20.20/32 172.31.10.10 8443 tcp
