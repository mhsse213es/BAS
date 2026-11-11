# BFSI segmentation lab (Phase 1)

A self-hosted, emulated BFSI network used to prove that zone segmentation is
enforced, not just drawn. Six Docker networks stand in for the zones; one
firewall container (`seg-fw`) is the only path between them and logs every
decision. Design: `docs/superpowers/specs/2026-11-11-bfsi-segmentation-lab-design.md`.

## Topology

| Zone | Network | Subnet | Firewall address | Target | Target service |
|---|---|---|---|---|---|
| Corporate IT | seg-corp | 172.31.10.0/24 | 172.31.10.1 | probe-corp 172.31.10.10 | none |
| SWIFT secure | seg-swift | 172.31.20.0/24 | 172.31.20.1 | swift-gateway 172.31.20.10 | TCP 8443 |
| CDE | seg-cde | 172.31.30.0/24 | 172.31.30.1 | cde-app 172.31.30.10 | TCP 8443 |
| ATM management | seg-atm | 172.31.40.0/24 | 172.31.40.1 | atm-mgmt 172.31.40.10 | TCP 9000 |
| Core banking app | seg-app | 172.31.50.0/24 | 172.31.50.1 | core-app 172.31.50.10 | TCP 8080 |
| Core banking DB | seg-db | 172.31.60.0/24 | 172.31.60.1 | core-db 172.31.60.10 | TCP 5432 |

Probe runners sit at `.20` in each zone (probe-corp is `.10`). Every zone
container sets its default route to its zone's firewall address, so cross-zone
traffic always crosses `seg-fw`. No host ports are published.

## Pinned images

Pinned by digest, resolved on staging. Filled in when the lab first runs there.

| Image | Digest |
|---|---|
| alpine:3.20 | pending (resolve on staging) |
| postgres:16-alpine | pending (resolve on staging) |

## Bring-up (on staging only)

    docker compose -f lab/segmentation/docker-compose.yml config --quiet
    docker compose -f lab/segmentation/docker-compose.yml up -d
