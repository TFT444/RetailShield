# RetailShield — Hunting Queries

Proactive threat-hunting KQL queries for use in Sentinel's **Hunting** blade. Unlike scheduled analytics rules, these are run on-demand by the SOC to investigate specific hypotheses or sweep for attacker activity that hasn't yet triggered an alert.

Hunting queries to be added here as the library grows. Planned coverage:
- Dormant guest account re-activation (Scattered Spider staging)
- OAuth app consent grant sweep (T1550.001)
- Service principal credential additions (T1098.001)
- POS cashier behaviour baseline deviation
