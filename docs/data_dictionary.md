# Data Dictionary

Generated from `src/fss/schema.py` (the single source of truth for DDL, validation and this document).

Conventions: timestamps are UTC ISO-8601 (`YYYY-MM-DDTHH:MM:SSZ`); NULL is an empty CSV cell / JSON `null`; `Allowed` lists the enumerated values enforced by `CHECK` constraints and by the validator.

## `plants`

Factory locations (entity: Plant).

Primary key: `plant_id`

| Field | Type | Null? | Allowed values / FK | Description & validation rule |
|---|---|---|---|---|
| `plant_id` | TEXT | no | PK | Unique plant id, e.g. P1. |
| `plant_name` | TEXT | no |  | Plant display name. |
| `city` | TEXT | no |  | City. |
| `country` | TEXT | no |  | Country. |
| `timezone` | TEXT | no |  | IANA timezone; shifts are defined in this local time, timestamps stored in UTC. |

## `safety_zones`

Areas where safety rules apply (entity: SafetyZone).

Primary key: `zone_id`

| Field | Type | Null? | Allowed values / FK | Description & validation rule |
|---|---|---|---|---|
| `zone_id` | TEXT | no | PK | Unique zone id, e.g. Z01. |
| `plant_id` | TEXT | no | FK -> plants.plant_id | Owning plant. |
| `zone_name` | TEXT | no |  | Zone name. |
| `zone_type` | TEXT | no | ROBOTIC_CELL, PRESS_SHOP, WELDING_BAY, ASSEMBLY_LINE, MACHINING_AREA, PACKAGING_AREA | Zone category. |
| `risk_level` | TEXT | no | LOW, MEDIUM, HIGH | Inherent zone risk. |

## `machines`

Equipment on the shop floor (entity: Machine).

Primary key: `machine_id`

| Field | Type | Null? | Allowed values / FK | Description & validation rule |
|---|---|---|---|---|
| `machine_id` | TEXT | no | PK | Unique machine id, e.g. M001. |
| `plant_id` | TEXT | no | FK -> plants.plant_id | Plant where installed. |
| `zone_id` | TEXT | no | FK -> safety_zones.zone_id | Safety zone the machine sits in. **Rule:** Zone must belong to the same plant as the machine. |
| `machine_name` | TEXT | no |  | Display name. |
| `machine_type` | TEXT | no |  | Equipment class. |
| `criticality` | TEXT | no | LOW, MEDIUM, HIGH | Business/safety criticality. |
| `install_date` | TEXT | no |  | ISO date (YYYY-MM-DD). |
| `status` | TEXT | no | ACTIVE, DECOMMISSIONED | Operational status. |

## `interlocks`

Safety mechanisms fitted to machines (entity: Interlock).

Primary key: `interlock_id`

| Field | Type | Null? | Allowed values / FK | Description & validation rule |
|---|---|---|---|---|
| `interlock_id` | TEXT | no | PK | Unique interlock id, e.g. IL0001. |
| `machine_id` | TEXT | no | FK -> machines.machine_id | Machine protected by this interlock. |
| `zone_id` | TEXT | no | FK -> safety_zones.zone_id | Zone of the machine. |
| `interlock_type` | TEXT | no | GUARD_DOOR, E_STOP, LIGHT_CURTAIN, PRESSURE_MAT, TWO_HAND_CONTROL | Mechanism type. |
| `tag_name` | TEXT | no |  | PLC tag name. |
| `safety_rating` | TEXT | no | PLc, PLd, PLe | Performance level. |
| `bypass_permitted_states` | TEXT | no |  | Pipe-separated machine states in which BYPASSED is a legal interlock state. **Rule:** Defines rule R-ST-01c: BYPASSED while machine is in any other state is an invalid combination. |
| `status` | TEXT | no | ACTIVE, RETIRED | Interlock status. |

## `alarm_definitions`

Rules defining each alarm (entity: AlarmDefinition).

Primary key: `alarm_def_id`

| Field | Type | Null? | Allowed values / FK | Description & validation rule |
|---|---|---|---|---|
| `alarm_def_id` | TEXT | no | PK | Unique definition id, e.g. AD-001. |
| `alarm_code` | TEXT | no |  | Template code + machine type. |
| `alarm_name` | TEXT | no |  | Human readable name. |
| `category` | TEXT | no |  | Alarm category. |
| `severity` | TEXT | no | LOW, MEDIUM, HIGH, CRITICAL | Alarm severity. |
| `applicable_machine_type` | TEXT | no |  | Machine type this definition applies to. |
| `interlock_type` | TEXT | yes | GUARD_DOOR, E_STOP, LIGHT_CURTAIN, PRESSURE_MAT, TWO_HAND_CONTROL | Interlock type this alarm relates to (NULL if none). |
| `expected_interlock_states` | TEXT | no |  | Pipe-separated interlock states permitted when this alarm fires; NOT_APPLICABLE if no interlock. **Rule:** Defines rule R-ST-01a. |
| `ack_sla_seconds` | INTEGER | no |  | Maximum acceptable seconds from alarm to acknowledgement. |
| `requires_incident` | INTEGER | no | 0, 1 | 1 if an occurrence normally warrants an incident record. |
| `nuisance_candidate` | INTEGER | no | 0, 1 | 1 if repeated short-interval occurrences may be classed as nuisance. |
| `is_active` | INTEGER | no | 0, 1 | 1 if definition is enabled. |
| `description` | TEXT | no |  | Description. |

## `operator_shifts`

Who covered which zone in which shift (entity: OperatorShift).

Primary key: `shift_id`

| Field | Type | Null? | Allowed values / FK | Description & validation rule |
|---|---|---|---|---|
| `shift_id` | TEXT | no | PK | Unique shift record id. |
| `plant_id` | TEXT | no | FK -> plants.plant_id | Plant. |
| `zone_id` | TEXT | no | FK -> safety_zones.zone_id | Zone covered. |
| `operator_id` | TEXT | no |  | Operator id. |
| `operator_name` | TEXT | no |  | Operator name (synthetic). |
| `shift_name` | TEXT | no | MORNING, AFTERNOON, NIGHT | Shift. |
| `shift_start` | TEXT | no |  | UTC start (ISO-8601). |
| `shift_end` | TEXT | no |  | UTC end (ISO-8601). **Rule:** Must be later than shift_start. |

## `alarm_events`

Actual alarm occurrences (entity: AlarmEvent). Append-only. **Append-only** (UPDATE/DELETE blocked by trigger).

Primary key: `alarm_event_id`

| Field | Type | Null? | Allowed values / FK | Description & validation rule |
|---|---|---|---|---|
| `alarm_event_id` | TEXT | no | PK | Unique id, assigned in ingestion order, e.g. AE-000001. |
| `alarm_def_id` | TEXT | no | FK -> alarm_definitions.alarm_def_id | Alarm definition. |
| `machine_id` | TEXT | no | FK -> machines.machine_id | Machine raising the alarm. |
| `zone_id` | TEXT | no | FK -> safety_zones.zone_id | Zone of the machine. |
| `interlock_id` | TEXT | yes | FK -> interlocks.interlock_id | Interlock involved (NULL for non-interlock alarms). |
| `event_ts` | TEXT | no |  | UTC time the alarm was raised. |
| `clear_ts` | TEXT | yes |  | UTC time the alarm cleared (NULL = still active). **Rule:** Must be >= event_ts. |
| `machine_state` | TEXT | no | RUNNING, IDLE, STOPPED, FAULT, MAINTENANCE, SETUP | Machine state when the alarm was raised. |
| `interlock_state` | TEXT | no | ENGAGED, DISENGAGED, BYPASSED, NOT_APPLICABLE | Interlock state when the alarm was raised. |
| `source_system` | TEXT | no | PLC_SCADA, EDGE_GATEWAY, HISTORIAN | Originating system. |
| `ingest_batch_id` | TEXT | no |  | Ingestion batch; REPLAY-* marks re-delivered batches. |
| `ingested_ts` | TEXT | no |  | UTC time the record was stored. **Rule:** Must be >= event_ts. |
| `content_hash` | TEXT | no |  | SHA-256 of the business content (machine, definition, interlock, time, states). |

## `acknowledgements`

Operator responses to alarms (entity: Acknowledgement). Append-only. **Append-only** (UPDATE/DELETE blocked by trigger).

Primary key: `ack_id`

| Field | Type | Null? | Allowed values / FK | Description & validation rule |
|---|---|---|---|---|
| `ack_id` | TEXT | no | PK | Unique acknowledgement id. |
| `alarm_event_id` | TEXT | no | FK -> alarm_events.alarm_event_id | Alarm acknowledged. |
| `operator_id` | TEXT | no |  | Operator who acknowledged. |
| `shift_id` | TEXT | no | FK -> operator_shifts.shift_id | Shift record of that operator. |
| `ack_ts` | TEXT | no |  | UTC time of acknowledgement. **Rule:** Must be >= the alarm's event_ts (rule R-TL-01). |
| `ack_method` | TEXT | no | HMI, RADIO, PHONE, MOBILE_APP | How acknowledged. |
| `comment` | TEXT | yes |  | Free text. |

## `incidents`

Safety incidents (entity: Incident).

Primary key: `incident_id`

| Field | Type | Null? | Allowed values / FK | Description & validation rule |
|---|---|---|---|---|
| `incident_id` | TEXT | no | PK | Unique incident id. |
| `machine_id` | TEXT | no | FK -> machines.machine_id | Machine involved. |
| `zone_id` | TEXT | no | FK -> safety_zones.zone_id | Zone. |
| `trigger_alarm_event_id` | TEXT | yes | FK -> alarm_events.alarm_event_id | Alarm that triggered the incident (supporting evidence). **Rule:** NULL is an evidence gap (rule R-IN-01). |
| `machine_state_at_incident` | TEXT | yes | RUNNING, IDLE, STOPPED, FAULT, MAINTENANCE, SETUP | Machine state evidence. **Rule:** NULL is an evidence gap (rule R-IN-01). |
| `incident_type` | TEXT | no |  | Incident classification. |
| `severity` | TEXT | no | MINOR, MODERATE, MAJOR, CRITICAL | Incident severity. |
| `opened_ts` | TEXT | no |  | UTC time opened. |
| `closed_ts` | TEXT | yes |  | UTC time closed. |
| `status` | TEXT | no | OPEN, INVESTIGATING, CLOSED | Status. |
| `description` | TEXT | no |  | Description. |

## `corrective_actions`

Remediation of incidents (entity: CorrectiveAction).

Primary key: `action_id`

| Field | Type | Null? | Allowed values / FK | Description & validation rule |
|---|---|---|---|---|
| `action_id` | TEXT | no | PK | Unique action id. |
| `incident_id` | TEXT | no | FK -> incidents.incident_id | Incident addressed. |
| `machine_id` | TEXT | no | FK -> machines.machine_id | Machine repaired. |
| `action_type` | TEXT | no | REPAIR, REPLACE_SENSOR, RECALIBRATE, ADJUST_GUARD, INSPECTION, SOFTWARE_FIX | Type of work. |
| `description` | TEXT | no |  | Description. |
| `assigned_to` | TEXT | no |  | Technician id. |
| `verification_required` | INTEGER | no | 0, 1 | 1 if independent verification is mandatory before closure. |
| `status` | TEXT | no | OPEN, IN_PROGRESS, COMPLETED, VERIFIED, CLOSED | Current lifecycle status. |
| `opened_ts` | TEXT | no |  | UTC opened. |
| `completed_ts` | TEXT | yes |  | UTC work completed. |
| `verified_ts` | TEXT | yes |  | UTC verification. |
| `verified_by` | TEXT | yes |  | Verifier id. |
| `closed_ts` | TEXT | yes |  | UTC closed. |

## `corrective_action_history`

Append-only status transitions of corrective actions (preserves lifecycle history). **Append-only** (UPDATE/DELETE blocked by trigger).

Primary key: `history_id`

| Field | Type | Null? | Allowed values / FK | Description & validation rule |
|---|---|---|---|---|
| `history_id` | TEXT | no | PK | Unique id. |
| `action_id` | TEXT | no | FK -> corrective_actions.action_id | Action. |
| `seq` | INTEGER | no |  | 1-based transition sequence per action. |
| `from_status` | TEXT | yes | OPEN, IN_PROGRESS, COMPLETED, VERIFIED, CLOSED | Previous status (NULL for creation). |
| `to_status` | TEXT | no | OPEN, IN_PROGRESS, COMPLETED, VERIFIED, CLOSED | New status. **Rule:** Valid path: OPEN>IN_PROGRESS>COMPLETED>[VERIFIED]>CLOSED; COMPLETED>CLOSED only if verification not required. |
| `changed_ts` | TEXT | no |  | UTC time of transition. |
| `changed_by` | TEXT | no |  | Actor. |

## Ground-truth files (kept separate from the data)

`ground_truth/ground_truth.csv` - one row per injected anomaly: `anomaly_id`, `edge_case_no`, `anomaly_type`, `table`, `record_id`, `related_record_id`, `variant`, `why_anomalous`, `expected_rule`, `expected_decision`.

`ground_truth/ground_truth_controls.csv` - hard negatives that look suspicious but are valid; the detector must NOT flag them: `control_id`, `control_type`, `table`, `record_id`, `why_normal`, `expected_decision`.
