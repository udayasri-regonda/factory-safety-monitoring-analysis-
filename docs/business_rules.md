# Business Rules

All thresholds live in `src/fss/config.py` (`RULES`) and are applied by `src/fss/detector.py`.

## A. Event classification
Each stored alarm event gets one class, evaluated in this precedence order:

| Class | Rule |
|---|---|
| DUPLICATE | Re-delivered copy of an earlier event (R-DU-01). Excluded from all KPIs. |
| SUSPICIOUS | Impossible / contradictory interlock data (R-ST-01). |
| UNSAFE | `machine_state = RUNNING` while `interlock_state = DISENGAGED` (protection open during operation). |
| DELAYED | Acknowledged after the definition's SLA (CRITICAL 60 s, HIGH 120 s, MEDIUM 300 s, LOW 900 s) **or** HIGH/CRITICAL never acknowledged. |
| SAFE | None of the above. |

Extra flags (an event can carry several): `NUISANCE_CHATTER`, `ALARM_FLOOD`, `RECURRING_ALARM`.

## B. Operational detections
* **Nuisance (chatter)**: >= 3 occurrences of the same LOW/MEDIUM alarm on one machine within 10 minutes; every event in the cluster is flagged.
* **Alarm flood**: >= 10 alarms on one machine within 10 minutes (ISA-18.2 style); overlapping windows merge into one episode.
* **Recurring alarm**: >= 5 occurrences of the same HIGH/CRITICAL alarm on one machine within 7 days.
* **Recurring unsafe condition (machine level)**: >= 3 UNSAFE events on one machine within 7 days.
* **Delayed / missing acknowledgement**: see class DELAYED. Acknowledgements violating R-TL-01 are excluded from response-time statistics.

## C. The five edge-case rules
| Rule | Edge case | Logic | Flags |
|---|---|---|---|
| R-TL-01 | Acknowledgement before alarm | `ack_ts < alarm.event_ts` (equal timestamps are valid) | the acknowledgement |
| R-ST-01 | Impossible interlock state | (a) `interlock_state` not in the definition's `expected_interlock_states`; (b) interlock belongs to another machine or has the wrong type; (c) `BYPASSED` while machine state is not in the interlock's `bypass_permitted_states`; (d) non-interlock alarm carrying interlock data | the alarm event |
| R-IN-01 | Incident without triggering context | `trigger_alarm_event_id` NULL (or alarm of another machine) **or** `machine_state_at_incident` NULL | the incident |
| R-DU-01 | Duplicate alarm replay | identical (machine, definition, interlock, event_ts, machine_state, interlock_state); earliest-ingested copy kept, later copies flagged. Events 1-2 s apart are *not* duplicates | each later copy |
| R-LC-01 | Closed without verification | `COMPLETED -> CLOSED` while `verification_required = 1`, or CLOSED with no verified_ts/verified_by, or any transition outside the valid graph | the action |

Valid lifecycle: `OPEN -> IN_PROGRESS -> COMPLETED -> [VERIFIED] -> CLOSED` (VERIFIED skippable only when `verification_required = 0`).

## D. History preservation
* `alarm_events`, `acknowledgements`, `corrective_action_history` are append-only (SQL triggers reject UPDATE/DELETE).
* Replayed duplicates are **stored, never deleted or overwritten**; they are flagged and excluded from analytics.
* Corrective-action status changes are new rows in `corrective_action_history`.

## E. Machine risk score
`3 x unsafe + 2 x recurring-alarm events + delayed acks + 2 x unacknowledged + 0.5 x flood events`.
