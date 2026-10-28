"""Single source of truth for the data model.

The same definitions drive: the SQL DDL, the data dictionary, CSV/JSON column order,
and the generic structural validation (PK / FK / NOT NULL / enumerations).
"""
from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Optional, Tuple

MACHINE_STATES = ("RUNNING", "IDLE", "STOPPED", "FAULT", "MAINTENANCE", "SETUP")
INTERLOCK_STATES = ("ENGAGED", "DISENGAGED", "BYPASSED", "NOT_APPLICABLE")
INTERLOCK_TYPES = ("GUARD_DOOR", "E_STOP", "LIGHT_CURTAIN", "PRESSURE_MAT", "TWO_HAND_CONTROL")
SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
ACTION_STATUSES = ("OPEN", "IN_PROGRESS", "COMPLETED", "VERIFIED", "CLOSED")
INCIDENT_SEVERITIES = ("MINOR", "MODERATE", "MAJOR", "CRITICAL")


@dataclass(frozen=True)
class Col:
    name: str
    sqltype: str
    desc: str
    nullable: bool = False
    allowed: Optional[Tuple[str, ...]] = None
    fk: Optional[str] = None  # "table.column"
    rule: str = ""            # extra validation rule text for the data dictionary


@dataclass
class Table:
    name: str
    pk: str
    desc: str
    cols: list = field(default_factory=list)
    append_only: bool = False

    @property
    def col_names(self):
        return [c.name for c in self.cols]


def _t(name, pk, desc, cols, append_only=False):
    return Table(name, pk, desc, cols, append_only)


TABLES: "OrderedDict[str, Table]" = OrderedDict()

TABLES["plants"] = _t("plants", "plant_id", "Factory locations (entity: Plant).", [
    Col("plant_id", "TEXT", "Unique plant id, e.g. P1."),
    Col("plant_name", "TEXT", "Plant display name."),
    Col("city", "TEXT", "City."),
    Col("country", "TEXT", "Country."),
    Col("timezone", "TEXT", "IANA timezone; shifts are defined in this local time, timestamps stored in UTC."),
])

TABLES["safety_zones"] = _t("safety_zones", "zone_id", "Areas where safety rules apply (entity: SafetyZone).", [
    Col("zone_id", "TEXT", "Unique zone id, e.g. Z01."),
    Col("plant_id", "TEXT", "Owning plant.", fk="plants.plant_id"),
    Col("zone_name", "TEXT", "Zone name."),
    Col("zone_type", "TEXT", "Zone category.",
        allowed=("ROBOTIC_CELL", "PRESS_SHOP", "WELDING_BAY", "ASSEMBLY_LINE", "MACHINING_AREA", "PACKAGING_AREA")),
    Col("risk_level", "TEXT", "Inherent zone risk.", allowed=("LOW", "MEDIUM", "HIGH")),
])

TABLES["machines"] = _t("machines", "machine_id", "Equipment on the shop floor (entity: Machine).", [
    Col("machine_id", "TEXT", "Unique machine id, e.g. M001."),
    Col("plant_id", "TEXT", "Plant where installed.", fk="plants.plant_id"),
    Col("zone_id", "TEXT", "Safety zone the machine sits in.", fk="safety_zones.zone_id",
        rule="Zone must belong to the same plant as the machine."),
    Col("machine_name", "TEXT", "Display name."),
    Col("machine_type", "TEXT", "Equipment class."),
    Col("criticality", "TEXT", "Business/safety criticality.", allowed=("LOW", "MEDIUM", "HIGH")),
    Col("install_date", "TEXT", "ISO date (YYYY-MM-DD)."),
    Col("status", "TEXT", "Operational status.", allowed=("ACTIVE", "DECOMMISSIONED")),
])

TABLES["interlocks"] = _t("interlocks", "interlock_id", "Safety mechanisms fitted to machines (entity: Interlock).", [
    Col("interlock_id", "TEXT", "Unique interlock id, e.g. IL0001."),
    Col("machine_id", "TEXT", "Machine protected by this interlock.", fk="machines.machine_id"),
    Col("zone_id", "TEXT", "Zone of the machine.", fk="safety_zones.zone_id"),
    Col("interlock_type", "TEXT", "Mechanism type.", allowed=INTERLOCK_TYPES),
    Col("tag_name", "TEXT", "PLC tag name."),
    Col("safety_rating", "TEXT", "Performance level.", allowed=("PLc", "PLd", "PLe")),
    Col("bypass_permitted_states", "TEXT",
        "Pipe-separated machine states in which BYPASSED is a legal interlock state.",
        rule="Defines rule R-ST-01c: BYPASSED while machine is in any other state is an invalid combination."),
    Col("status", "TEXT", "Interlock status.", allowed=("ACTIVE", "RETIRED")),
])

TABLES["alarm_definitions"] = _t("alarm_definitions", "alarm_def_id", "Rules defining each alarm (entity: AlarmDefinition).", [
    Col("alarm_def_id", "TEXT", "Unique definition id, e.g. AD-001."),
    Col("alarm_code", "TEXT", "Template code + machine type."),
    Col("alarm_name", "TEXT", "Human readable name."),
    Col("category", "TEXT", "Alarm category."),
    Col("severity", "TEXT", "Alarm severity.", allowed=SEVERITIES),
    Col("applicable_machine_type", "TEXT", "Machine type this definition applies to."),
    Col("interlock_type", "TEXT", "Interlock type this alarm relates to (NULL if none).", nullable=True,
        allowed=INTERLOCK_TYPES),
    Col("expected_interlock_states", "TEXT",
        "Pipe-separated interlock states permitted when this alarm fires; NOT_APPLICABLE if no interlock.",
        rule="Defines rule R-ST-01a."),
    Col("ack_sla_seconds", "INTEGER", "Maximum acceptable seconds from alarm to acknowledgement."),
    Col("requires_incident", "INTEGER", "1 if an occurrence normally warrants an incident record.",
        allowed=("0", "1")),
    Col("nuisance_candidate", "INTEGER", "1 if repeated short-interval occurrences may be classed as nuisance.",
        allowed=("0", "1")),
    Col("is_active", "INTEGER", "1 if definition is enabled.", allowed=("0", "1")),
    Col("description", "TEXT", "Description."),
])

TABLES["operator_shifts"] = _t("operator_shifts", "shift_id", "Who covered which zone in which shift (entity: OperatorShift).", [
    Col("shift_id", "TEXT", "Unique shift record id."),
    Col("plant_id", "TEXT", "Plant.", fk="plants.plant_id"),
    Col("zone_id", "TEXT", "Zone covered.", fk="safety_zones.zone_id"),
    Col("operator_id", "TEXT", "Operator id."),
    Col("operator_name", "TEXT", "Operator name (synthetic)."),
    Col("shift_name", "TEXT", "Shift.", allowed=("MORNING", "AFTERNOON", "NIGHT")),
    Col("shift_start", "TEXT", "UTC start (ISO-8601)."),
    Col("shift_end", "TEXT", "UTC end (ISO-8601).", rule="Must be later than shift_start."),
])

TABLES["alarm_events"] = _t("alarm_events", "alarm_event_id", "Actual alarm occurrences (entity: AlarmEvent). Append-only.", [
    Col("alarm_event_id", "TEXT", "Unique id, assigned in ingestion order, e.g. AE-000001."),
    Col("alarm_def_id", "TEXT", "Alarm definition.", fk="alarm_definitions.alarm_def_id"),
    Col("machine_id", "TEXT", "Machine raising the alarm.", fk="machines.machine_id"),
    Col("zone_id", "TEXT", "Zone of the machine.", fk="safety_zones.zone_id"),
    Col("interlock_id", "TEXT", "Interlock involved (NULL for non-interlock alarms).", nullable=True,
        fk="interlocks.interlock_id"),
    Col("event_ts", "TEXT", "UTC time the alarm was raised."),
    Col("clear_ts", "TEXT", "UTC time the alarm cleared (NULL = still active).", nullable=True,
        rule="Must be >= event_ts."),
    Col("machine_state", "TEXT", "Machine state when the alarm was raised.", allowed=MACHINE_STATES),
    Col("interlock_state", "TEXT", "Interlock state when the alarm was raised.", allowed=INTERLOCK_STATES),
    Col("source_system", "TEXT", "Originating system.", allowed=("PLC_SCADA", "EDGE_GATEWAY", "HISTORIAN")),
    Col("ingest_batch_id", "TEXT", "Ingestion batch; REPLAY-* marks re-delivered batches."),
    Col("ingested_ts", "TEXT", "UTC time the record was stored.", rule="Must be >= event_ts."),
    Col("content_hash", "TEXT", "SHA-256 of the business content (machine, definition, interlock, time, states)."),
], append_only=True)

TABLES["acknowledgements"] = _t("acknowledgements", "ack_id", "Operator responses to alarms (entity: Acknowledgement). Append-only.", [
    Col("ack_id", "TEXT", "Unique acknowledgement id."),
    Col("alarm_event_id", "TEXT", "Alarm acknowledged.", fk="alarm_events.alarm_event_id"),
    Col("operator_id", "TEXT", "Operator who acknowledged."),
    Col("shift_id", "TEXT", "Shift record of that operator.", fk="operator_shifts.shift_id"),
    Col("ack_ts", "TEXT", "UTC time of acknowledgement.", rule="Must be >= the alarm's event_ts (rule R-TL-01)."),
    Col("ack_method", "TEXT", "How acknowledged.", allowed=("HMI", "RADIO", "PHONE", "MOBILE_APP")),
    Col("comment", "TEXT", "Free text.", nullable=True),
], append_only=True)

TABLES["incidents"] = _t("incidents", "incident_id", "Safety incidents (entity: Incident).", [
    Col("incident_id", "TEXT", "Unique incident id."),
    Col("machine_id", "TEXT", "Machine involved.", fk="machines.machine_id"),
    Col("zone_id", "TEXT", "Zone.", fk="safety_zones.zone_id"),
    Col("trigger_alarm_event_id", "TEXT", "Alarm that triggered the incident (supporting evidence).", nullable=True,
        fk="alarm_events.alarm_event_id", rule="NULL is an evidence gap (rule R-IN-01)."),
    Col("machine_state_at_incident", "TEXT", "Machine state evidence.", nullable=True, allowed=MACHINE_STATES,
        rule="NULL is an evidence gap (rule R-IN-01)."),
    Col("incident_type", "TEXT", "Incident classification."),
    Col("severity", "TEXT", "Incident severity.", allowed=INCIDENT_SEVERITIES),
    Col("opened_ts", "TEXT", "UTC time opened."),
    Col("closed_ts", "TEXT", "UTC time closed.", nullable=True),
    Col("status", "TEXT", "Status.", allowed=("OPEN", "INVESTIGATING", "CLOSED")),
    Col("description", "TEXT", "Description."),
])

TABLES["corrective_actions"] = _t("corrective_actions", "action_id", "Remediation of incidents (entity: CorrectiveAction).", [
    Col("action_id", "TEXT", "Unique action id."),
    Col("incident_id", "TEXT", "Incident addressed.", fk="incidents.incident_id"),
    Col("machine_id", "TEXT", "Machine repaired.", fk="machines.machine_id"),
    Col("action_type", "TEXT", "Type of work.",
        allowed=("REPAIR", "REPLACE_SENSOR", "RECALIBRATE", "ADJUST_GUARD", "INSPECTION", "SOFTWARE_FIX")),
    Col("description", "TEXT", "Description."),
    Col("assigned_to", "TEXT", "Technician id."),
    Col("verification_required", "INTEGER", "1 if independent verification is mandatory before closure.",
        allowed=("0", "1")),
    Col("status", "TEXT", "Current lifecycle status.", allowed=ACTION_STATUSES),
    Col("opened_ts", "TEXT", "UTC opened."),
    Col("completed_ts", "TEXT", "UTC work completed.", nullable=True),
    Col("verified_ts", "TEXT", "UTC verification.", nullable=True),
    Col("verified_by", "TEXT", "Verifier id.", nullable=True),
    Col("closed_ts", "TEXT", "UTC closed.", nullable=True),
])

TABLES["corrective_action_history"] = _t("corrective_action_history", "history_id",
    "Append-only status transitions of corrective actions (preserves lifecycle history).", [
    Col("history_id", "TEXT", "Unique id."),
    Col("action_id", "TEXT", "Action.", fk="corrective_actions.action_id"),
    Col("seq", "INTEGER", "1-based transition sequence per action."),
    Col("from_status", "TEXT", "Previous status (NULL for creation).", nullable=True, allowed=ACTION_STATUSES),
    Col("to_status", "TEXT", "New status.", allowed=ACTION_STATUSES,
        rule="Valid path: OPEN>IN_PROGRESS>COMPLETED>[VERIFIED]>CLOSED; COMPLETED>CLOSED only if verification not required."),
    Col("changed_ts", "TEXT", "UTC time of transition."),
    Col("changed_by", "TEXT", "Actor."),
], append_only=True)

CREATE_ORDER = list(TABLES.keys())

GROUND_TRUTH_COLUMNS = ["anomaly_id", "edge_case_no", "anomaly_type", "table", "record_id",
                        "related_record_id", "variant", "why_anomalous", "expected_rule", "expected_decision"]
CONTROL_COLUMNS = ["control_id", "control_type", "table", "record_id", "why_normal", "expected_decision"]
