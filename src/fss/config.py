"""Profiles, domain catalogues and documented business-rule thresholds."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

DEFAULT_SEED = 20261022                   # fixed reproducible seed required by the project specification
BASE_DATE = datetime(2026, 7, 1)          # fixed -> reproducible (never uses wall-clock time)
IST_OFFSET_MIN = 330                      # all plants are in India (UTC+05:30)


@dataclass(frozen=True)
class Profile:
    name: str
    n_plants: int
    n_machines: int
    n_machine_types: int
    templates_per_type: int
    zones_per_plant: int
    n_events: int              # total alarm_events rows INCLUDING replayed duplicates
    days: int
    n_chronic_machines: int
    n_floods: int
    n_chatter_bursts: int
    n_twins: int               # legitimate near-duplicates (hard negatives)
    # injected edge cases
    inj_ack_before_alarm: int
    inj_impossible_state: int
    inj_incident_no_context: int
    inj_duplicate_replay: int
    inj_action_unverified: int
    # hard-negative controls
    ctl_zero_second_ack: int
    ctl_unverified_not_required: int

    @property
    def n_alarm_defs(self):
        return self.n_machine_types * self.templates_per_type


PROFILES = {
    "full": Profile("full", 4, 60, 10, 20, 6, 50_000, 30, 8, 30, 160, 40,
                    60, 60, 25, 150, 30, 20, 20),
    "starter": Profile("starter", 2, 12, 4, 10, 3, 2_000, 30, 2, 4, 15, 8,
                       6, 6, 4, 12, 5, 5, 5),
}

PLANTS = [
    ("P1", "Hyderabad Factory", "Hyderabad"),
    ("P2", "Chennai Factory", "Chennai"),
    ("P3", "Pune Factory", "Pune"),
    ("P4", "Ahmedabad Factory", "Ahmedabad"),
]

ZONE_TYPES = ["ROBOTIC_CELL", "PRESS_SHOP", "WELDING_BAY", "ASSEMBLY_LINE", "MACHINING_AREA", "PACKAGING_AREA"]
ZONE_RISK = {"ROBOTIC_CELL": "HIGH", "PRESS_SHOP": "HIGH", "WELDING_BAY": "HIGH",
             "ASSEMBLY_LINE": "MEDIUM", "MACHINING_AREA": "MEDIUM", "PACKAGING_AREA": "LOW"}

MACHINE_TYPES = ["CNC_MILL", "ROBOTIC_ARM", "HYDRAULIC_PRESS", "CONVEYOR", "WELDING_STATION",
                 "INJECTION_MOLDER", "PACKAGING_LINE", "LATHE", "LASER_CUTTER", "PAINT_BOOTH"]
MACHINE_CRITICALITY = {"CNC_MILL": "MEDIUM", "ROBOTIC_ARM": "HIGH", "HYDRAULIC_PRESS": "HIGH",
                       "CONVEYOR": "LOW", "WELDING_STATION": "HIGH", "INJECTION_MOLDER": "MEDIUM",
                       "PACKAGING_LINE": "LOW", "LATHE": "MEDIUM", "LASER_CUTTER": "HIGH",
                       "PAINT_BOOTH": "MEDIUM"}

OPTIONAL_INTERLOCKS = ["LIGHT_CURTAIN", "PRESSURE_MAT", "TWO_HAND_CONTROL"]  # GUARD_DOOR and E_STOP always fitted

# code, name, category, severity, interlock_type, expected interlock states, requires_incident, median duration (s)
ALARM_TEMPLATES = [
    ("GUARD_DOOR_OPEN", "Safety guard door opened", "SAFETY_INTERLOCK", "HIGH", "GUARD_DOOR", "DISENGAGED", 0),
    ("LIGHT_CURTAIN_BREACH", "Light curtain beam broken", "SAFETY_INTERLOCK", "CRITICAL", "LIGHT_CURTAIN", "DISENGAGED", 1),
    ("E_STOP_PRESSED", "Emergency stop pressed", "SAFETY_INTERLOCK", "CRITICAL", "E_STOP", "DISENGAGED", 1),
    ("PRESSURE_MAT_TRIGGERED", "Pressure mat triggered", "SAFETY_INTERLOCK", "HIGH", "PRESSURE_MAT", "DISENGAGED", 0),
    ("TWO_HAND_VIOLATION", "Two-hand control violation", "SAFETY_INTERLOCK", "CRITICAL", "TWO_HAND_CONTROL", "DISENGAGED", 1),
    ("DOOR_LOCK_FAULT", "Guard door lock fault", "SAFETY_INTERLOCK", "MEDIUM", "GUARD_DOOR", "ENGAGED|DISENGAGED", 0),
    ("SAFETY_RELAY_FAULT", "Safety relay fault", "SAFETY_INTERLOCK", "CRITICAL", "E_STOP", "ENGAGED|DISENGAGED", 1),
    ("OVER_TEMPERATURE", "Over temperature", "THERMAL", "HIGH", None, "NOT_APPLICABLE", 0),
    ("OVERPRESSURE", "Over pressure", "PRESSURE", "HIGH", None, "NOT_APPLICABLE", 0),
    ("MOTOR_OVERLOAD", "Motor overload", "ELECTRICAL", "MEDIUM", None, "NOT_APPLICABLE", 0),
    ("VIBRATION_HIGH", "High vibration", "MECHANICAL", "MEDIUM", None, "NOT_APPLICABLE", 0),
    ("COOLANT_LOW", "Coolant level low", "FLUID", "LOW", None, "NOT_APPLICABLE", 0),
    ("LUBRICATION_LOW", "Lubrication level low", "FLUID", "LOW", None, "NOT_APPLICABLE", 0),
    ("AIR_PRESSURE_LOW", "Compressed air pressure low", "PNEUMATIC", "LOW", None, "NOT_APPLICABLE", 0),
    ("SENSOR_DRIFT", "Sensor drift detected", "INSTRUMENTATION", "LOW", None, "NOT_APPLICABLE", 0),
    ("COMMS_LOSS", "Controller communication loss", "NETWORK", "MEDIUM", None, "NOT_APPLICABLE", 0),
    ("PLC_WATCHDOG_TIMEOUT", "PLC watchdog timeout", "CONTROL", "HIGH", None, "NOT_APPLICABLE", 0),
    ("FIRE_SUPPRESSION_FAULT", "Fire suppression fault", "FIRE", "CRITICAL", None, "NOT_APPLICABLE", 1),
    ("GAS_LEAK_DETECTED", "Gas leak detected", "ENVIRONMENTAL", "CRITICAL", None, "NOT_APPLICABLE", 1),
    ("TOOL_BREAKAGE", "Tool breakage detected", "MECHANICAL", "LOW", None, "NOT_APPLICABLE", 0),
]

ACK_SLA_SECONDS = {"CRITICAL": 60, "HIGH": 120, "MEDIUM": 300, "LOW": 900}
ACK_MEDIAN_SECONDS = {"CRITICAL": 18, "HIGH": 40, "MEDIUM": 110, "LOW": 360}
ACK_PROBABILITY = {"CRITICAL": 0.99, "HIGH": 0.97, "MEDIUM": 0.92, "LOW": 0.85}
DURATION_MEDIAN_SECONDS = {"CRITICAL": 300, "HIGH": 240, "MEDIUM": 120, "LOW": 60}

SHIFTS = [("MORNING", 0), ("AFTERNOON", 8), ("NIGHT", 16)]  # name, hours after 06:00 IST

# ---- Documented business-rule thresholds (see docs/business_rules.md) ----
RULES = {
    "flood_window_s": 600,          # ISA-18.2 style: >= 10 alarms in 10 min on one machine
    "flood_min_alarms": 10,
    "chatter_window_s": 600,        # nuisance: >= 3 repeats of the same LOW/MEDIUM alarm in 10 min
    "chatter_min_repeats": 3,
    "recurring_window_days": 7,     # recurring: >= 5 of the same HIGH/CRITICAL alarm in 7 days
    "recurring_min_events": 5,
    "recurring_unsafe_window_days": 7,   # machine with >= 3 UNSAFE events in 7 days
    "recurring_unsafe_min_events": 3,
    "unack_grace_s": 3600,          # a HIGH/CRITICAL alarm younger than this at dataset end is not yet "unacknowledged"
    "ack_pattern_window_days": 7,   # machine-level: >= 3 delayed/unacknowledged HIGH/CRITICAL alarms in 7 days
    "ack_pattern_min_events": 3,
    "repeat_incident_window_days": 7,    # >= 3 incidents on one machine in 7 days
    "repeat_incident_min": 3,
    "context_events_each_side": 3,  # neighbouring alarms on the same machine shown as context in an investigation
}

# Machine risk score = sum(weight x count of flagged events). A RELATIVE ranking index, not a probability of accident.
RISK_WEIGHTS = {"UNSAFE_CONDITION": 3.0, "RECURRING_ALARM": 2.0, "DELAYED_ACK": 1.0,
                "UNACKNOWLEDGED": 2.0, "ALARM_FLOOD": 0.5}
RISK_LABELS = {"UNSAFE_CONDITION": "Alarm while RUNNING with interlock DISENGAGED",
               "RECURRING_ALARM": "Events in a recurring HIGH/CRITICAL alarm pattern",
               "DELAYED_ACK": "Acknowledged later than the alarm's SLA",
               "UNACKNOWLEDGED": "HIGH/CRITICAL alarm never acknowledged",
               "ALARM_FLOOD": "Events inside an alarm-flood episode"}

FIRST_NAMES = ["Arjun", "Priya", "Ravi", "Anita", "Suresh", "Kavita", "Manoj", "Deepa", "Vikram", "Sunita",
               "Rahul", "Meena", "Karthik", "Lakshmi", "Sanjay", "Pooja", "Naveen", "Divya", "Imran", "Farah"]
LAST_NAMES = ["Reddy", "Sharma", "Iyer", "Patel", "Nair", "Singh", "Rao", "Kumar", "Das", "Mehta",
              "Gupta", "Pillai", "Joshi", "Shah", "Naidu", "Khan"]
