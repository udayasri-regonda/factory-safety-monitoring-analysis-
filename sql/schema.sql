-- Factory Safety Monitoring schema (SQLite dialect; portable to PostgreSQL with minor edits)
PRAGMA foreign_keys = ON;

-- Factory locations (entity: Plant).
CREATE TABLE plants (
  plant_id TEXT PRIMARY KEY,
  plant_name TEXT NOT NULL,
  city TEXT NOT NULL,
  country TEXT NOT NULL,
  timezone TEXT NOT NULL
);

-- Areas where safety rules apply (entity: SafetyZone).
CREATE TABLE safety_zones (
  zone_id TEXT PRIMARY KEY,
  plant_id TEXT NOT NULL,
  zone_name TEXT NOT NULL,
  zone_type TEXT NOT NULL CHECK (zone_type IN ('ROBOTIC_CELL', 'PRESS_SHOP', 'WELDING_BAY', 'ASSEMBLY_LINE', 'MACHINING_AREA', 'PACKAGING_AREA')),
  risk_level TEXT NOT NULL CHECK (risk_level IN ('LOW', 'MEDIUM', 'HIGH')),
  FOREIGN KEY (plant_id) REFERENCES plants(plant_id)
);

-- Equipment on the shop floor (entity: Machine).
CREATE TABLE machines (
  machine_id TEXT PRIMARY KEY,
  plant_id TEXT NOT NULL,
  zone_id TEXT NOT NULL,
  machine_name TEXT NOT NULL,
  machine_type TEXT NOT NULL,
  criticality TEXT NOT NULL CHECK (criticality IN ('LOW', 'MEDIUM', 'HIGH')),
  install_date TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('ACTIVE', 'DECOMMISSIONED')),
  FOREIGN KEY (plant_id) REFERENCES plants(plant_id),
  FOREIGN KEY (zone_id) REFERENCES safety_zones(zone_id)
);

-- Safety mechanisms fitted to machines (entity: Interlock).
CREATE TABLE interlocks (
  interlock_id TEXT PRIMARY KEY,
  machine_id TEXT NOT NULL,
  zone_id TEXT NOT NULL,
  interlock_type TEXT NOT NULL CHECK (interlock_type IN ('GUARD_DOOR', 'E_STOP', 'LIGHT_CURTAIN', 'PRESSURE_MAT', 'TWO_HAND_CONTROL')),
  tag_name TEXT NOT NULL,
  safety_rating TEXT NOT NULL CHECK (safety_rating IN ('PLc', 'PLd', 'PLe')),
  bypass_permitted_states TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('ACTIVE', 'RETIRED')),
  FOREIGN KEY (machine_id) REFERENCES machines(machine_id),
  FOREIGN KEY (zone_id) REFERENCES safety_zones(zone_id)
);

-- Rules defining each alarm (entity: AlarmDefinition).
CREATE TABLE alarm_definitions (
  alarm_def_id TEXT PRIMARY KEY,
  alarm_code TEXT NOT NULL,
  alarm_name TEXT NOT NULL,
  category TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
  applicable_machine_type TEXT NOT NULL,
  interlock_type TEXT CHECK (interlock_type IS NULL OR interlock_type IN ('GUARD_DOOR', 'E_STOP', 'LIGHT_CURTAIN', 'PRESSURE_MAT', 'TWO_HAND_CONTROL')),
  expected_interlock_states TEXT NOT NULL,
  ack_sla_seconds INTEGER NOT NULL,
  requires_incident INTEGER NOT NULL CHECK (requires_incident IN (0, 1)),
  nuisance_candidate INTEGER NOT NULL CHECK (nuisance_candidate IN (0, 1)),
  is_active INTEGER NOT NULL CHECK (is_active IN (0, 1)),
  description TEXT NOT NULL
);

-- Who covered which zone in which shift (entity: OperatorShift).
CREATE TABLE operator_shifts (
  shift_id TEXT PRIMARY KEY,
  plant_id TEXT NOT NULL,
  zone_id TEXT NOT NULL,
  operator_id TEXT NOT NULL,
  operator_name TEXT NOT NULL,
  shift_name TEXT NOT NULL CHECK (shift_name IN ('MORNING', 'AFTERNOON', 'NIGHT')),
  shift_start TEXT NOT NULL,
  shift_end TEXT NOT NULL,
  FOREIGN KEY (plant_id) REFERENCES plants(plant_id),
  FOREIGN KEY (zone_id) REFERENCES safety_zones(zone_id)
);

-- Actual alarm occurrences (entity: AlarmEvent). Append-only.
CREATE TABLE alarm_events (
  alarm_event_id TEXT PRIMARY KEY,
  alarm_def_id TEXT NOT NULL,
  machine_id TEXT NOT NULL,
  zone_id TEXT NOT NULL,
  interlock_id TEXT,
  event_ts TEXT NOT NULL,
  clear_ts TEXT,
  machine_state TEXT NOT NULL CHECK (machine_state IN ('RUNNING', 'IDLE', 'STOPPED', 'FAULT', 'MAINTENANCE', 'SETUP')),
  interlock_state TEXT NOT NULL CHECK (interlock_state IN ('ENGAGED', 'DISENGAGED', 'BYPASSED', 'NOT_APPLICABLE')),
  source_system TEXT NOT NULL CHECK (source_system IN ('PLC_SCADA', 'EDGE_GATEWAY', 'HISTORIAN')),
  ingest_batch_id TEXT NOT NULL,
  ingested_ts TEXT NOT NULL,
  content_hash TEXT NOT NULL,
  FOREIGN KEY (alarm_def_id) REFERENCES alarm_definitions(alarm_def_id),
  FOREIGN KEY (machine_id) REFERENCES machines(machine_id),
  FOREIGN KEY (zone_id) REFERENCES safety_zones(zone_id),
  FOREIGN KEY (interlock_id) REFERENCES interlocks(interlock_id)
);

-- Operator responses to alarms (entity: Acknowledgement). Append-only.
CREATE TABLE acknowledgements (
  ack_id TEXT PRIMARY KEY,
  alarm_event_id TEXT NOT NULL,
  operator_id TEXT NOT NULL,
  shift_id TEXT NOT NULL,
  ack_ts TEXT NOT NULL,
  ack_method TEXT NOT NULL CHECK (ack_method IN ('HMI', 'RADIO', 'PHONE', 'MOBILE_APP')),
  comment TEXT,
  FOREIGN KEY (alarm_event_id) REFERENCES alarm_events(alarm_event_id),
  FOREIGN KEY (shift_id) REFERENCES operator_shifts(shift_id)
);

-- Safety incidents (entity: Incident).
CREATE TABLE incidents (
  incident_id TEXT PRIMARY KEY,
  machine_id TEXT NOT NULL,
  zone_id TEXT NOT NULL,
  trigger_alarm_event_id TEXT,
  machine_state_at_incident TEXT CHECK (machine_state_at_incident IS NULL OR machine_state_at_incident IN ('RUNNING', 'IDLE', 'STOPPED', 'FAULT', 'MAINTENANCE', 'SETUP')),
  incident_type TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('MINOR', 'MODERATE', 'MAJOR', 'CRITICAL')),
  opened_ts TEXT NOT NULL,
  closed_ts TEXT,
  status TEXT NOT NULL CHECK (status IN ('OPEN', 'INVESTIGATING', 'CLOSED')),
  description TEXT NOT NULL,
  FOREIGN KEY (machine_id) REFERENCES machines(machine_id),
  FOREIGN KEY (zone_id) REFERENCES safety_zones(zone_id),
  FOREIGN KEY (trigger_alarm_event_id) REFERENCES alarm_events(alarm_event_id)
);

-- Remediation of incidents (entity: CorrectiveAction).
CREATE TABLE corrective_actions (
  action_id TEXT PRIMARY KEY,
  incident_id TEXT NOT NULL,
  machine_id TEXT NOT NULL,
  action_type TEXT NOT NULL CHECK (action_type IN ('REPAIR', 'REPLACE_SENSOR', 'RECALIBRATE', 'ADJUST_GUARD', 'INSPECTION', 'SOFTWARE_FIX')),
  description TEXT NOT NULL,
  assigned_to TEXT NOT NULL,
  verification_required INTEGER NOT NULL CHECK (verification_required IN (0, 1)),
  status TEXT NOT NULL CHECK (status IN ('OPEN', 'IN_PROGRESS', 'COMPLETED', 'VERIFIED', 'CLOSED')),
  opened_ts TEXT NOT NULL,
  completed_ts TEXT,
  verified_ts TEXT,
  verified_by TEXT,
  closed_ts TEXT,
  FOREIGN KEY (incident_id) REFERENCES incidents(incident_id),
  FOREIGN KEY (machine_id) REFERENCES machines(machine_id)
);

-- Append-only status transitions of corrective actions (preserves lifecycle history).
CREATE TABLE corrective_action_history (
  history_id TEXT PRIMARY KEY,
  action_id TEXT NOT NULL,
  seq INTEGER NOT NULL,
  from_status TEXT CHECK (from_status IS NULL OR from_status IN ('OPEN', 'IN_PROGRESS', 'COMPLETED', 'VERIFIED', 'CLOSED')),
  to_status TEXT NOT NULL CHECK (to_status IN ('OPEN', 'IN_PROGRESS', 'COMPLETED', 'VERIFIED', 'CLOSED')),
  changed_ts TEXT NOT NULL,
  changed_by TEXT NOT NULL,
  FOREIGN KEY (action_id) REFERENCES corrective_actions(action_id)
);

CREATE INDEX idx_alarm_events_machine_id_event_ts ON alarm_events(machine_id, event_ts);
CREATE INDEX idx_alarm_events_alarm_def_id ON alarm_events(alarm_def_id);
CREATE INDEX idx_alarm_events_content_hash ON alarm_events(content_hash);
CREATE INDEX idx_acknowledgements_alarm_event_id ON acknowledgements(alarm_event_id);
CREATE INDEX idx_incidents_machine_id ON incidents(machine_id);
CREATE INDEX idx_corrective_actions_incident_id ON corrective_actions(incident_id);
CREATE INDEX idx_corrective_action_history_action_id_seq ON corrective_action_history(action_id, seq);
CREATE INDEX idx_operator_shifts_plant_id_zone_id_shift_start ON operator_shifts(plant_id, zone_id, shift_start);

-- History preservation: append-only tables reject UPDATE and DELETE.
CREATE TRIGGER trg_alarm_events_no_update BEFORE UPDATE ON alarm_events
BEGIN SELECT RAISE(ABORT, 'alarm_events is append-only'); END;
CREATE TRIGGER trg_alarm_events_no_delete BEFORE DELETE ON alarm_events
BEGIN SELECT RAISE(ABORT, 'alarm_events is append-only'); END;
CREATE TRIGGER trg_acknowledgements_no_update BEFORE UPDATE ON acknowledgements
BEGIN SELECT RAISE(ABORT, 'acknowledgements is append-only'); END;
CREATE TRIGGER trg_acknowledgements_no_delete BEFORE DELETE ON acknowledgements
BEGIN SELECT RAISE(ABORT, 'acknowledgements is append-only'); END;
CREATE TRIGGER trg_corrective_action_history_no_update BEFORE UPDATE ON corrective_action_history
BEGIN SELECT RAISE(ABORT, 'corrective_action_history is append-only'); END;
CREATE TRIGGER trg_corrective_action_history_no_delete BEFORE DELETE ON corrective_action_history
BEGIN SELECT RAISE(ABORT, 'corrective_action_history is append-only'); END;
