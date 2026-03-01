PROGRAM water_pump
  VAR
    water_level AT %IW0 : INT := 81;      
    pump_running AT %QX0.0 : BOOL := FALSE; 
    alarm_active AT %QX0.1 : BOOL := FALSE; 
  END_VAR
  
  VAR
    setpoint_high : INT := 80;
    setpoint_low : INT := 20;
    alarm_threshold : INT := 95;
  END_VAR

  IF water_level < setpoint_low THEN
    pump_running := TRUE;
  END_IF;
  
  IF water_level > setpoint_high THEN
    pump_running := FALSE;
  END_IF;
  
  IF water_level > alarm_threshold THEN
    alarm_active := TRUE;
  END_IF;
  
  IF water_level < setpoint_high THEN
    alarm_active := FALSE;
  END_IF;

END_PROGRAM

CONFIGURATION Config0
  RESOURCE Res0 ON PLC
    TASK Main(INTERVAL := T#500ms,PRIORITY := 0);
    PROGRAM Inst0 WITH Main : water_pump;
  END_RESOURCE
END_CONFIGURATION