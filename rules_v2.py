# Regras de detecção geradas pelo LLM (limpas)
# Origem: rules_raw.py
# Data: 13/09/2026 21:38:21
# Para uso no pipeline de detecção GOOSE IEC 61850

def rule_grayhole_sqnum_tdiff(packet: dict) -> bool:
    """Detect grayhole: very low SqNum combined with high tDiff."""
    sq_num = packet.get("SqNum", 0)
    t_diff = packet.get("tDiff", 0)
    return (sq_num < 1) and (t_diff > 1500)

def rule_grayhole_sqnum_stdiff(packet: dict) -> bool:
    """Detect grayhole: very low SqNum combined with large positive stDiff."""
    sq_num = packet.get("SqNum", 0)
    st_diff = packet.get("stDiff", 0)
    return (sq_num < 1) and (st_diff > 500)

def rule_grayhole_stnum_tdiff(packet: dict) -> bool:
    """Detect grayhole: low StNum combined with high tDiff."""
    st_num = packet.get("StNum", 0)
    t_diff = packet.get("tDiff", 0)
    return (st_num < 35) and (t_diff > 1500)

def rule_grayhole_stnum_timechange(packet: dict) -> bool:
    """Detect grayhole: low StNum combined with long time since last change."""
    st_num = packet.get("StNum", 0)
    time_change = packet.get("timeFromLastChange", 0)
    return (st_num < 35) and (time_change > 51)


# === high_StNum ===

def rule_high_StNum_state(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de high_StNum (estado)."""
    stnum = packet.get("StNum", 0)
    stdiff = packet.get("stDiff", 0)
    tflc = packet.get("timeFromLastChange", 0)
    return (stnum > 1000) and (stdiff > 500) and (tflc < 0)

def rule_high_StNum_seq(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de high_StNum (sequência)."""
    sqnum = packet.get("SqNum", 0)
    sqdiff = packet.get("sqDiff", 0)
    tdiff = packet.get("tDiff", 0)
    delay = packet.get("delay", 0)
    return (sqnum > 100) and (sqdiff > 50) and (tdiff > 2000) and (delay > 0.0005)


# === injection ===

def rule_injection_seq_state(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de injection por sequência e estado."""
    sq = packet.get("SqNum", 0)
    st = packet.get("StNum", 0)
    return (sq > 80) and (st < 20)

def rule_injection_timing_status(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de injection por anomalias de tempo e status."""
    tdiff = packet.get("tDiff", 0)
    cb = packet.get("cbStatus", 0)
    tsdiff = packet.get("timestampDiff", 0)
    return (tdiff < -2000) and (cb > 1.5) and (tsdiff > 0.5)


# === inverse_replay ===

def rule_inverse_replay_seq_timegap(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de inverse_replay."""
    sq_num = packet.get("SqNum", 0)
    time_gap = packet.get("timeFromLastChange", 0)
    return (sq_num < 0.5) and (time_gap > 100.0)

def rule_inverse_replay_state_timestamp(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de inverse_replay."""
    st_diff = packet.get("stDiff", 0)
    t_diff = packet.get("tDiff", 0)
    return (st_diff > 500.0) and (t_diff > 2500.0)


# === masquerade_fake_fault ===

def rule_masquerade_fake_fault_low_stnum(packet: dict) -> bool:
    """Detect low StNum combined with unusually long inter-message interval."""
    st_num = packet.get("StNum", 0)
    t_diff = packet.get("tDiff", 0)
    return (st_num < 30) and (t_diff > 2000)

def rule_masquerade_fake_fault_cbstatus_on(packet: dict) -> bool:
    """Detect constant breaker-ON status together with abnormal timestamp drift."""
    cb_status = packet.get("cbStatus", 0)
    ts_diff = packet.get("timestampDiff", 0)
    return (cb_status == 1) and (ts_diff > 0.2)

def rule_masquerade_fake_fault_long_gap(packet: dict) -> bool:
    """Detect very long gaps between GOOSE messages combined with large state change delta."""
    t_diff = packet.get("tDiff", 0)
    st_diff = packet.get("stDiff", 0)
    return (t_diff > 2000) and (st_diff > 400)

def rule_masquerade_fake_fault_sqnum_timestamp(packet: dict) -> bool:
    """Detect unusually high sequence numbers together with significant timestamp drift."""
    sq_num = packet.get("SqNum", 0)
    ts_diff = packet.get("timestampDiff", 0)
    return (sq_num > 60) and (ts_diff > 0.2)


# === masquerade_fake_normal ===

def rule_masquerade_fake_normal_seq_state(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de masquerade_fake_normal."""
    sq_num = packet.get("SqNum", 0)
    st_num = packet.get("StNum", 0)
    return (sq_num < 0.5) and (st_num > 700)

def rule_masquerade_fake_normal_state_diff_time(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de masquerade_fake_normal."""
    st_diff = packet.get("stDiff", 0)
    time_from_last_change = packet.get("timeFromLastChange", 0)
    return (st_diff > 400) and (time_from_last_change > 100)


# === poisoned_high_rate ===

def rule_poisoned_high_rate_seq_state(packet: dict) -> bool:
    """Retorna True se o pacote apresentar anomalias de sequência e timestamp."""
    sq_diff = packet.get("sqDiff", 0)
    timestamp_diff = packet.get("timestampDiff", 0)
    return (sq_diff < -70) and (timestamp_diff > 0.5)

def rule_poisoned_high_rate_timing(packet: dict) -> bool:
    """Retorna True se o pacote apresentar anomalias de tempo e atraso."""
    t_diff = packet.get("tDiff", 0)
    delay = packet.get("delay", 0)
    time_last_change = packet.get("timeFromLastChange", 0)
    return (t_diff < -200) and (delay > 0.001) and (time_last_change > 60)


# === random_replay ===

def rule_random_replay_stdiff_timestamp(packet: dict) -> bool:
    """Detect extreme negative stDiff together with a large timestamp offset."""
    st_diff = packet.get("stDiff", 0)
    timestamp_diff = packet.get("timestampDiff", 0)
    return (st_diff < -65000) and (timestamp_diff > 0.5)

def rule_random_replay_sqnum_stnum(packet: dict) -> bool:
    """Detect unusually high SqNum combined with abnormally low StNum."""
    sq_num = packet.get("SqNum", 0)
    st_num = packet.get("StNum", 0)
    return (sq_num > 55) and (st_num < 30)

def rule_random_replay_sqdiff_stdiff(packet: dict) -> bool:
    """Detect large positive sqDiff together with extreme negative stDiff."""
    sq_diff = packet.get("sqDiff", 0)
    st_diff = packet.get("stDiff", 0)
    return (sq_diff > 40) and (st_diff < -65000)

def rule_random_replay_time_fields(packet: dict) -> bool:
    """Detect excessive timestamp deviation and long idle time since last change."""
    timestamp_diff = packet.get("timestampDiff", 0)
    time_from_last_change = packet.get("timeFromLastChange", 0)
    return (timestamp_diff > 0.5) and (time_from_last_change > 60)

