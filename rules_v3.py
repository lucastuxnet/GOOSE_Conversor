# Regras de detecção geradas pelo LLM (limpas)
# Origem: rules_raw.py
# Data: 13/09/2026 22:42:57
# Para uso no pipeline de detecção GOOSE IEC 61850

def rule_grayhole_sqnum_low_stdiff_high(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de grayhole."""
    sq_num = packet.get("SqNum", 0)
    st_diff = packet.get("stDiff", 0)
    return (sq_num < 1) and (st_diff > 500)

def rule_grayhole_sqnum_low_tdiff_high(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de grayhole."""
    sq_num = packet.get("SqNum", 0)
    t_diff = packet.get("tDiff", 0)
    return (sq_num < 1) and (t_diff > 1500)

def rule_grayhole_stnum_low_sqnum_low(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de grayhole."""
    st_num = packet.get("StNum", 0)
    sq_num = packet.get("SqNum", 0)
    return (st_num < 30) and (sq_num < 1)

def rule_grayhole_delay_high_sqnum_low(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de grayhole."""
    delay = packet.get("delay", 0)
    sq_num = packet.get("SqNum", 0)
    return (delay > 0.0004) and (sq_num < 1)


# === high_StNum ===

def rule_high_StNum_conservadora(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de high_StNum."""
    StNum = packet.get("StNum", 0)
    SqNum = packet.get("SqNum", 0)
    stDiff = packet.get("stDiff", 0)
    sqDiff = packet.get("sqDiff", 0)
    return (StNum > 1000) and (SqNum > 70) and (stDiff > 500) and (sqDiff > 40)

def rule_high_StNum_tempo(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de high_StNum."""
    timestampDiff = packet.get("timestampDiff", 0)
    tDiff = packet.get("tDiff", 0)
    timeFromLastChange = packet.get("timeFromLastChange", 0)
    delay = packet.get("delay", 0)
    return (timestampDiff > 0.5) and (tDiff > 2000) and (timeFromLastChange < -10) and (delay > 0.0005)


# === injection ===

def rule_injection_a(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de injection."""
    sqnum = packet.get("SqNum", 0)
    stnum = packet.get("StNum", 0)
    st_diff = packet.get("stDiff", 0)
    sq_diff = packet.get("sqDiff", 0)
    cb_status = packet.get("cbStatus", 0)
    t_diff = packet.get("tDiff", 0)
    time_from_last_change = packet.get("timeFromLastChange", 0)
    return (sqnum > 55.0) and (stnum < 35.0) and (st_diff < -62000.0) and (sq_diff > 31.0) and (cb_status > 1.0) and (t_diff < -130.0) and (time_from_last_change < 0.0)

def rule_injection_b(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de injection."""
    sqnum = packet.get("SqNum", 0)
    stnum = packet.get("StNum", 0)
    st_diff = packet.get("stDiff", 0)
    sq_diff = packet.get("sqDiff", 0)
    cb_status = packet.get("cbStatus", 0)
    t_diff = packet.get("tDiff", 0)
    time_from_last_change = packet.get("timeFromLastChange", 0)
    return (sqnum > 60.0) and (stnum < 30.0) and (st_diff < -65000.0) and (sq_diff > 35.0) and (cb_status > 1.0) and (t_diff < -150.0) and (time_from_last_change < -10.0)


# === inverse_replay ===

def rule_inverse_replay_low_seq(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de inverse_replay por valores de sequência anormalmente baixos."""
    SqNum = packet.get("SqNum", 0)
    StNum = packet.get("StNum", 0)
    return (SqNum < 1.0) and (StNum < 35.0)

def rule_inverse_replay_high_jumps(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de inverse_replay por saltos de estado e tempo fora dos limites normais."""
    stDiff = packet.get("stDiff", 0)
    tDiff = packet.get("tDiff", 0)
    return (stDiff > 392.0) and (tDiff > 1977.8)


# === masquerade_fake_fault ===

def rule_masquerade_fake_fault_stnum_low(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de masquerade_fake_fault."""
    stnum = packet.get("StNum", 0)
    timestamp_diff = packet.get("timestampDiff", 0)
    return (stnum < 30) and (timestamp_diff > 0.4)

def rule_masquerade_fake_fault_cbstatus_high(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de masquerade_fake_fault."""
    cbstatus = packet.get("cbStatus", 0)
    tdiff = packet.get("tDiff", 0)
    return (cbstatus > 0.55) and (tdiff > 2000)

def rule_masquerade_fake_fault_tdiff_high(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de masquerade_fake_fault."""
    tdiff = packet.get("tDiff", 0)
    stnum = packet.get("StNum", 0)
    return (tdiff > 1977.8) and (stnum < 30)

def rule_masquerade_fake_fault_timestamp_high(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de masquerade_fake_fault."""
    timestamp_diff = packet.get("timestampDiff", 0)
    sqnum = packet.get("SqNum", 0)
    return (timestamp_diff > 0.3765) and (sqnum < 1)


# === masquerade_fake_normal ===

def rule_masquerade_fake_normal_low_sqnum_stnum(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de masquerade_fake_normal."""
    sqnum = packet.get("SqNum", 0)
    stnum = packet.get("StNum", 0)
    return (sqnum < 4.9) and (stnum > 669.4)

def rule_masquerade_fake_normal_stdiff_timefromlastchange(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de masquerade_fake_normal."""
    stDiff = packet.get("stDiff", 0)
    timeFromLastChange = packet.get("timeFromLastChange", 0)
    return (stDiff > 266.75) and (timeFromLastChange < 0.557)

