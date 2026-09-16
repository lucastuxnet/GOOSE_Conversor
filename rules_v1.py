# Regras de detecção geradas pelo LLM (limpas)
# Origem: rules_raw.py
# Data: 14/09/2026 01:09:41
# Para uso no pipeline de detecção GOOSE IEC 61850

def rule_grayhole_sq_tdiff(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de grayhole."""
    sq = packet.get("SqNum", 0)
    td = packet.get("tDiff", 0)
    return (sq < 5) and (td > 1000)

def rule_grayhole_sq_stdiff(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de grayhole."""
    sq = packet.get("SqNum", 0)
    sd = packet.get("stDiff", 0)
    return (sq < 5) and (sd > 500)


# === high_StNum ===

def rule_high_StNum_simple(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de high_StNum."""
    stnum = packet.get("StNum", 0)
    stdiff = packet.get("stDiff", 0)
    return (stnum > 800) and (stdiff > 500)

def rule_high_StNum_advanced(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de high_StNum."""
    stnum = packet.get("StNum", 0)
    sqnum = packet.get("SqNum", 0)
    tdiff = packet.get("tDiff", 0)
    return (stnum > 800) and (sqnum > 60) and (tdiff > 2000)


# === injection ===

def rule_injection_sqnum_stnum(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de injection."""
    sq = packet.get("SqNum", 0)
    st = packet.get("StNum", 0)
    return (sq > 55) and (st < 35)

def rule_injection_cbstatus_ts(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de injection."""
    cb = packet.get("cbStatus", 0)
    ts = packet.get("timestampDiff", 0)
    return (cb > 1.0) and (ts > 0.4)


# === inverse_replay ===

def rule_inverse_replay_low_stnum_and_high_tdiff(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de inverse_replay."""
    stnum = packet.get("StNum", 0)
    tdiff = packet.get("tDiff", 0)
    return (stnum < 30) and (tdiff > 2000)

def rule_inverse_replay_low_sqnum_and_long_time(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de inverse_replay."""
    sqnum = packet.get("SqNum", 0)
    time_from_last = packet.get("timeFromLastChange", 0)
    return (sqnum < 0.5) and (time_from_last > 60)


# === masquerade_fake_fault ===

def rule_masquerade_fake_fault_low_stnum_cbstatus(packet: dict) -> bool:
    stnum = packet.get("StNum", 0)
    cb = packet.get("cbStatus", 0)
    return (stnum < 200) and (cb > 0.55)

def rule_masquerade_fake_fault_high_tdiff_ts(packet: dict) -> bool:
    td = packet.get("tDiff", 0)
    ts = packet.get("timestampDiff", 0)
    return (td > 1000) and (ts > 0.2)

def rule_masquerade_fake_fault_high_tdiff_stdiff(packet: dict) -> bool:
    td = packet.get("tDiff", 0)
    sd = packet.get("stDiff", 0)
    return (td > 1000) and (sd > 300)

def rule_masquerade_fake_fault_low_sqnum_ts(packet: dict) -> bool:
    sq = packet.get("SqNum", 0)
    ts = packet.get("timestampDiff", 0)
    return (sq < 10) and (ts > 0.3)


# === masquerade_fake_normal ===

def rule_masquerade_fake_normal_low_sqnum_high_stnum(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de masquerade_fake_normal."""
    sq = packet.get("SqNum", 0)
    st = packet.get("StNum", 0)
    return (sq < 1) and (st > 680)

def rule_masquerade_fake_normal_high_stdiff_high_stnum(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de masquerade_fake_normal."""
    stdiff = packet.get("stDiff", 0)
    st = packet.get("StNum", 0)
    return (stdiff > 400) and (st > 680)


# === poisoned_high_rate ===

def rule_poisoned_high_rate_timing(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de poisoned_high_rate."""
    t = packet.get("tDiff", 0)
    tf = packet.get("timeFromLastChange", 0)
    d = packet.get("delay", 0)
    return (t < -500) and (tf > 200) and (d > 0.001)

def rule_poisoned_high_rate_counters(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de poisoned_high_rate."""
    st = packet.get("StNum", 0)
    sq = packet.get("SqNum", 0)
    ts = packet.get("timestampDiff", 0)
    return (st > 800) and (sq < 1) and (ts > 1.0)


# === random_replay ===

def rule_random_replay_stdiff_sqnum(packet: dict) -> bool:
    """Detect random replay via extreme negative stDiff and high SqNum."""
    stdiff = packet.get("stDiff", 0)
    sqnum = packet.get("SqNum", 0)
    return (stdiff < -40000) and (sqnum > 55)

def rule_random_replay_sqnum_stnum(packet: dict) -> bool:
    """Detect random replay via high SqNum and low StNum."""
    sqnum = packet.get("SqNum", 0)
    stnum = packet.get("StNum", 0)
    return (sqnum > 55) and (stnum < 100)

def rule_random_replay_sqdiff_stdiff(packet: dict) -> bool:
    """Detect random replay via large sqDiff and extreme negative stDiff."""
    sqdiff = packet.get("sqDiff", 0)
    stdiff = packet.get("stDiff", 0)
    return (sqdiff > 30) and (stdiff < -50000)

def rule_random_replay_timestamp_time(packet: dict) -> bool:
    """Detect random replay via abnormal timestampDiff and timeFromLastChange."""
    tsdiff = packet.get("timestampDiff", 0)
    timechange = packet.get("timeFromLastChange", 0)
    return (tsdiff > 0.1721) and (timechange > 31.8974)

