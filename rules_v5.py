# Regras de detecção geradas pelo LLM (limpas)
# Origem: rules_raw.py
# Data: 14/09/2026 00:31:15
# Para uso no pipeline de detecção GOOSE IEC 61850

def rule_grayhole_sq_low_tdiff_high(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de grayhole (SqNum baixo e tDiff alto)."""
    sq_num = packet.get("SqNum", 0)
    t_diff = packet.get("tDiff", 0)
    return (sq_num < 5) and (t_diff > 1000)

def rule_grayhole_sq_low_stdiff_high(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de grayhole (SqNum baixo e stDiff alto)."""
    sq_num = packet.get("SqNum", 0)
    st_diff = packet.get("stDiff", 0)
    return (sq_num < 5) and (st_diff > 500)

def rule_grayhole_sq_very_low_timefromlastchange_high(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de grayhole (SqNum muito baixo e timeFromLastChange alto)."""
    sq_num = packet.get("SqNum", 0)
    time_from_last_change = packet.get("timeFromLastChange", 0)
    return (sq_num < 3) and (time_from_last_change > 100)


# === high_StNum ===

def rule_high_StNum_stnum_sqnum(packet: dict) -> bool:
    """Detect high StNum based on elevated StNum and SqNum."""
    stnum = packet.get("StNum", 0)
    sqnum = packet.get("SqNum", 0)
    return stnum > 679.0 and sqnum > 55.0

def rule_high_StNum_tdiff_timestampdiff(packet: dict) -> bool:
    """Detect high StNum based on excessive tDiff and timestampDiff."""
    tdiff = packet.get("tDiff", 0)
    tsdiff = packet.get("timestampDiff", 0)
    return tdiff > 1422.2 and tsdiff > 0.3765


# === injection ===

def rule_injection_sq_st(packet: dict) -> bool:
    """Detect injection based on anomalously high SqNum and low StNum."""
    sq_num = packet.get("SqNum", 0)
    st_num = packet.get("StNum", 0)
    return sq_num > 70 and st_num < 20

def rule_inverse_replay_stDiff_tDiff(packet: dict) -> bool:
    """Detect inverse_replay via high stDiff and high tDiff."""
    stDiff = packet.get("stDiff", 0)
    tDiff = packet.get("tDiff", 0)
    return stDiff > 392 and tDiff > 1422.2

def rule_masquerade_fake_normal_stnum_stdiff(packet):
    stnum = packet.get("StNum", 0)
    stdiff = packet.get("stDiff", 0)
    return stnum > 679 and stdiff > 392

def rule_poisoned_high_rate_stnum_delay(packet: dict) -> bool:
    stNum = packet.get("StNum", 0)
    delay = packet.get("delay", 0.0)
    return (stNum > 679.0) and (delay > 0.0004)

