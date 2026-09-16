# Regras de detecção geradas pelo LLM (limpas)
# Origem: rules_raw.py
# Data: 13/09/2026 23:09:33
# Para uso no pipeline de detecção GOOSE IEC 61850

def rule_grayhole_low_sqnum_high_tdiff(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de grayhole."""
    sq_num = packet.get("SqNum", 0)
    t_diff = packet.get("tDiff", 0)
    return (sq_num < 5) and (t_diff > 1000)

def rule_grayhole_low_sqnum_high_stdiff(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de grayhole."""
    sq_num = packet.get("SqNum", 0)
    st_diff = packet.get("stDiff", 0)
    return (sq_num < 5) and (st_diff > 500)

def rule_grayhole_low_sqnum_high_tflc(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de grayhole."""
    sq_num = packet.get("SqNum", 0)
    tflc = packet.get("timeFromLastChange", 0)
    return (sq_num < 3) and (tflc > 100)

def rule_grayhole_low_sqnum_high_stnum(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de grayhole."""
    sq_num = packet.get("SqNum", 0)
    st_num = packet.get("StNum", 0)
    return (sq_num < 5) and (st_num > 679)


# === high_StNum ===

def rule_high_StNum_stnum_stdiff(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de high_StNum."""
    stnum = packet.get("StNum", 0)
    stdiff = packet.get("stDiff", 0)
    return (stnum > 679.0) and (stdiff > 392.0)

def rule_high_StNum_stnum_time(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de high_StNum."""
    stnum = packet.get("StNum", 0)
    time_from_last_change = packet.get("timeFromLastChange", 0)
    return (stnum > 679.0) and (time_from_last_change < 0.0)


# === inverse_replay ===

def rule_inverse_replay_low_seq_state(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de inverse_replay."""
    sq_num = packet.get("SqNum", 0)
    st_num = packet.get("StNum", 0)
    return (sq_num < 1.0) and (st_num < 35.0)

def rule_inverse_replay_time_jump(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de inverse_replay."""
    time_from_last_change = packet.get("timeFromLastChange", 0)
    t_diff = packet.get("tDiff", 0)
    return (time_from_last_change > 50.9807) and (t_diff > 1422.2)


# === random_replay ===

def rule_random_replay_stdiff_extreme(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de random_replay."""
    st_diff = packet.get("stDiff", 0)
    sq_num = packet.get("SqNum", 0)
    return (st_diff < -40000) and (sq_num > 5)

def rule_random_replay_sqnum_high_stnum_low(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de random_replay."""
    sq_num = packet.get("SqNum", 0)
    st_num = packet.get("StNum", 0)
    return (sq_num > 55) and (st_num < 100)

def rule_random_replay_sqdiff_high_stdiff_neg(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de random_replay."""
    sq_diff = packet.get("sqDiff", 0)
    st_diff = packet.get("stDiff", 0)
    return (sq_diff > 30) and (st_diff < -50000)

def rule_random_replay_stnum_low_sqnum_high(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de random_replay."""
    st_num = packet.get("StNum", 0)
    sq_num = packet.get("SqNum", 0)
    return (st_num < 35) and (sq_num > 55)

