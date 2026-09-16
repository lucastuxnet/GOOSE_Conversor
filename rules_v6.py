# Regras de detecção geradas pelo LLM (limpas)
# Origem: rules_raw.py
# Data: 14/09/2026 00:59:56
# Para uso no pipeline de detecção GOOSE IEC 61850

def rule_high_StNum_excessive_state_jump(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de high_StNum por salto excessivo de StNum/stDiff."""
    st_num = packet.get("StNum", 0)
    st_diff = packet.get("stDiff", 0)
    return (st_num > 679.0) and (st_diff > 392.0)

def rule_high_StNum_causality_violation(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de high_StNum por violação de causalidade temporal."""
    time_from_last_change = packet.get("timeFromLastChange", 0)
    t_diff = packet.get("tDiff", 0)
    return (time_from_last_change < 0) and (t_diff > 1422.2)


# === injection ===

def rule_injection_seq_burst(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de injection por rajada de sequência."""
    sqnum = packet.get("SqNum", 0)
    sqdiff = packet.get("sqDiff", 0)
    return (sqnum > 60) and (sqdiff > 40)

def rule_injection_state_anomaly_cb(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de injection por cbStatus fora de faixa."""
    stnum = packet.get("StNum", 0)
    cbstatus = packet.get("cbStatus", 0)
    return (stnum < 30) and (cbstatus > 1)

def rule_injection_state_anomaly_time(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de injection por timestamp retrógrado."""
    stnum = packet.get("StNum", 0)
    time_change = packet.get("timeFromLastChange", 0)
    return (stnum < 30) and (time_change < 0)


# === masquerade_fake_fault ===

def rule_masquerade_fake_fault_low_stnum_forced_cb(packet: dict) -> bool:
    """Detecta StNum anormalmente baixo combinado com cbStatus forçado a closed."""
    stnum = packet.get("StNum", 0)
    cb_status = packet.get("cbStatus", 0)
    return (stnum < 40) and (cb_status == 1.0)

def rule_masquerade_fake_fault_excessive_tdiff_timestamp_drift(packet: dict) -> bool:
    """Detecta intervalo excessivo entre mensagens com deriva de timestamp."""
    tdiff = packet.get("tDiff", 0)
    timestamp_diff = packet.get("timestampDiff", 0)
    return (tdiff > 1977.84) and (timestamp_diff > 0.1721)

def rule_masquerade_fake_fault_high_tdiff_stdiff_forced_cb(packet: dict) -> bool:
    """Detecta tDiff alto com stDiff anômalo e cbStatus forçado."""
    tdiff = packet.get("tDiff", 0)
    stdiff = packet.get("stDiff", 0)
    cb_status = packet.get("cbStatus", 0)
    return (tdiff > 1000) and (stdiff > 300) and (cb_status == 1.0)



