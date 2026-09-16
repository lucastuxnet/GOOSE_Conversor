#!/usr/bin/env python3
"""Populado por rules2p4. Executar via: run_bfshell.sh -b setup_rules.py

Nomes de parâmetro conforme a API bfrt_python:
  - ação da tabela de faixa tem sufixo do campo: add_with_set_band_<campo>
  - chave RANGE usa apenas o último componente: <campo>_start / <campo>_end
  - prioridade é MATCH_PRIORITY (sem cifrão, sem underscore inicial)
  - chave TERNARY da detect usa band_<campo> / band_<campo>_mask
"""

import json

P4_NAME = "goose_ids"
BANDS = json.loads(r"""{"SqNum": [[0, 60], [61, 65535]], "StNum": [[0, 29], [30, 39], [40, 679], [680, 65535]], "cbStatus": [[0, 0], [1, 1], [2, 255]], "sqDiff": [[0, 32808], [32809, 65535]], "stDiff": [[0, 65301], [65302, 65393], [65394, 65535]], "tDiff": [[0, 33768], [33769, 34190], [34191, 34746], [34747, 65535]], "timeFromLastChange": [[0, 10], [11, 65535]], "timestampDiff": [[0, 34489], [34490, 65535]]}""")
ENTRIES = json.loads(r"""[{"rule": "rule_high_StNum_excessive_state_jump", "attack": "high_StNum", "attack_id": 1, "rule_order": 1, "priority": 1, "key": {"SqNum": {"value": 0, "mask": 0}, "StNum": {"value": 3, "mask": 3}, "cbStatus": {"value": 0, "mask": 0}, "sqDiff": {"value": 0, "mask": 0}, "stDiff": {"value": 2, "mask": 3}, "tDiff": {"value": 0, "mask": 0}, "timeFromLastChange": {"value": 0, "mask": 0}, "timestampDiff": {"value": 0, "mask": 0}}}, {"rule": "rule_high_StNum_causality_violation", "attack": "high_StNum", "attack_id": 1, "rule_order": 2, "priority": 2, "key": {"SqNum": {"value": 0, "mask": 0}, "StNum": {"value": 0, "mask": 0}, "cbStatus": {"value": 0, "mask": 0}, "sqDiff": {"value": 0, "mask": 0}, "stDiff": {"value": 0, "mask": 0}, "tDiff": {"value": 2, "mask": 3}, "timeFromLastChange": {"value": 0, "mask": 1}, "timestampDiff": {"value": 0, "mask": 0}}}, {"rule": "rule_high_StNum_causality_violation", "attack": "high_StNum", "attack_id": 1, "rule_order": 2, "priority": 3, "key": {"SqNum": {"value": 0, "mask": 0}, "StNum": {"value": 0, "mask": 0}, "cbStatus": {"value": 0, "mask": 0}, "sqDiff": {"value": 0, "mask": 0}, "stDiff": {"value": 0, "mask": 0}, "tDiff": {"value": 3, "mask": 3}, "timeFromLastChange": {"value": 0, "mask": 1}, "timestampDiff": {"value": 0, "mask": 0}}}, {"rule": "rule_injection_seq_burst", "attack": "injection", "attack_id": 2, "rule_order": 3, "priority": 4, "key": {"SqNum": {"value": 1, "mask": 1}, "StNum": {"value": 0, "mask": 0}, "cbStatus": {"value": 0, "mask": 0}, "sqDiff": {"value": 1, "mask": 1}, "stDiff": {"value": 0, "mask": 0}, "tDiff": {"value": 0, "mask": 0}, "timeFromLastChange": {"value": 0, "mask": 0}, "timestampDiff": {"value": 0, "mask": 0}}}, {"rule": "rule_injection_state_anomaly_cb", "attack": "injection", "attack_id": 2, "rule_order": 4, "priority": 5, "key": {"SqNum": {"value": 0, "mask": 0}, "StNum": {"value": 0, "mask": 3}, "cbStatus": {"value": 2, "mask": 3}, "sqDiff": {"value": 0, "mask": 0}, "stDiff": {"value": 0, "mask": 0}, "tDiff": {"value": 0, "mask": 0}, "timeFromLastChange": {"value": 0, "mask": 0}, "timestampDiff": {"value": 0, "mask": 0}}}, {"rule": "rule_injection_state_anomaly_time", "attack": "injection", "attack_id": 2, "rule_order": 5, "priority": 6, "key": {"SqNum": {"value": 0, "mask": 0}, "StNum": {"value": 0, "mask": 3}, "cbStatus": {"value": 0, "mask": 0}, "sqDiff": {"value": 0, "mask": 0}, "stDiff": {"value": 0, "mask": 0}, "tDiff": {"value": 0, "mask": 0}, "timeFromLastChange": {"value": 0, "mask": 1}, "timestampDiff": {"value": 0, "mask": 0}}}, {"rule": "rule_masquerade_fake_fault_low_stnum_forced_cb", "attack": "masquerade_fake_fault", "attack_id": 3, "rule_order": 6, "priority": 7, "key": {"SqNum": {"value": 0, "mask": 0}, "StNum": {"value": 0, "mask": 3}, "cbStatus": {"value": 1, "mask": 3}, "sqDiff": {"value": 0, "mask": 0}, "stDiff": {"value": 0, "mask": 0}, "tDiff": {"value": 0, "mask": 0}, "timeFromLastChange": {"value": 0, "mask": 0}, "timestampDiff": {"value": 0, "mask": 0}}}, {"rule": "rule_masquerade_fake_fault_low_stnum_forced_cb", "attack": "masquerade_fake_fault", "attack_id": 3, "rule_order": 6, "priority": 8, "key": {"SqNum": {"value": 0, "mask": 0}, "StNum": {"value": 1, "mask": 3}, "cbStatus": {"value": 1, "mask": 3}, "sqDiff": {"value": 0, "mask": 0}, "stDiff": {"value": 0, "mask": 0}, "tDiff": {"value": 0, "mask": 0}, "timeFromLastChange": {"value": 0, "mask": 0}, "timestampDiff": {"value": 0, "mask": 0}}}, {"rule": "rule_masquerade_fake_fault_excessive_tdiff_timestamp_drift", "attack": "masquerade_fake_fault", "attack_id": 3, "rule_order": 7, "priority": 9, "key": {"SqNum": {"value": 0, "mask": 0}, "StNum": {"value": 0, "mask": 0}, "cbStatus": {"value": 0, "mask": 0}, "sqDiff": {"value": 0, "mask": 0}, "stDiff": {"value": 0, "mask": 0}, "tDiff": {"value": 3, "mask": 3}, "timeFromLastChange": {"value": 0, "mask": 0}, "timestampDiff": {"value": 1, "mask": 1}}}, {"rule": "rule_masquerade_fake_fault_high_tdiff_stdiff_forced_cb", "attack": "masquerade_fake_fault", "attack_id": 3, "rule_order": 8, "priority": 10, "key": {"SqNum": {"value": 0, "mask": 0}, "StNum": {"value": 0, "mask": 0}, "cbStatus": {"value": 1, "mask": 3}, "sqDiff": {"value": 0, "mask": 0}, "stDiff": {"value": 1, "mask": 3}, "tDiff": {"value": 1, "mask": 3}, "timeFromLastChange": {"value": 0, "mask": 0}, "timestampDiff": {"value": 0, "mask": 0}}}, {"rule": "rule_masquerade_fake_fault_high_tdiff_stdiff_forced_cb", "attack": "masquerade_fake_fault", "attack_id": 3, "rule_order": 8, "priority": 11, "key": {"SqNum": {"value": 0, "mask": 0}, "StNum": {"value": 0, "mask": 0}, "cbStatus": {"value": 1, "mask": 3}, "sqDiff": {"value": 0, "mask": 0}, "stDiff": {"value": 2, "mask": 3}, "tDiff": {"value": 1, "mask": 3}, "timeFromLastChange": {"value": 0, "mask": 0}, "timestampDiff": {"value": 0, "mask": 0}}}, {"rule": "rule_masquerade_fake_fault_high_tdiff_stdiff_forced_cb", "attack": "masquerade_fake_fault", "attack_id": 3, "rule_order": 8, "priority": 12, "key": {"SqNum": {"value": 0, "mask": 0}, "StNum": {"value": 0, "mask": 0}, "cbStatus": {"value": 1, "mask": 3}, "sqDiff": {"value": 0, "mask": 0}, "stDiff": {"value": 1, "mask": 3}, "tDiff": {"value": 2, "mask": 3}, "timeFromLastChange": {"value": 0, "mask": 0}, "timestampDiff": {"value": 0, "mask": 0}}}, {"rule": "rule_masquerade_fake_fault_high_tdiff_stdiff_forced_cb", "attack": "masquerade_fake_fault", "attack_id": 3, "rule_order": 8, "priority": 13, "key": {"SqNum": {"value": 0, "mask": 0}, "StNum": {"value": 0, "mask": 0}, "cbStatus": {"value": 1, "mask": 3}, "sqDiff": {"value": 0, "mask": 0}, "stDiff": {"value": 2, "mask": 3}, "tDiff": {"value": 2, "mask": 3}, "timeFromLastChange": {"value": 0, "mask": 0}, "timestampDiff": {"value": 0, "mask": 0}}}, {"rule": "rule_masquerade_fake_fault_high_tdiff_stdiff_forced_cb", "attack": "masquerade_fake_fault", "attack_id": 3, "rule_order": 8, "priority": 14, "key": {"SqNum": {"value": 0, "mask": 0}, "StNum": {"value": 0, "mask": 0}, "cbStatus": {"value": 1, "mask": 3}, "sqDiff": {"value": 0, "mask": 0}, "stDiff": {"value": 1, "mask": 3}, "tDiff": {"value": 3, "mask": 3}, "timeFromLastChange": {"value": 0, "mask": 0}, "timestampDiff": {"value": 0, "mask": 0}}}, {"rule": "rule_masquerade_fake_fault_high_tdiff_stdiff_forced_cb", "attack": "masquerade_fake_fault", "attack_id": 3, "rule_order": 8, "priority": 15, "key": {"SqNum": {"value": 0, "mask": 0}, "StNum": {"value": 0, "mask": 0}, "cbStatus": {"value": 1, "mask": 3}, "sqDiff": {"value": 0, "mask": 0}, "stDiff": {"value": 2, "mask": 3}, "tDiff": {"value": 3, "mask": 3}, "timeFromLastChange": {"value": 0, "mask": 0}, "timestampDiff": {"value": 0, "mask": 0}}}]""")

p4 = bfrt.goose_ids.pipe


def populate_bands():
    total = 0
    for field, ranges in BANDS.items():
        tbl = getattr(p4.Ingress, "tbl_band_" + field)
        tbl.clear()
        add = getattr(tbl, "add_with_set_band_" + field)
        for idx, (lo, hi) in enumerate(ranges):
            add(**{
                field + "_start": lo,
                field + "_end": hi,
                "MATCH_PRIORITY": idx,
                "idx": idx,
            })
        total += len(ranges)
        print("  tbl_band_%-20s %d faixas" % (field, len(ranges)))
    print("faixas inseridas: %d" % total)


def populate_detect():
    tbl = p4.Ingress.detect
    tbl.clear()
    for e in ENTRIES:
        kwargs = {"MATCH_PRIORITY": e["priority"]}
        for field, k in e["key"].items():
            kwargs["band_" + field] = k["value"]
            kwargs["band_" + field + "_mask"] = k["mask"]
        # Ação nomeada por classe (Opção A): sem parâmetro attack_id.
        add = getattr(tbl, "add_with_flag_" + e["attack"])
        add(**kwargs)
    print("detect: %d entradas" % len(ENTRIES))


def show_counters():
    """Contadores por entrada. Chame após injetar tráfego."""
    tbl = p4.Ingress.detect
    tbl.operation_counter_sync()
    tbl.dump(from_hw=True)


def hits():
    """Só as entradas que contaram pacotes, agrupadas por classe.

    Lê pela ação da entrada (flag_<classe>), sem parsear texto do dump —
    a classe vem do nome da ação, não de um campo de dado.
    Nesta versão do SDE, ent.data já é um dict com chaves em bytes.
    """
    tbl = p4.Ingress.detect
    tbl.operation_counter_sync()
    por_classe = {}
    total = 0
    for ent in tbl.get(regex=True, print_ents=False):
        d = ent.data
        if hasattr(d, "to_dict"):
            d = d.to_dict()
        pkts = d.get(b"$COUNTER_SPEC_PKTS", d.get("$COUNTER_SPEC_PKTS", 0)) or 0
        if not pkts:
            continue
        acao = getattr(ent, "action", None) or "?"
        classe = acao.split("flag_", 1)[-1] if "flag_" in acao else acao
        por_classe[classe] = por_classe.get(classe, 0) + pkts
        total += pkts
    for classe in sorted(por_classe):
        print("%4d pkts  %s" % (por_classe[classe], classe))
    print("---")
    print("%d classes com trafego, %d pacotes no total" % (len(por_classe), total))


populate_bands()
populate_detect()
print("OK - regras carregadas")
