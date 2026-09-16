# Runbook — Pipeline GOOSE IDS (rules2p4 → Tofino)

Passo a passo para gerar, compilar, carregar e testar as regras de detecção GOOSE no simulador Tofino.

**Convenção usada aqui:** a variável `V` define qual versão de regras está sendo testada. Defina-a uma vez em cada terminal e todos os caminhos (build, logs, pcap) saem separados por versão — assim uma rodada não sobrescreve a anterior.

**Diretórios:**

| Apelido | Caminho |
|---|---|
| Conversor | `/home/lucas/Documentos/Mestrado/Goose/Conversor` |
| SDE | `~/open-p4studio` |

---

## Ordem dos terminais

A ordem importa. O modelo Tofino precisa estar no ar antes do `switchd`, e o `switchd` antes do `bfshell` popular as tabelas.

```
T1 (setup + build)  →  T2 (tofino model)  →  T3 (switchd)  →  T4 (bfshell: regras)  →  T5 (tráfego)
                                                                                      T6 (inspeção)
```

Cada terminal precisa do ambiente carregado. Se um comando reclamar de `$SDE` vazio, você esqueceu o `source`.

---

## Terminal 1 — Setup das veths

```bash
{
  source ~/setup-open-p4studio.bash
  echo "SDE.........: $SDE"
  echo "SDE_INSTALL.: $SDE_INSTALL"
  sudo ${SDE_INSTALL}/bin/veth_setup.sh 128
  ip link show veth0 >/dev/null 2>&1 && echo "veths OK"
} 2>&1 | tee setup_veths.log
```

Só precisa rodar uma vez por boot. Se `ip -br link show | grep -c veth` já retorna 256, as interfaces estão de pé.

---

## Terminal 1 — Geração do P4 a partir das regras

Defina a versão e gere. Note o `build_v${V}` e os logs versionados:

```bash
cd /home/lucas/Documentos/Mestrado/Goose/Conversor
export V=6

python3 rules2p4.py rules_v${V}.py -o build_v${V} --prog goose_ids --report \
  2>&1 | tee "saida_v${V}.txt"

python3 validate.py rules_v${V}.py -n 100000 \
  2>&1 | tee "validacao_v${V}.txt"
```

Para testar outra versão, basta trocar `export V=1` e repetir o bloco.

> **Se der `ValueError: disjunção não suportada`:** o arquivo de regras tem um `or` dentro de um `return`. O parser só aceita conjunções puras (`and`), porque cada regra vira uma entrada de match-action. Distribua o `and` sobre o `or` e separe em duas funções. Ver o apêndice no fim deste documento.

---

## Terminal 1 — Compilação com p4c

Primeira vez apenas — criar o diretório do programa no SDE:

```bash
mkdir -p ~/open-p4studio/pkgsrc/p4-examples/p4_16_programs/goose_ids
```

Copiar e compilar:

```bash
cd /home/lucas/Documentos/Mestrado/Goose/Conversor
cp build_v${V}/goose_ids.p4 ~/open-p4studio/pkgsrc/p4-examples/p4_16_programs/goose_ids/

p4c --target tofino --arch tna \
    --program-name goose_ids \
    --bf-rt-schema $SDE_INSTALL/share/tofinopd/goose_ids/bf-rt.json \
    -o $SDE_INSTALL/share/tofinopd/goose_ids \
    ~/open-p4studio/pkgsrc/p4-examples/p4_16_programs/goose_ids/goose_ids.p4 \
    2>&1 | tee "p4c_build_v${V}_$(date +%Y%m%d_%H%M%S).log"
```

O nome do programa é sempre `goose_ids`, independente da versão de regras — o que muda é o conteúdo. Por isso o log carrega `v${V}`: é o único rastro de qual versão está carregada no SDE neste momento.

---

## Terminal 1 — Verificação dos artefatos

```bash
ls -la $SDE_INSTALL/share/tofinopd/goose_ids/ | tee listagem_goose_ids.txt
```

```bash
{
  python3 -m json.tool $SDE_INSTALL/share/p4/targets/tofino/goose_ids.conf >/dev/null \
    && echo "JSON ok" || echo "FALTA ou inválido: goose_ids.conf"

  for f in bf-rt.json pipe/context.json pipe/tofino.bin; do
    [ -f "$SDE_INSTALL/share/tofinopd/goose_ids/$f" ] && echo "ok    $f" || echo "FALTA $f"
  done
} 2>&1 | tee verificacao.log
```

Os três arquivos precisam existir antes de seguir. Se `tofino.bin` faltar, a compilação falhou mesmo que o `p4c` não tenha retornado erro visível — confira o log do passo anterior.

---

## Terminal 2 — Modelo Tofino

```bash
source ~/setup-open-p4studio.bash
cd ~/open-p4studio
./run_tofino_model.sh -p goose_ids --arch tofino 2>&1 | tee "tofino_model_$(date +%Y%m%d_%H%M%S).log"
```

Deixe rodando. Espere as portas aparecerem antes de abrir o próximo terminal.

---

## Terminal 3 — switchd

```bash
source ~/setup-open-p4studio.bash
cd ~/open-p4studio
./run_switchd.sh -p goose_ids --arch tofino 2>&1 | tee "switchd_$(date +%Y%m%d_%H%M%S).log"
```

Deixe rodando. Espere o prompt `bfshell>` aparecer — é o sinal de que o programa carregou.

---

## Terminal 4 — Popular as tabelas de regras

```bash
source ~/setup-open-p4studio.bash
cd ~/open-p4studio
./run_bfshell.sh -b /home/lucas/Documentos/Mestrado/Goose/Conversor/build_v${V}/setup_rules.py \
  2>&1 | tee "bfshell_setup_v${V}_$(date +%Y%m%d_%H%M%S).log"
```

> Se `V` não estiver definida neste terminal, o caminho sai quebrado. Rode `export V=6` antes.

---

## Terminal 5 — Gerar e reproduzir tráfego

```bash
cd /home/lucas/Documentos/Mestrado/Goose/Conversor
export V=6

(
  echo "=== Gerando tráfego de teste v${V} - $(date) ==="
  python3 gen_test_traffic.py rules_v${V}.py -o test_goose_v${V}.pcap || exit 1
  echo ""

  echo "=== Verificando interfaces veth ==="
  ip -br link show | grep veth | head
  echo ""

  echo "=== Reproduzindo tráfego ==="
  sudo tcpreplay -i veth0 test_goose_v${V}.pcap
  echo ""
  echo "=== Fim - $(date) ==="
) 2>&1 | tee -a test_traffic.log
```

Note os parênteses no lugar das chaves: com `{ }`, o `|| exit 1` encerraria o seu shell inteiro. Com `( )`, aborta só o bloco.

O `tee -a` acumula no mesmo log em vez de apagar o anterior — assim as rodadas de v1 e v6 ficam ambas registradas, com timestamp para separar.

---

## Terminal 6 — Inspeção interativa

```bash
source ~/setup-open-p4studio.bash
cd ~/open-p4studio
script -c "./run_bfshell.sh" bfshell_session.log
```

Dentro do bfshell:

```python
bfrt_python
d = bfrt.goose_ids.pipe.Ingress.detect
exec(open('/home/lucas/Documentos/Mestrado/Goose/Conversor/build_v6/setup_rules.py').read())
hits()
```

> O `exec(...)` refaz o que o Terminal 4 já fez. Use um **ou** o outro, não os dois — recarregar as mesmas entradas pode gerar erro de chave duplicada ou zerar os contadores no meio da medição. Se o Terminal 4 já rodou, pule direto para `hits()`.

O `script` grava a sessão inteira em `bfshell_session.log`, incluindo o que você digita.

---

## Ciclo completo para trocar de versão

Para rodar a v1 depois da v6, sem desmontar tudo:

1. **T1:** `export V=1` → regenerar (`rules2p4`) → `cp` → `p4c` → verificar
2. **T3:** parar e reiniciar o `switchd` (ele precisa recarregar o binário novo)
3. **T4:** `export V=1` → rodar o `setup_rules.py` do `build_v1`
4. **T5:** `export V=1` → gerar e reproduzir o pcap

O modelo Tofino (T2) geralmente sobrevive à troca. Se o `switchd` não reconectar, reinicie o T2 também e refaça na ordem.

---

## Apêndice — Corrigindo `or` nas regras

O `rules_v6.py` tem um `or` em `rule_injection_state_anomaly`. Substitua a função por estas duas:

```python
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
```

**Efeito na contagem:** um pacote que satisfaça as duas condições agora dispara dois alertas onde antes disparava um. Se o `validate.py` soma alertas por regra, a taxa dessa classe sobe artificialmente; se agrega por pacote, não muda nada. Confira antes de comparar v6 com as versões anteriores.

**Prevenção:** como as regras vêm do LLM, isso vai reincidir. Vale acrescentar ao prompt de geração: *cada regra deve ser uma única conjunção de comparações; nunca use `or` — separe em funções distintas.*

---

## Checklist rápido de falhas

| Sintoma | Causa provável |
|---|---|
| `can't open file 'gen_test_traffic.py'` | Não está no diretório Conversor |
| `Error opening pcap file` | A geração falhou antes; o pcap nunca foi criado |
| `ValueError: disjunção não suportada` | `or` no `return` de alguma regra |
| `$SDE` vazio | Faltou `source ~/setup-open-p4studio.bash` neste terminal |
| `FALTA pipe/tofino.bin` | p4c falhou — ver o log de build |
| bfshell não conecta | `switchd` não está rodando, ou modelo Tofino caiu |
| Caminho com `build_v/` | `V` não definida neste terminal |
