# rules2p4 — GOOSE IDS em P4/Tofino

Conversor de regras de detecção em Python para P4_16/TNA (Intel Tofino) e guia
de execução fim a fim no `tofino-model` (P4Studio).

**Autores:** Lucas A. Martins¹, Éderson Rosa da Silva¹, Silvio E. Quincozes¹², Camilla B. Quincozes¹², Giovanni Siervo¹, Marcelo Caggiani Luizelli²
¹ Universidade Federal de Uberlândia (UFU) – Uberlândia, Brazil
² Universidade Federal do Pampa (UNIPAMPA) – Alegrete, Brazil

`{lucas.martins, camillaquincozes, sequincozes, gsiervo}@ufu.br`
`{marceloluizelli}@unipampa.edu.br`

---

## Sumário

1. [Motivação](#motivação)
2. [Versões](#versões)
3. [Visão geral do fluxo](#visão-geral-do-fluxo)
4. [Passo a passo](#passo-a-passo) — etapas 1 a 7
5. [Diagnóstico](#diagnóstico)
6. [Ciclo de iteração](#ciclo-de-iteração)
7. [Referência do conversor](#referência-do-conversor) — formato de regra, campos e escalas, contadores, limites
8. [Limitação importante](#limitação-importante)

---

## Motivação

O TNA não avalia comparações aritméticas arbitrárias em tempo de execução. Uma
regra como `SqNum < 5 and tDiff > 1500` não pode virar um `if` no dataplane sem
consumir ALUs e estágios de forma proibitiva quando há dezenas de regras.

A solução adotada é **discretização em faixas + match ternário**:

1. As constantes de todas as regras viram pontos de corte por campo.
2. Uma tabela `range` por campo mapeia o valor bruto para um índice de faixa
   (poucos bits). Essas tabelas são independentes e o compilador as aloca em
   paralelo no mesmo estágio.
3. Uma única tabela ternária `detect` casa combinações de índices de faixa.
   Campos não citados por uma regra recebem máscara zero (don't-care).
4. Prioridade da entrada = ordem da regra no arquivo original.

O resultado é O(1) em estágios independentemente do número de regras; o custo
cresce em entradas de TCAM, não em recursos de pipeline.

---

## Versões

### Releases do simulador (GOOSE_Simulator)

| Release | Data | Resumo |
|---|---|---|
| **v1** | 14/jun/2026 | Primeiro pipeline fim a fim: converter → validar → compilar → popular → injetar → ler contadores no `tofino-model`. |
| **v2** | 16/jul/2026 | Passe de correção nos defeitos que distorciam o resultado final (ver 0.1.1 abaixo). Reproduz as métricas reportadas. |

### Histórico do conversor `rules2p4`

| Versão | Antiga nomenclatura | Consumida por | Mudança principal |
|---|---|---|---|
| **0.1** | rev. 1 | `rules_v1.py` | Tradução inicial AST Python → P4_16/TNA com tabela ternária `detect` e tabelas de faixa por campo. Campos em 32 bits, offset binário `+2^31` para campos com sinal, escalas 10⁴ (`timestampDiff`) e 10⁶ (`delay`). |
| **0.1.1** | rev. 2 | `rules_v2.py` | Ações nomeadas por classe (`flag_grayhole`, `flag_injection`, …) em vez de `flag_attack` genérico; paridade dos ramos VLAN/untagged do parser; prioridade única por entrada TCAM; ajustes de escala apontados pelo `validate.py`; ordem obrigatória populate → inject → read. |
| **0.1.2** | rev. 3 | `rules_v3.py` | Faixas rederivadas para o conjunto regenerado pela LLM; larguras reduzidas de 32 para 16 bits — o match `range` do Tofino exige chaves de até 4 nibbles e o p4c rejeita 32 bits (`does not fit in under 5 PHV nibbles`). |
| **0.2** | — | `rules_v1` a `rules_v6` | Codificação com `bias` explícito e nova checagem de limiares (detalhes abaixo). Primeira versão a converter `rules_v2` e `rules_v3` sem alterar as regras. |

### Alterações da 0.2 (set/2026)

Objetivo: converter todos os conjuntos `rules_v1` a `rules_v6` e capturar as
detecções de cada regra nos contadores, sem reescrever limiares gerados pela
LLM.

`field_model.py`:

- Novo parâmetro `bias` em `FieldSpec`: offset explícito que substitui o
  offset binário simétrico (`2^(w-1)`) quando a faixa de limiares de um campo
  é assimétrica. Usado em:
  - `stDiff` (`bias=65001`): o limiar `-65000` de `rules_v2` exige 65001
    valores negativos, acima dos 32768 do offset simétrico. Escala fracionária
    não serve, porque colapsaria valores adjacentes e destruiria a fronteira
    do predicado.
  - `timeFromLastChange` (`bias=11`): o limiar `-10` de `rules_v3` exige
    valores negativos em um campo antes tratado como sem sinal.
- `scale` passa a aceitar float.

`rules2p4.py`:

- A verificação de limiares deixou de usar margem arbitrária (2% do domínio)
  e passou a testar se a saturação invalida o predicado: para cada operador,
  o corte gerado precisa cair dentro de `[0, 2^w - 1]`. Limiares encostados no
  teto ou no piso do domínio (como `stDiff > 500` com bias 65001) são aceitos;
  apenas cortes que sairiam do domínio abortam a conversão.
- Aviso informativo em `stderr` quando um limiar codifica a uma posição do
  extremo do domínio, para registro no log do experimento.

### Conjuntos de regras

| Arquivo | Descrição | Testado no `tofino-model` |
|---|---|---|
| `rules_v1.py` | Primeiro conjunto gerado pela LLM (baseline). | 0.1 |
| `rules_v2.py` | Conjunto alinhado às correções da 0.1.1. Limiar `stDiff < -65000` não representável antes da 0.2. | pendente (0.2) |
| `rules_v3.py` | Conjunto regenerado. Limiar `timeFromLastChange > -10` não representável antes da 0.2. | pendente (0.2) |
| `rules_v4.py` – `rules_v6.py` | Conjuntos posteriores. | 0.1.x |

Todos os conjuntos serão reexecutados com o conversor 0.2 para que o lote de
resultados use uma única versão do conversor.

---

## Visão geral do fluxo

| Etapa | O que acontece | Onde roda |
|---|---|---|
| 1 | Ambiente e variáveis | host |
| 2 | Conversão: `rules_vN.py` → `goose_ids.p4` + `setup_rules.py` | host |
| 3 | Validação semântica (oráculo Python) | host |
| 4 | Compilação P4 | host |
| 5 | Subir `tofino-model` + `bf_switchd` | 2 terminais |
| 6 | Popular tabelas via BF-Runtime | 3º terminal |
| 7 | Injetar tráfego e ler contadores | 4º terminal |

Etapas 1–4 rodam sem o switch. Se algo falhar ali, não adianta subir o modelo.

Fluxo automatizado para as etapas 2–4:

```bash
./deploy.sh ~/rules_v1.py                 # converte, valida e compila
./deploy.sh ~/rules_v1.py --skip-build    # só converte e valida
```

Aborta com código 1 se a validação divergir ou se as entradas ternárias
excederem a capacidade da tabela `detect`.

---

## Passo a passo

### 1. Ambiente

```bash
source ~/setup-open-p4studio.bash

echo "SDE.........: $SDE"
echo "SDE_INSTALL.: $SDE_INSTALL"
python3 --version
```

Se `$SDE` vier vazio, o script de ambiente não foi carregado — reveja a instalação antes de continuar.

Interfaces virtuais (uma vez por boot da máquina):

```bash
sudo ${SDE_INSTALL}/bin/veth_setup.sh 128
ip link show veth0 >/dev/null 2>&1 && echo "veths OK"
```

### 2. Gerar o P4 e o script de regras

```bash
cd ~/rules2p4

python3 rules2p4.py ~/rules_v1.py -o build --prog goose_ids --report
```

Saída esperada:

```
regras lidas ......... 21
campos ativos ........ 9
entradas ternárias ... 95
classes de ataque .... 8
```

Dois arquivos em `build/`:

- `goose_ids.p4` — programa TNA com as tabelas de faixa, `detect` e `DirectCounter`
- `setup_rules.py` — script BF-Runtime que popula ambas as tabelas

#### Interpretando o `--report`

O relatório lista faixas e bits por campo. **Vale conferir antes de compilar**, especialmente após regenerar as regras com o LLM:

- **Entradas ternárias muito acima de ~4× o número de regras** → alguma regra nova expandiu demais. A tabela `detect` tem `size = 2048`; passando disso, o compilador rejeita.
- **Campo com muitas faixas** → limiares demais sobre o mesmo campo, aumentando o produto cartesiano.
- **Aviso de limiar no extremo do domínio** (a partir da 0.2) → o valor codificado está encostado no piso ou no teto; é informativo, a conversão prossegue.

#### Erros comuns nesta etapa

| Mensagem | Causa | Correção |
|---|---|---|
| `campos não mapeados em FIELDS` | Regra usa campo novo | Adicione a `FIELDS` em `field_model.py` com largura, escala e sinal |
| `disjunção não suportada` | Regra usa `or` | Separe em duas funções `rule_*` — o match ternário faz a união |
| `comparação precisa ser variável/get vs constante` | Aritmética ou comparação entre dois campos | Reescreva a regra ou pré-compute o valor |
| `... a faixa que satisfaz o predicado cai fora do domínio [0, 65535]` | Limiar negativo em campo sem offset, ou fora do domínio codificado | Ajuste `bias` do campo em `field_model.py` (ver [Campos e escalas](#campos-e-escalas)) |

### 3. Validar antes de compilar

```bash
python3 validate.py ~/rules_v1.py -n 100000
```

Critério de aceitação — **as duas linhas de divergência em zero**:

```
divergência detecção ..... 0
divergência classe ....... 0
```

Divergência diferente de zero significa que a tradução não preserva a semântica das regras. Não prossiga: o pipeline vai classificar diferente do Python.

Causas mais prováveis:

- **Perda de precisão em ponto flutuante** — um limiar com mais casas decimais do que a escala do campo comporta faz valores distintos colapsarem na mesma faixa. Aumente `scale` do campo em `field_model.py` e revalide.
- **Saturação** — valores do tráfego fora do domínio codificado (ex.: `timestampDiff` acima de ±3,2767 s com escala 10⁴) saturam no extremo no P4, mas não no Python. Reduza a escala ou aplique o mesmo clamp no oráculo.

### 4. Compilar o P4

```bash
mkdir -p ~/open-p4studio/pkgsrc/p4-examples/p4_16_programs/goose_ids
cp build/goose_ids.p4 \
   ~/open-p4studio/pkgsrc/p4-examples/p4_16_programs/goose_ids/

cd ~/open-p4studio
./p4_build.sh pkgsrc/p4-examples/p4_16_programs/goose_ids/goose_ids.p4
```

Confirme que os artefatos existem:

```bash
ls -la $SDE_INSTALL/share/tofinopd/goose_ids/
```

Devem aparecer `context.json` e `pipe/tofino.bin`. Sem eles, a compilação falhou mesmo que o script tenha retornado zero.

**Se falhar por recursos** (`table placement failed`, `not enough stages`): reduza o número de regras ou consolide limiares próximos no arquivo Python. O relatório da etapa 2 já indicava o risco.

### 5. Subir modelo e switchd

**Terminal 1** — modelo:

```bash
source ~/setup-open-p4studio.bash
cd ~/open-p4studio
./run_tofino_model.sh -p goose_ids --arch tofino
```

**Terminal 2** — driver:

```bash
source ~/setup-open-p4studio.bash
cd ~/open-p4studio
./run_switchd.sh -p goose_ids --arch tofino
```

Aguarde o prompt `bfshell>` e a linha do gRPC:

```
bfshell> bfruntime gRPC server started on 0.0.0.0:50052
```

Leva um a dois minutos. Antes disso, a etapa 6 falha por conexão recusada.

### 6. Popular as tabelas

**Terminal 3:**

```bash
source ~/setup-open-p4studio.bash
cd ~/open-p4studio

ls -la ~/rules2p4/build/setup_rules.py   # confirme que existe

./run_bfshell.sh -b ~/rules2p4/build/setup_rules.py
```

Saída esperada:

```
tbl_band_SqNum: 8 faixas
tbl_band_StNum: 7 faixas
...
detect: 95 entradas
OK - regras carregadas
```

#### Se der erro de sintaxe da API

Os nomes de parâmetros do `range match` variam entre versões do SDE. Se aparecer `unexpected keyword argument`, inspecione a assinatura real no `bfshell` interativo:

```bash
./run_bfshell.sh
```

```
bfrt_python
bfrt.goose_ids.pipe.Ingress.tbl_band_SqNum.info(return_info=False)
bfrt.goose_ids.pipe.Ingress.detect.info(return_info=False)
```

Isso imprime os nomes exatos dos campos de chave e ações. Ajuste `bfrt_emitter.py` conforme o que aparecer e regenere. Os sufixos que o script assume hoje são `_start`/`_end` para `range` e `_mask` para `ternary`.

#### Verificar o que foi inserido

Ainda no `bfshell>`:

```
bfrt
goose_ids
pipe
Ingress
detect
dump
```

### 7. Injetar tráfego e conferir

**Terminal 4** — gerar o PCAP de teste:

```bash
cd ~/rules2p4
python3 gen_test_traffic.py ~/rules_v1.py -o test_goose.pcap
```

Gera um pacote por classe de ataque, mais tráfego normal, e imprime o veredito esperado de cada um:

```
  #  caso                    esperado         regras acionadas
  1  normal_1                NORMAL           -
  2  normal_2                NORMAL           -
  3  grayhole_sq_tdiff       grayhole         rule_grayhole_sq_tdiff
  ...
19 pacotes -> test_goose.pcap  (17 devem casar em detect, 2 normais)
```

Os campos não relevantes a cada caso recebem valores **neutros**, não zero: zero satisfaz predicados como `SqNum < 5`, o que faria todo pacote acionar regras não pretendidas.

Injetar:

```bash
sudo tcpreplay -i veth0 test_goose.pcap
```

Sem `tcpreplay` instalado:

```bash
sudo apt install -y tcpreplay
```

Ler os contadores — no **terminal 3**:

```bash
./run_bfshell.sh
```

```
bfrt_python
tbl = bfrt.goose_ids.pipe.Ingress.detect
tbl.operations_execute("SyncCounters")
tbl.dump(from_hw=True)
```

**Resultado esperado:** a soma dos contadores das entradas `flag_*` deve bater com o número de pacotes de ataque do gerador (17), e os 2 normais caem no `no_attack`.

#### Testar o caminho sem VLAN

O parser trata os dois casos. Para exercitar o ramo sem marcação:

```bash
python3 gen_test_traffic.py ~/rules_v1.py -o test_untagged.pcap --untagged
sudo tcpreplay -i veth0 test_untagged.pcap
```

Os contadores devem incrementar igual. Se só a versão com VLAN funcionar (ou vice-versa), o problema está na transição do parser.

---

## Diagnóstico

### Contadores zerados após injeção

Em ordem de probabilidade:

1. **Pacote não chegou ao parser GOOSE.** No terminal 1, o log do modelo mostra os headers válidos por pacote. Se aparecer só `ethernet` (sem `goose`), o EtherType não casou — confira o `0x88B8` no PCAP:
   ```bash
   tcpdump -r test_goose.pcap -xx -c 1 | head -5
   ```
2. **Tabelas de faixa não populadas.** Sem entradas, todo campo cai no `default_action` e vai para a faixa 0, que raramente casa em `detect`:
   ```
   bfrt.goose_ids.pipe.Ingress.tbl_band_SqNum.dump()
   ```
3. **Interface errada.** O `veth_setup.sh` cria pares; o modelo escuta em um lado específico. Teste `veth1` se `veth0` não funcionar.

### Contadores incrementam mas na entrada errada

Compare o `attack_id` retornado com a tabela impressa pelo gerador. Divergência aqui, com o `validate.py` passando, aponta para diferença entre a codificação do gerador de tráfego e a do plano de controle — verifique se `GOOSE_FIELDS` em `gen_test_traffic.py` está na mesma ordem que `goose_feat_h` no `goose_ids.p4`.

### Erro ao inserir entradas com prioridade repetida

Não deve ocorrer: cada entrada recebe prioridade única (1 a N), atribuída na ordem das regras. Se aparecer, o `bfrt_emitter.py` foi modificado — a unicidade é obrigatória no TCAM.

---

## Ciclo de iteração

Ao regenerar as regras com o LLM, o caminho curto:

```bash
cd ~/rules2p4

# 1. converter e conferir a expansão
python3 rules2p4.py ~/rules_v2.py -o build --prog goose_ids --report

# 2. validar — não pule esta etapa
python3 validate.py ~/rules_v2.py -n 100000

# 3. recompilar
cp build/goose_ids.p4 ~/open-p4studio/pkgsrc/p4-examples/p4_16_programs/goose_ids/
cd ~/open-p4studio && ./p4_build.sh pkgsrc/p4-examples/p4_16_programs/goose_ids/goose_ids.p4
```

Se apenas os **limiares** mudaram e os campos são os mesmos, o P4 muda também — as faixas são derivadas das constantes. Não dá para recarregar só as regras sem recompilar.

Ordem obrigatória no modelo: **popular → injetar → ler**. Rodar o `setup_rules.py` de novo depois da injeção zera os contadores.

---

## Referência do conversor

### Formato de regra suportado

```python
def rule_<classe>_<variante>(packet: dict) -> bool:
    x = packet.get("SqNum", 0)
    y = packet.get("tDiff", 0)
    return (x < 5) and (y > 1500)
```

Aceita: conjunções (`and`), operadores `< <= > >= == !=`, constantes negativas,
`packet.get()` inline ou via variável local.

Não aceita: disjunção (`or`), comparação entre dois campos, aritmética nos
operandos. Para `or`, separe em regras distintas — o match ternário já faz a
união naturalmente.

### Campos e escalas

Campos float são convertidos a inteiro por escala fixa antes da comparação.
Todas as larguras são limitadas a 16 bits pelo match `range` do Tofino.

| Campo | Largura | Escala | Offset |
|---|---|---|---|
| SqNum, StNum | 16 | 1 | 0 |
| cbStatus | 8 | 1 | 0 |
| sqDiff, tDiff | 16 | 1 | 2^15 (sinal) |
| stDiff | 16 | 1 | 65001 (bias explícito) |
| timeFromLastChange | 16 | 1 | 11 (bias explícito) |
| timestampDiff | 16 | 10000 | 2^15 (sinal) |
| delay | 16 | 1000000 | 0 |

O match `range` do Tofino é unsigned, então campos que assumem valores
negativos recebem um offset — binário simétrico (`signed=True`) ou explícito
(`bias=N`) quando a faixa de limiares é assimétrica. O plano de controle aplica
o mesmo offset ao inserir as faixas, então a ordenação é preservada. Valores
fora do domínio codificado saturam nos extremos; o conversor aborta apenas
quando a saturação faria a faixa de um predicado deixar de existir.

A escala do `timestampDiff` é 10⁴ porque as regras usam limiares com quatro
casas decimais (`0.1721`). Escala menor colapsa valores distintos na mesma
faixa e gera divergência.

### Contadores

A tabela `detect` tem `DirectCounter` associado. Para ler:

```
bfrt.goose_ids.pipe.Ingress.detect.operations_execute("SyncCounters")
bfrt.goose_ids.pipe.Ingress.detect.dump()
```

### Limites

- Entradas ternárias crescem com o produto cartesiano das faixas por regra.
  21 regras → 95 entradas. Regras com muitos campos de baixa seletividade
  expandem rápido; `--report` mostra a contagem antes do deploy.
- `size = 2048` na tabela `detect` é o teto atual; ajuste se o conjunto crescer.
- A regra de maior prioridade (menor índice) vence em caso de sobreposição,
  igual à ordem de avaliação sequencial no Python.

---

## Limitação importante

O `goose_ids.p4` assume que os campos chegam prontos no header `goose_feat_h`, preenchido por um estágio anterior (parser GOOSE completo ou pré-processamento). Quatro deles são derivados e exigem estado por publicador (`gocbRef`):

| Campo | Como se obtém |
|---|---|
| `tDiff` | diferença entre timestamps de chegada consecutivos |
| `stDiff` | variação de `StNum` |
| `sqDiff` | variação de `SqNum` |
| `timeFromLastChange` | tempo desde a última mudança de `StNum` |

No Tofino isso exige `Register` + `RegisterAction` indexados por hash do `gocbRef`. **Esse estágio não é gerado pelo conversor.** O gerador de tráfego preenche os valores diretamente, o que permite validar a lógica de classificação, mas não substitui a extração real.

Em produção, esse módulo precisa existir a montante. É a parte de maior dificuldade da implementação completa — cada `RegisterAction` admite uma única operação de leitura-modificação-escrita por estágio.
