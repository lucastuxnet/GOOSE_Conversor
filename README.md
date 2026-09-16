# rules2p4

Conversor de regras de detecção em Python para P4_16/TNA (Intel Tofino).

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

## Uso

```bash
python3 rules2p4.py rules_v1.py -o build --prog goose_ids --report
```

Saídas em `build/`:

- `goose_ids.p4` — programa TNA com as tabelas de faixa, `detect` e `DirectCounter`
- `setup_rules.py` — script BF-Runtime que popula ambas as tabelas

## Fluxo automatizado

```bash
./deploy.sh ~/rules_v1.py                 # converte, valida e compila
./deploy.sh ~/rules_v1.py --skip-build    # só converte e valida
```

Aborta com código 1 se a validação divergir ou se as entradas ternárias
excederem a capacidade da tabela `detect`. Passo a passo completo, incluindo
a execução no modelo, em `GUIA_rules2p4_tofino.md`.

## Tráfego de teste

```bash
python3 gen_test_traffic.py rules_v1.py -o test_goose.pcap
sudo tcpreplay -i veth0 test_goose.pcap
```

Gera um pacote por classe de ataque, mais tráfego normal, e imprime o veredito
esperado de cada um para conferência contra os contadores. A opção `--untagged`
produz quadros sem VLAN, exercitando o outro ramo do parser.

Os campos não relevantes a cada caso recebem valores **neutros**, não zero:
zero satisfaz predicados como `SqNum < 5`, o que faria todo pacote acionar
regras não pretendidas.

## Validação

```bash
python3 validate.py rules_v1.py -n 100000
```

Executa as funções Python originais e a simulação do pipeline sobre pacotes
aleatórios, comparando detecção e classe atribuída. Zero divergências é o
critério de aceitação.

## Formato de regra suportado

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

## Campos e escalas

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

## Integração no pipeline

O programa gerado assume que os campos GOOSE já chegam no header
`goose_feat_h`, preenchido por um estágio anterior (parser GOOSE completo ou
pré-processamento). Os campos derivados — `tDiff`, `stDiff`, `sqDiff`,
`timeFromLastChange` — exigem estado por gocbRef, o que no Tofino se faz com
`Register` + `RegisterAction` indexados por hash do identificador do fluxo.
Esse estágio não é gerado por este conversor.

## Contadores

A tabela `detect` tem `DirectCounter` associado. Para ler:

```
bfrt.goose_ids.pipe.Ingress.detect.operations_execute("SyncCounters")
bfrt.goose_ids.pipe.Ingress.detect.dump()
```

## Limites

- Entradas ternárias crescem com o produto cartesiano das faixas por regra.
  21 regras → 95 entradas. Regras com muitos campos de baixa seletividade
  expandem rápido; `--report` mostra a contagem antes do deploy.
- `size = 2048` na tabela `detect` é o teto atual; ajuste se o conjunto crescer.
- A regra de maior prioridade (menor índice) vence em caso de sobreposição,
  igual à ordem de avaliação sequencial no Python.
