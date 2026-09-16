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

Campos float são convertidos a inteiro por escala fixa antes da comparação:

| Campo | Largura | Escala | Sinal |
|---|---|---|---|
| SqNum, StNum, timeFromLastChange | 32 | 1 | não |
| cbStatus | 8 | 1 | não |
| sqDiff, stDiff, tDiff | 32 | 1 | sim |
| timestampDiff | 32 | 10000 | sim |
| delay | 32 | 1000000 | não |

Campos com sinal usam offset binário (`+2^31`), porque o match `range` do
Tofino é unsigned. O plano de controle aplica o mesmo offset ao inserir as
faixas, então a ordenação é preservada.

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
