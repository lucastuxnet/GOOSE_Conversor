#!/usr/bin/env bash
# Coleta os logs/artefatos do pipeline GOOSE IDS gerados a partir de um horário.
#
# Uso:
#   ./coletar_logs.sh                       # desde hoje 21:30
#   ./coletar_logs.sh "today 18:00"         # outro horário de hoje
#   ./coletar_logs.sh "2026-09-14 21:30:00" # data e hora explícitas
#
# Atenção: "today" é resolvido pela data do sistema. Se você rodar isto depois
# da meia-noite, "today 21:30" aponta para HOJE à noite (futuro) e não acha
# nada — nesse caso passe a data completa.

set -uo pipefail

SINCE="${1:-today 21:30}"
DEST_BASE="$HOME/Documentos/Mestrado/Goose/Conversor/Ordem"
DEST="$DEST_BASE/coleta_$(date +%Y%m%d_%H%M%S)"
# Duas execuções no mesmo segundo não podem compartilhar a mesma pasta
[ -e "$DEST" ] && DEST="${DEST}_$$"

# Diretórios varridos, no formato "rótulo:caminho"
ORIGENS=(
  "home:$HOME"
  "conversor:$HOME/Documentos/Mestrado/Goose/Conversor"
  "sde:$HOME/open-p4studio"
)

# Padrões considerados artefato do pipeline
PATTERNS=(
  '*.log'
  'saida*.txt'
  'validacao*.txt'
  'listagem_goose_ids.txt'
  'test_goose*.pcap'
)

# Monta a expressão do find como array: ( -name A -o -name B ... )
NAME_EXPR=( '(' )
for i in "${!PATTERNS[@]}"; do
  [ "$i" -gt 0 ] && NAME_EXPR+=( -o )
  NAME_EXPR+=( -name "${PATTERNS[$i]}" )
done
NAME_EXPR+=( ')' )

# Valida o horário antes de varrer
if ! date -d "$SINCE" >/dev/null 2>&1; then
  echo "Horário inválido: $SINCE" >&2
  exit 1
fi

echo "Coletando arquivos modificados desde: $(date -d "$SINCE" '+%d/%m/%Y %H:%M')"
echo "Destino: $DEST"
echo ""

mkdir -p "$DEST"

for entrada in "${ORIGENS[@]}"; do
  rotulo="${entrada%%:*}"
  origem="${entrada#*:}"

  if [ ! -d "$origem" ]; then
    echo "  $rotulo: diretório não existe ($origem)"
    continue
  fi

  destino="$DEST/$rotulo"
  mkdir -p "$destino"

  n=0
  while IFS= read -r -d '' f; do
    if cp -p "$f" "$destino/"; then
      n=$((n + 1))
    else
      echo "  aviso: falha ao copiar $f" >&2
    fi
  done < <(find "$origem" -maxdepth 1 -type f "${NAME_EXPR[@]}" \
             -newermt "$SINCE" -print0 2>/dev/null)

  echo "  $rotulo: $n arquivo(s)"
  [ "$n" -eq 0 ] && rmdir "$destino" 2>/dev/null
done

echo ""

TOTAL=$(find "$DEST" -type f | wc -l)
if [ "$TOTAL" -eq 0 ]; then
  echo "Nenhum arquivo encontrado na janela. Confira o horário informado."
  rmdir "$DEST" 2>/dev/null
  exit 1
fi

# Inventário com data, tamanho e caminho relativo
{
  echo "Coleta gerada em: $(date)"
  echo "Janela: desde $(date -d "$SINCE" '+%d/%m/%Y %H:%M')"
  echo ""
  find "$DEST" -type f ! -name INVENTARIO.txt \
    -printf '%TY-%Tm-%Td %TH:%TM  %8s  %P\n' | sort
} > "$DEST/INVENTARIO.txt"

echo "Total: $TOTAL arquivo(s)"
echo ""
cat "$DEST/INVENTARIO.txt"
echo ""
echo "Para compactar:"
echo "  tar czf '${DEST}.tar.gz' -C '$(dirname "$DEST")' '$(basename "$DEST")'"
