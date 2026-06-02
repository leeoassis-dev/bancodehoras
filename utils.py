from datetime import date, datetime, timedelta


def somente_digitos(valor):
    return ''.join(ch for ch in str(valor or '') if ch.isdigit())


def cpf_sem_pontuacao_sql(coluna):
    return f"REPLACE(REPLACE(REPLACE(COALESCE({coluna},''),'.',''),'-',''),' ','')"


def formatar_cpf(valor):
    d = somente_digitos(valor)
    if len(d) != 11:
        return valor or '\u2013'
    return f"{d[:3]}.{d[3:6]}.{d[6:9]}-{d[9:]}"


def horas_para_minutos(valor):
    try:
        h, m = map(int, str(valor).split(":"))
        if m < 0 or m > 59:
            return 0
        return h * 60 + m
    except Exception:
        return 0


def minutos_para_horas(valor):
    minutos = int(valor or 0)
    sinal = "-" if minutos < 0 else ""
    minutos = abs(minutos)
    return f"{sinal}{minutos // 60:02d}:{minutos % 60:02d}"


def formatar_data_br(valor):
    if not valor:
        return '\u2013'
    s = str(valor).strip()[:10]
    try:
        return date.fromisoformat(s).strftime('%d/%m/%Y')
    except Exception:
        return s


def formatar_datetime_br(valor):
    if not valor:
        return '\u2013'
    s = str(valor).strip()
    try:
        if len(s) >= 16:
            return datetime.strptime(s[:16], '%Y-%m-%d %H:%M').strftime('%d/%m/%Y %H:%M')
        return date.fromisoformat(s[:10]).strftime('%d/%m/%Y')
    except Exception:
        return s


def calcular_data_fim_periodo(data_inicio, quantidade, tipo):
    if tipo == 'eleicao' and quantidade > 1:
        try:
            d = date.fromisoformat(data_inicio)
            return (d + timedelta(days=quantidade - 1)).isoformat()
        except Exception:
            pass
    return data_inicio


def datas_periodo_consecutivo(data_inicio, quantidade):
    qtd = max(1, int(quantidade or 1))
    d = date.fromisoformat(data_inicio)
    return [(d + timedelta(days=i)).isoformat() for i in range(qtd)]
