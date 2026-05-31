from flask import Flask, render_template, request, redirect, url_for, flash, make_response, jsonify, session, g
from database import init_db, get_db, _consumir_fifo_raw, six_months_ago, five_months_ago, IS_POSTGRES
from datetime import datetime, date, timedelta
from urllib.parse import urlencode
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os, json, io, csv, secrets, string, smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from database import six_months_ago, five_months_ago

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "ibipora_banco_horas_2024_seguro")
app.url_map.strict_slashes = False

LIMITE_PAGAMENTO_MINUTOS = 45 * 60
MESES_PT = ["Jan","Fev","Mar","Abr","Mai","Jun","Jul","Ago","Set","Out","Nov","Dez"]
MESES_FULL = ["Janeiro","Fevereiro","Março","Abril","Maio","Junho",
              "Julho","Agosto","Setembro","Outubro","Novembro","Dezembro"]

# â”€â”€â”€ Auth helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

ROTAS_PUBLICAS = {'login','logout','recuperar_senha','recuperar_senha_token','setup',
                  'criar_conta','api_verificar_cpf','static'}

@app.errorhandler(404)
def pagina_nao_encontrada(e):
    """Evita 404 por pequenas variações de URL em produção."""
    caminho = (request.path or "").rstrip("/")
    rotas = {
        "/login": "login",
        "/recuperar-senha": "recuperar_senha",
        "/criar-conta": "criar_conta",
        "/portal": "portal",
        "/": "portal",
    }
    if caminho in rotas:
        return redirect(url_for(rotas[caminho]))
    return render_template("404.html"), 404

def gerar_senha_temp(n=10):
    chars = string.ascii_letters + string.digits + "!@#$"
    return ''.join(secrets.choice(chars) for _ in range(n))

def obter_config_smtp():
    """Lê SMTP do banco e, se faltar, usa variáveis de ambiente do Render."""
    db = get_db()
    cfg_db = {r['chave']: r['valor'] for r in db.execute("SELECT * FROM config").fetchall()}
    cfg = {
        'smtp_host': cfg_db.get('smtp_host') or os.environ.get('SMTP_HOST', ''),
        'smtp_port': cfg_db.get('smtp_port') or os.environ.get('SMTP_PORT', '587'),
        'smtp_user': cfg_db.get('smtp_user') or os.environ.get('SMTP_USER', ''),
        'smtp_pass': cfg_db.get('smtp_pass') or os.environ.get('SMTP_PASS', ''),
        'smtp_from': cfg_db.get('smtp_from') or os.environ.get('SMTP_FROM', ''),
        'smtp_tls': cfg_db.get('smtp_tls') or os.environ.get('SMTP_TLS', 'true'),
    }
    cfg['smtp_from'] = cfg['smtp_from'] or cfg['smtp_user']
    cfg['_configurado'] = bool(cfg['smtp_host'] and cfg['smtp_user'] and cfg['smtp_pass'])
    cfg['_origem'] = 'Render/env' if os.environ.get('SMTP_HOST') and not cfg_db.get('smtp_host') else 'Banco de dados'
    return cfg

def enviar_email_smtp(para, assunto, corpo_html):
    """Envia e-mail via SMTP configurado no banco. Retorna (ok, msg)."""
    try:
        cfg = obter_config_smtp()
        host = cfg.get('smtp_host','')
        porta = int(cfg.get('smtp_port','587') or 587)
        user = cfg.get('smtp_user','')
        pwd  = cfg.get('smtp_pass','')
        de   = cfg.get('smtp_from', user)
        tls  = str(cfg.get('smtp_tls','true')).lower() not in ('0','false','nao','não','no')
        if not host or not user or not pwd:
            return False, "SMTP_NAO_CONFIGURADO"
        msg = MIMEMultipart('alternative')
        msg['Subject'] = assunto; msg['From'] = de; msg['To'] = para
        msg.attach(MIMEText(corpo_html, 'html', 'utf-8'))
        smtp_cls = smtplib.SMTP_SSL if porta == 465 else smtplib.SMTP
        with smtp_cls(host, porta, timeout=20) as srv:
            srv.ehlo()
            if tls and porta != 465:
                srv.starttls()
                srv.ehlo()
            srv.login(user, pwd)
            srv.sendmail(de, para, msg.as_string())
        return True, ""
    except Exception as e:
        return False, str(e)

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'uid' not in session:
            flash("Faça login para continuar.", "warning")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def master_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get('nivel') != 'master':
            flash("Acesso restrito ao RH.", "danger")
            return redirect(url_for('portal'))
        return f(*args, **kwargs)
    return decorated

@app.context_processor
def injetar_usuario():
    return {
        'u_nivel': session.get('nivel'),
        'u_nome':  session.get('nome'),
        'u_cpf':   session.get('cpf'),
    }

@app.before_request
def verificar_acesso():
    if request.endpoint in ROTAS_PUBLICAS or request.endpoint is None:
        return None

    if 'uid' not in session:
        # Se não há usuários, redireciona para setup
        db = get_db()
        if db.execute("SELECT COUNT(*) FROM usuarios").fetchone()[0] == 0:
            return redirect(url_for('setup'))
        flash("Faça login para continuar.", "warning")
        return redirect(url_for('login'))

    nivel = session.get('nivel')

    # Senha temporária → forçar troca
    if session.get('temp') and request.endpoint != 'trocar_senha':
        flash("Sua senha é temporária. Defina uma nova senha para continuar.", "warning")
        return redirect(url_for('trocar_senha'))

    # Servidor → só meu_banco
    if nivel == 'servidor' and request.endpoint not in ('meu_banco', 'meu_cadastro', 'trocar_senha', 'logout'):
        return redirect(url_for('meu_banco'))

    # Secretário / Chefia → só consulta + api_historico
    if nivel in ('secretario', 'chefia') and request.endpoint not in (
            'portal', 'consulta', 'api_historico', 'meu_cadastro', 'trocar_senha', 'logout'):
        return redirect(url_for('consulta'))

    # Master: bloqueia apenas se tentar acessar rota de outro nível
    # (master tem acesso total, nada a bloquear)
    registrar_visualizacao()

# â”€â”€â”€ Utilitários â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def horas_para_minutos(s):
    try:
        h, m = map(int, str(s).split(":")); return h*60+m
    except: return 0

def minutos_para_horas(m):
    m = int(m or 0)
    s = "-" if m < 0 else ""; m = abs(m)
    return f"{s}{m//60:02d}:{m%60:02d}"

def minutos_num(m):
    return int(m or 0)

def registrar_auditoria(db, acao, entidade, entidade_id=None, matricula=None, servidor_nome=None, detalhe=""):
    db.execute("""
        INSERT INTO auditoria
            (criado_em, usuario_id, usuario_nome, usuario_cpf, acao, entidade, entidade_id, matricula, servidor_nome, detalhe)
        VALUES (?,?,?,?,?,?,?,?,?,?)
    """, (
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        session.get("uid"), session.get("nome"), session.get("cpf"),
        acao, entidade, str(entidade_id or ""), matricula, servidor_nome, detalhe
    ))

def registrar_visualizacao():
    if request.method != "GET" or "uid" not in session:
        return
    if request.endpoint in ROTAS_PUBLICAS or request.endpoint == "static":
        return
    if (request.path or "").startswith("/api/"):
        return
    titulos = {
        "dashboard": "Dashboard",
        "servidores": "Servidores",
        "arquivados": "Arquivados",
        "pagamentos_index": "Pagamentos",
        "relatorios": "Relatórios",
        "admin_usuarios": "Usuários",
        "admin_acessos": "Permissões",
        "admin_auditoria": "Auditoria",
        "consulta": "Consulta",
        "meu_banco": "Meu Banco",
    }
    try:
        db = get_db()
        db.execute("""
            INSERT INTO visualizacoes (usuario_id,usuario_nome,usuario_cpf,endpoint,caminho,titulo,criado_em)
            VALUES (?,?,?,?,?,?,?)
        """, (
            session.get("uid"), session.get("nome"), session.get("cpf"),
            request.endpoint or "", request.full_path.rstrip("?"),
            titulos.get(request.endpoint, request.path),
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))
        db.commit()
    except Exception:
        pass

def _csv_response(filename, headers, rows):
    out = io.StringIO()
    w = csv.writer(out, delimiter=";")
    w.writerow(headers)
    w.writerows(rows)
    r = make_response("\ufeff" + out.getvalue())
    r.headers["Content-Type"] = "text/csv; charset=utf-8"
    r.headers["Content-Disposition"] = f"attachment; filename={filename}.csv"
    return r

def _xlsx_response(filename, title, headers, rows):
    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill, Alignment
    from openpyxl.utils import get_column_letter

    wb = Workbook()
    ws = wb.active
    ws.title = "Relatório"
    ws.merge_cells(start_row=1, start_column=1, end_row=1, end_column=max(1, len(headers)))
    cell = ws.cell(1, 1, title)
    cell.font = Font(bold=True, color="FFFFFF", size=14)
    cell.fill = PatternFill("solid", fgColor="1A3A6B")
    cell.alignment = Alignment(horizontal="center")
    ws.append([])
    ws.append(headers)
    for c in ws[3]:
        c.font = Font(bold=True, color="FFFFFF")
        c.fill = PatternFill("solid", fgColor="1A3A6B")
        c.alignment = Alignment(horizontal="center")
    for row in rows:
        ws.append(row)
    for col in range(1, len(headers) + 1):
        max_len = max(len(str(ws.cell(r, col).value or "")) for r in range(1, ws.max_row + 1))
        ws.column_dimensions[get_column_letter(col)].width = min(max(max_len + 2, 12), 45)
    buf = io.BytesIO()
    wb.save(buf)
    buf.seek(0)
    r = make_response(buf.getvalue())
    r.headers["Content-Type"] = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    r.headers["Content-Disposition"] = f"attachment; filename={filename}.xlsx"
    return r

def _pdf_response(filename, title, headers, rows):
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=landscape(A4), rightMargin=18, leftMargin=18, topMargin=18, bottomMargin=18)
    styles = getSampleStyleSheet()
    story = [Paragraph(f"<b>{title}</b>", styles["Title"]), Spacer(1, 10)]
    table_data = [headers] + [[str(v or "") for v in row] for row in rows]
    table = Table(table_data, repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1A3A6B")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#D0D7DE")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F4F6F9")]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(table)
    doc.build(story)
    buf.seek(0)
    r = make_response(buf.getvalue())
    r.headers["Content-Type"] = "application/pdf"
    r.headers["Content-Disposition"] = f"attachment; filename={filename}.pdf"
    return r

def _export_response(fmt_out, filename, title, headers, rows):
    if fmt_out == "csv":
        return _csv_response(filename, headers, rows)
    if fmt_out == "xlsx":
        return _xlsx_response(filename, title, headers, rows)
    if fmt_out == "pdf":
        return _pdf_response(filename, title, headers, rows)
    return None

def calcular_saldo(db, matricula):
    c = db.execute("SELECT COALESCE(SUM(minutos_creditados),0) FROM lancamentos WHERE matricula=?", (matricula,)).fetchone()[0]
    u = db.execute("""SELECT COALESCE(SUM(c.minutos),0) FROM consumos c
                      JOIN lancamentos l ON l.id=c.lancamento_id WHERE l.matricula=?""", (matricula,)).fetchone()[0]
    return c - u

def lancamentos_com_saldo(db, matricula, apenas_vencidos=False):
    seis_meses = six_months_ago()
    f = "AND l.data <= ?" if apenas_vencidos else ""
    params = [matricula, seis_meses] if apenas_vencidos else [matricula]
    rows = db.execute(f"""
        SELECT l.*,
               COALESCE((SELECT SUM(c.minutos) FROM consumos c WHERE c.lancamento_id=l.id),0) AS consumido,
               CASE WHEN l.data<=? THEN 1 ELSE 0 END AS vencido
        FROM lancamentos l WHERE l.matricula=? {f} ORDER BY l.data ASC, l.id ASC
    """, [seis_meses] + params).fetchall()
    out = []
    for l in rows:
        sm = l["minutos_creditados"] - l["consumido"]
        if sm <= 0: continue
        mb = l["minutos_base"] if l["minutos_base"] else horas_para_minutos(l["horas_base"])
        sb = round(sm * mb / l["minutos_creditados"]) if l["minutos_creditados"] > 0 else 0
        out.append({**dict(l), "saldo_minutos": sm, "saldo_base_minutos": sb})
    return out

def _filtro_servidores(busca="", secretaria="", setor="", arquivado=0):
    f = f"WHERE s.arquivado={arquivado}"
    p = []
    if busca:
        f += " AND (s.matricula LIKE ? OR s.nome LIKE ?)"; p += [f"%{busca}%", f"%{busca}%"]
    if secretaria:
        f += " AND s.secretaria=?"; p.append(secretaria)
    if setor:
        f += " AND s.setor=?"; p.append(setor)
    return f, p

def _listas_filtro(db, arquivado=0):
    secs = [r[0] for r in db.execute(
        f"SELECT DISTINCT secretaria FROM servidores WHERE secretaria IS NOT NULL AND secretaria!='' AND arquivado={arquivado} ORDER BY secretaria").fetchall()]
    sets = [r[0] for r in db.execute(
        f"SELECT DISTINCT setor FROM servidores WHERE setor IS NOT NULL AND setor!='' AND arquivado={arquivado} ORDER BY setor").fetchall()]
    return secs, sets

def _fg(servidor): return bool(servidor["funcao_gratificada"])

def get_vinculos(obj):
    """Retorna lista de vínculos (secretarias/setores) de usuário ou pré-autorização."""
    if not obj:
        return []

    def valor(campo):
        try:
            return obj[campo]
        except Exception:
            try:
                return obj.get(campo)
            except Exception:
                return ""

    try:
        lst = json.loads(valor('vinculos') or '[]')
        if isinstance(lst, list) and lst:
            return [str(v).strip() for v in lst if str(v).strip()]
    except Exception:
        pass

    # Fallback para bases antigas que ainda usavam uma única secretaria/setor.
    v = (valor('secretaria') or valor('setor') or '').strip()
    return [v] if v else []

def usuario_pode_ver_matricula(db, matricula):
    """Valida acesso de leitura ao histórico conforme nível e vínculos da sessão."""
    nivel = session.get('nivel')
    if nivel == 'master':
        return True
    if nivel == 'servidor':
        return session.get('matricula') == matricula
    if nivel in ('secretario', 'chefia'):
        vinculos = session.get('vinculos') or []
        if not vinculos:
            return False
        srv = db.execute(
            "SELECT secretaria,setor FROM servidores WHERE matricula=? AND arquivado=0",
            (matricula,)
        ).fetchone()
        if not srv:
            return False
        campo = srv['secretaria'] if nivel == 'secretario' else srv['setor']
        return campo in vinculos
    return False

def ultimos_n_meses(n=6):
    hoje = date.today()
    res = []
    for i in range(n-1, -1, -1):
        off = hoje.month - 1 - i
        ano = hoje.year + off // 12
        mes = off % 12 + 1
        res.append({"ano": ano, "mes": mes,
                    "label": f"{MESES_PT[mes-1]}/{str(ano)[2:]}",
                    "ym": f"{ano:04d}-{mes:02d}"})
    return res

# â”€â”€â”€ Dashboard â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@app.route("/")
def dashboard():
    db = get_db()
    meses6 = ultimos_n_meses(6)
    servidores_atalho = db.execute(
        "SELECT matricula,nome,secretaria,setor FROM servidores WHERE arquivado=0 ORDER BY nome"
    ).fetchall()

    # Lançamentos por mês (horas base)
    lanc_mes = []
    comp_mes = []
    pag_mes  = []
    for m in meses6:
        v = db.execute("""SELECT COALESCE(SUM(l.minutos_base),0) FROM lancamentos l
                          JOIN servidores s ON s.matricula=l.matricula
                          WHERE substr(l.data,1,7)=? AND s.arquivado=0""", (m["ym"],)).fetchone()[0]
        lanc_mes.append(round(minutos_num(v)/60, 1))
        v2 = db.execute("""SELECT COALESCE(SUM(c2.minutos_compensados),0) FROM compensacoes c2
                           JOIN servidores s ON s.matricula=c2.matricula
                           WHERE substr(c2.data,1,7)=? AND s.arquivado=0""", (m["ym"],)).fetchone()[0]
        comp_mes.append(round(minutos_num(v2)/60, 1))
        v3 = db.execute("""SELECT COALESCE(SUM(ROUND(c.minutos*l.minutos_base*1.0/l.minutos_creditados)),0)
                           FROM pagamentos p
                           JOIN consumos c ON c.referencia_id=p.id AND c.tipo='pagamento'
                           JOIN lancamentos l ON l.id=c.lancamento_id
                           JOIN servidores s ON s.matricula=p.matricula
                           WHERE substr(p.data_pagamento,1,7)=? AND s.arquivado=0""", (m["ym"],)).fetchone()[0]
        pag_mes.append(round(minutos_num(v3)/60, 1))

    # KPIs
    saldo_total = db.execute("""
        SELECT COALESCE(SUM(
            (SELECT COALESCE(SUM(minutos_creditados),0) FROM lancamentos WHERE matricula=s.matricula)
            -(SELECT COALESCE(SUM(c.minutos),0) FROM consumos c JOIN lancamentos l ON l.id=c.lancamento_id WHERE l.matricula=s.matricula)
        ),0) FROM servidores s WHERE s.arquivado=0""").fetchone()[0]

    total_serv  = db.execute("SELECT COUNT(*) FROM servidores WHERE arquivado=0").fetchone()[0]
    serv_fg     = db.execute("SELECT COUNT(*) FROM servidores WHERE funcao_gratificada=1 AND arquivado=0").fetchone()[0]
    venc_count  = db.execute("""
        SELECT COUNT(DISTINCT l.matricula) FROM lancamentos l
        JOIN servidores s ON s.matricula=l.matricula
        WHERE l.data<=? AND s.arquivado=0
          AND l.minutos_creditados>(SELECT COALESCE(SUM(c.minutos),0) FROM consumos c WHERE c.lancamento_id=l.id)
    """, (six_months_ago(),)).fetchone()[0]

    # Próximos vencimentos (horas que vencerão em 30 dias)
    prox_venc = db.execute("""
        SELECT COUNT(DISTINCT l.matricula) FROM lancamentos l
        JOIN servidores s ON s.matricula=l.matricula
        WHERE l.data<=? AND l.data>? AND s.arquivado=0
          AND l.minutos_creditados>(SELECT COALESCE(SUM(c.minutos),0) FROM consumos c WHERE c.lancamento_id=l.id)
    """, (five_months_ago(), six_months_ago())).fetchone()[0]

    # Top 5 saldo
    top5 = db.execute("""
        SELECT s.matricula, s.nome, s.secretaria, s.setor,
            (SELECT COALESCE(SUM(minutos_creditados),0) FROM lancamentos WHERE matricula=s.matricula)
            -(SELECT COALESCE(SUM(c.minutos),0) FROM consumos c JOIN lancamentos l ON l.id=c.lancamento_id WHERE l.matricula=s.matricula)
            AS saldo
        FROM servidores s WHERE s.arquivado=0 ORDER BY saldo DESC LIMIT 5""").fetchall()

    # Top 5 departamentos por saldo agregado
    top5_deptos = db.execute("""
        SELECT COALESCE(NULLIF(s.setor,''),'Sem Departamento') AS setor,
               COALESCE(NULLIF(s.secretaria,''),'Sem Secretaria') AS secretaria,
               COUNT(*) AS qtd_servidores,
               SUM(
                   (SELECT COALESCE(SUM(minutos_creditados),0) FROM lancamentos WHERE matricula=s.matricula)
                   -(SELECT COALESCE(SUM(c.minutos),0) FROM consumos c JOIN lancamentos l ON l.id=c.lancamento_id WHERE l.matricula=s.matricula)
               ) AS saldo
        FROM servidores s
        WHERE s.arquivado=0
        GROUP BY COALESCE(NULLIF(s.setor,''),'Sem Departamento'),
                 COALESCE(NULLIF(s.secretaria,''),'Sem Secretaria')
        ORDER BY saldo DESC
        LIMIT 5
    """).fetchall()
    top5_deptos = [r for r in top5_deptos if minutos_num(r["saldo"]) > 0]

    return render_template("dashboard.html",
        meses_labels=json.dumps([m["label"] for m in meses6]),
        lanc_mes=json.dumps(lanc_mes),
        comp_mes=json.dumps(comp_mes),
        pag_mes=json.dumps(pag_mes),
        saldo_total=saldo_total,
        total_serv=total_serv,
        serv_fg=serv_fg,
        venc_count=venc_count,
        prox_venc=prox_venc,
        top5=top5,
        top5_deptos=top5_deptos,
        servidores_atalho=servidores_atalho,
        fmt=minutos_para_horas)

# â”€â”€â”€ Servidores â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@app.route("/servidores")
def servidores():
    db = get_db()
    busca = request.args.get("busca","").strip()
    sec   = request.args.get("secretaria","").strip()
    set_  = request.args.get("setor","").strip()
    apenas_com_saldo = request.args.get("saldo") == "com_saldo"
    f, p  = _filtro_servidores(busca, sec, set_, arquivado=0)
    saldo_expr = """
        (SELECT COALESCE(SUM(minutos_creditados),0) FROM lancamentos WHERE matricula=s.matricula)
        -(SELECT COALESCE(SUM(c.minutos),0) FROM consumos c JOIN lancamentos l ON l.id=c.lancamento_id WHERE l.matricula=s.matricula)
    """
    lista = db.execute(f"""
        SELECT s.*,
            {saldo_expr} AS saldo_minutos
        FROM servidores s {f} ORDER BY s.nome""", p).fetchall()
    if apenas_com_saldo:
        lista = [s for s in lista if minutos_num(s["saldo_minutos"]) > 0]
    secs, sets = _listas_filtro(db, 0)
    return render_template("servidores.html", servidores=lista, fmt=minutos_para_horas,
                            secretarias=secs, setores=sets,
                            busca=busca, secretaria_sel=sec, setor_sel=set_,
                            saldo_sel="com_saldo" if apenas_com_saldo else "")

@app.route("/api/historico/<matricula>")
def api_historico(matricula):
    db = get_db()
    if not usuario_pode_ver_matricula(db, matricula):
        return jsonify({"erro": "Acesso não autorizado para esta matrícula."}), 403

    lancs = db.execute("""
        SELECT l.data, l.horas_base, l.percentual, l.minutos_creditados, l.descricao,
               COALESCE((SELECT SUM(c.minutos) FROM consumos c WHERE c.lancamento_id=l.id),0) AS consumido
        FROM lancamentos l WHERE l.matricula=? ORDER BY l.data DESC LIMIT 30""", (matricula,)).fetchall()
    comps = db.execute("SELECT data,tipo,minutos_compensados,descricao FROM compensacoes WHERE matricula=? ORDER BY data DESC LIMIT 30", (matricula,)).fetchall()
    pags  = db.execute("""
        SELECT p.data_pagamento AS data, p.descricao,
               COALESCE(SUM(ROUND(c.minutos*l.minutos_base*1.0/l.minutos_creditados)),0) AS base_paga,
               COALESCE(SUM(c.minutos),0) AS minutos_pagos
        FROM pagamentos p JOIN consumos c ON c.referencia_id=p.id AND c.tipo='pagamento'
        JOIN lancamentos l ON l.id=c.lancamento_id WHERE p.matricula=?
        GROUP BY p.id,p.data_pagamento,p.descricao ORDER BY p.data_pagamento DESC LIMIT 20""", (matricula,)).fetchall()
    return jsonify({
        "lancamentos": [{**dict(r),"minutos_fmt":minutos_para_horas(r["minutos_creditados"]),"saldo_fmt":minutos_para_horas(r["minutos_creditados"]-r["consumido"])} for r in lancs],
        "compensacoes": [{**dict(r),"minutos_fmt":minutos_para_horas(r["minutos_compensados"])} for r in comps],
        "pagamentos":   [{**dict(r),"base_fmt":minutos_para_horas(int(r["base_paga"])),"banco_fmt":minutos_para_horas(r["minutos_pagos"])} for r in pags],
    })

@app.route("/servidores/novo", methods=["GET","POST"])
def novo_servidor():
    if request.method == "POST":
        mat = request.form["matricula"].strip()
        db  = get_db()
        if db.execute("SELECT 1 FROM servidores WHERE matricula=?", (mat,)).fetchone():
            flash("Matrícula já cadastrada.", "danger")
        else:
            fg = 1 if request.form.get("funcao_gratificada") else 0
            db.execute(
                "INSERT INTO servidores (matricula,nome,cpf,email,cargo,setor,secretaria,funcao_gratificada) VALUES (?,?,?,?,?,?,?,?)",
                (mat, request.form["nome"].strip(), request.form["cpf"].strip(),
                 request.form["email"].strip(), request.form["cargo"].strip(),
                 request.form["setor"].strip(), request.form["secretaria"].strip(), fg))
            db.commit()
            flash("Servidor cadastrado!", "success")
            return redirect(url_for("servidores"))
    return render_template("servidor_form.html", servidor=None)

@app.route("/servidores/<matricula>/editar", methods=["GET","POST"])
def editar_servidor(matricula):
    db  = get_db()
    srv = db.execute("SELECT * FROM servidores WHERE matricula=?", (matricula,)).fetchone()
    if not srv: flash("Não encontrado.", "danger"); return redirect(url_for("servidores"))
    if request.method == "POST":
        fg = 1 if request.form.get("funcao_gratificada") else 0
        db.execute("UPDATE servidores SET nome=?,cpf=?,email=?,cargo=?,setor=?,secretaria=?,funcao_gratificada=? WHERE matricula=?",
                   (request.form["nome"].strip(), request.form["cpf"].strip(), request.form["email"].strip(),
                    request.form["cargo"].strip(), request.form["setor"].strip(),
                    request.form["secretaria"].strip(), fg, matricula))
        db.commit()
        flash("Dados atualizados.", "success")
        return redirect(url_for("servidores"))
    return render_template("servidor_form.html", servidor=srv)

@app.route("/servidores/<matricula>/arquivar", methods=["POST"])
def arquivar_servidor(matricula):
    db = get_db()
    db.execute("UPDATE servidores SET arquivado=1 WHERE matricula=?", (matricula,))
    db.commit()
    flash("Servidor arquivado. Dados preservados para consulta.", "warning")
    return redirect(url_for("servidores"))

@app.route("/servidores/<matricula>/restaurar", methods=["POST"])
def restaurar_servidor(matricula):
    db = get_db()
    db.execute("UPDATE servidores SET arquivado=0 WHERE matricula=?", (matricula,))
    db.commit()
    flash("Servidor restaurado com sucesso.", "success")
    return redirect(url_for("arquivados"))

# â”€â”€â”€ Arquivados â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@app.route("/servidores/<matricula>/excluir", methods=["POST"])
@master_required
def excluir_servidor(matricula):
    db = get_db()
    srv = db.execute("SELECT * FROM servidores WHERE matricula=?", (matricula,)).fetchone()
    if not srv:
        flash("Servidor não encontrado.", "danger")
        return redirect(url_for("servidores"))
    registrar_auditoria(
        db, "Excluiu cadastro de servidor", "servidor", matricula, matricula, srv["nome"],
        f"Cadastro e movimentações removidos definitivamente; secretaria {srv['secretaria'] or '-'}; departamento {srv['setor'] or '-'}"
    )
    db.execute("DELETE FROM consumos WHERE lancamento_id IN (SELECT id FROM lancamentos WHERE matricula=?)", (matricula,))
    db.execute("DELETE FROM consumos WHERE tipo='compensacao' AND referencia_id IN (SELECT id FROM compensacoes WHERE matricula=?)", (matricula,))
    db.execute("DELETE FROM consumos WHERE tipo='pagamento' AND referencia_id IN (SELECT id FROM pagamentos WHERE matricula=?)", (matricula,))
    db.execute("DELETE FROM pagamentos WHERE matricula=?", (matricula,))
    db.execute("DELETE FROM compensacoes WHERE matricula=?", (matricula,))
    db.execute("DELETE FROM lancamentos WHERE matricula=?", (matricula,))
    db.execute("UPDATE usuarios SET ativo=0, matricula=NULL WHERE matricula=?", (matricula,))
    db.execute("DELETE FROM servidores WHERE matricula=?", (matricula,))
    db.commit()
    flash("Cadastro do servidor excluído definitivamente.", "warning")
    return redirect(url_for("servidores"))

@app.route("/arquivados")
def arquivados():
    db    = get_db()
    busca = request.args.get("busca","").strip()
    sec   = request.args.get("secretaria","").strip()
    set_  = request.args.get("setor","").strip()
    f, p  = _filtro_servidores(busca, sec, set_, arquivado=1)
    lista = db.execute(f"""
        SELECT s.*,
            (SELECT COALESCE(SUM(minutos_creditados),0) FROM lancamentos WHERE matricula=s.matricula)
            -(SELECT COALESCE(SUM(c.minutos),0) FROM consumos c JOIN lancamentos l ON l.id=c.lancamento_id WHERE l.matricula=s.matricula)
            AS saldo_minutos
        FROM servidores s {f} ORDER BY s.nome""", p).fetchall()
    secs, sets = _listas_filtro(db, 1)
    return render_template("arquivados.html", servidores=lista, fmt=minutos_para_horas,
                           secretarias=secs, setores=sets,
                           busca=busca, secretaria_sel=sec, setor_sel=set_)

# â”€â”€â”€ Lançamentos â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@app.route("/lancamentos/<matricula>", methods=["GET","POST"])
def lancamentos(matricula):
    db  = get_db()
    srv = db.execute("SELECT * FROM servidores WHERE matricula=?", (matricula,)).fetchone()
    if not srv: flash("Não encontrado.","danger"); return redirect(url_for("servidores"))
    if request.method == "POST":
        data = request.form["data"]; hrs = request.form["horas"].strip()
        pct  = int(request.form["percentual"]); desc = request.form["descricao"].strip()
        mb   = horas_para_minutos(hrs)
        if mb <= 0: flash("Formato HH:MM inválido.","danger")
        else:
            mc = mb + mb*pct//100
            lid = db.insert("INSERT INTO lancamentos (matricula,data,horas_base,minutos_base,percentual,minutos_creditados,descricao) VALUES (?,?,?,?,?,?,?)",
                            (matricula, data, hrs, mb, pct, mc, desc))
            registrar_auditoria(
                db, "Criou lançamento", "lancamento", lid, matricula, srv["nome"],
                f"Data {data}; horas base {hrs}; adicional {pct}%; crédito {minutos_para_horas(mc)}; descrição: {desc or '-'}"
            )
            db.commit()
            flash(f"Lançamento: {hrs} + {pct}% = {minutos_para_horas(mc)}","success")
            return redirect(url_for("lancamentos", matricula=matricula))
    hist = db.execute("""
        SELECT l.*, COALESCE((SELECT SUM(c.minutos) FROM consumos c WHERE c.lancamento_id=l.id),0) AS consumido
        FROM lancamentos l WHERE l.matricula=? ORDER BY l.data DESC""", (matricula,)).fetchall()
    return render_template("lancamentos.html", servidor=srv, historico=hist,
                           saldo=calcular_saldo(db, matricula), fmt=minutos_para_horas, fg=_fg(srv))

@app.route("/lancamentos/<int:id>/excluir", methods=["POST"])
def excluir_lancamento(id):
    db = get_db()
    r  = db.execute("""
        SELECT l.*, s.nome AS servidor_nome FROM lancamentos l
        LEFT JOIN servidores s ON s.matricula=l.matricula WHERE l.id=?
    """, (id,)).fetchone()
    if r:
        registrar_auditoria(
            db, "Excluiu lançamento", "lancamento", id, r["matricula"], r["servidor_nome"],
            f"Data {r['data']}; horas base {r['horas_base']}; adicional {r['percentual']}%; crédito {minutos_para_horas(r['minutos_creditados'])}; descrição: {r['descricao'] or '-'}"
        )
        db.execute("DELETE FROM consumos WHERE lancamento_id=?", (id,))
        db.execute("DELETE FROM lancamentos WHERE id=?", (id,))
        db.commit(); flash("Lançamento excluído.","warning")
        return redirect(url_for("lancamentos", matricula=r["matricula"]))
    return redirect(url_for("servidores"))

# â”€â”€â”€ Compensações â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@app.route("/compensacoes/<matricula>", methods=["GET","POST"])
def compensacoes(matricula):
    db  = get_db()
    srv = db.execute("SELECT * FROM servidores WHERE matricula=?", (matricula,)).fetchone()
    if not srv: flash("Não encontrado.","danger"); return redirect(url_for("servidores"))
    saldo = calcular_saldo(db, matricula)
    if request.method == "POST":
        data = request.form["data"]; tipo = request.form["tipo"]; desc = request.form["descricao"].strip()
        mc   = 8*60 if tipo=="dia_inteiro" else horas_para_minutos(request.form.get("horas","").strip())
        if mc <= 0: flash("Valor inválido.","danger")
        else:
            cid = db.insert("INSERT INTO compensacoes (matricula,data,tipo,minutos_compensados,descricao) VALUES (?,?,?,?,?)",
                            (matricula, data, tipo, mc, desc))
            _consumir_fifo_raw(db, matricula, mc, "compensacao", cid)
            registrar_auditoria(
                db, "Criou compensação", "compensacao", cid, matricula, srv["nome"],
                f"Data {data}; tipo {tipo}; compensado {minutos_para_horas(mc)}; saldo anterior {minutos_para_horas(saldo)}; descrição: {desc or '-'}"
            )
            db.commit()
            novo_saldo = saldo - mc
            if novo_saldo < 0:
                flash(f"Compensação registrada. Atenção: o saldo ficou negativo em {minutos_para_horas(novo_saldo)}.", "warning")
            else:
                flash(f"Compensação de {minutos_para_horas(mc)} registrada (FIFO).", "success")
            return redirect(url_for("compensacoes", matricula=matricula))
    hist = db.execute("SELECT * FROM compensacoes WHERE matricula=? ORDER BY data DESC", (matricula,)).fetchall()
    return render_template("compensacoes.html", servidor=srv, historico=hist,
                           saldo=saldo, fmt=minutos_para_horas, fg=_fg(srv))

@app.route("/compensacoes/<int:id>/excluir", methods=["POST"])
def excluir_compensacao(id):
    db = get_db()
    r  = db.execute("""
        SELECT c.*, s.nome AS servidor_nome FROM compensacoes c
        LEFT JOIN servidores s ON s.matricula=c.matricula WHERE c.id=?
    """, (id,)).fetchone()
    if r:
        registrar_auditoria(
            db, "Excluiu compensação", "compensacao", id, r["matricula"], r["servidor_nome"],
            f"Data {r['data']}; tipo {r['tipo']}; compensado {minutos_para_horas(r['minutos_compensados'])}; descrição: {r['descricao'] or '-'}"
        )
        db.execute("DELETE FROM consumos WHERE tipo='compensacao' AND referencia_id=?", (id,))
        db.execute("DELETE FROM compensacoes WHERE id=?", (id,))
        db.commit(); flash("Compensação excluída.","warning")
        return redirect(url_for("compensacoes", matricula=r["matricula"]))
    return redirect(url_for("servidores"))

# â”€â”€â”€ Pagamentos â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@app.route("/pagamentos")
def pagamentos_index():
    db   = get_db()
    srvs = db.execute("SELECT * FROM servidores WHERE arquivado=0 ORDER BY nome").fetchall()
    pend = []
    for s in srvs:
        itens_v = lancamentos_com_saldo(db, s["matricula"], apenas_vencidos=True)
        itens_t = lancamentos_com_saldo(db, s["matricula"], apenas_vencidos=False)
        if not itens_t: continue
        tb_v = sum(i["saldo_base_minutos"] for i in itens_v)
        tb_t = sum(i["saldo_base_minutos"] for i in itens_t)
        pend.append({"matricula":s["matricula"],"nome":s["nome"],"cargo":s["cargo"],
                     "setor":s["setor"],"secretaria":s["secretaria"],
                     "funcao_gratificada":bool(s["funcao_gratificada"]),
                     "total_base_vencidas":tb_v,"total_base_todos":tb_t,
                     "qtd_vencidas":len(itens_v),"qtd_total":len(itens_t),
                     "acima_limite":tb_t>LIMITE_PAGAMENTO_MINUTOS})
    return render_template("pagamentos_index.html", pendentes=pend,
                           fmt=minutos_para_horas, limite_fmt=minutos_para_horas(LIMITE_PAGAMENTO_MINUTOS))

@app.route("/pagamentos/<matricula>")
def pagamentos_servidor(matricula):
    db  = get_db()
    srv = db.execute("SELECT * FROM servidores WHERE matricula=?", (matricula,)).fetchone()
    if not srv: flash("Não encontrado.","danger"); return redirect(url_for("pagamentos_index"))
    itens = lancamentos_com_saldo(db, matricula, apenas_vencidos=False)
    hist  = db.execute("SELECT * FROM pagamentos WHERE matricula=? ORDER BY data_pagamento DESC", (matricula,)).fetchall()
    return render_template("pagamentos_servidor.html", servidor=srv, itens=itens, historico=hist,
                           fmt=minutos_para_horas, limite=LIMITE_PAGAMENTO_MINUTOS,
                           today=date.today().isoformat(), fg=_fg(srv))

@app.route("/pagamentos/<matricula>/registrar", methods=["POST"])
def registrar_pagamento(matricula):
    db = get_db()
    srv = db.execute("SELECT nome FROM servidores WHERE matricula=?", (matricula,)).fetchone()
    data_pag = request.form["data_pagamento"]
    descricao = request.form.get("descricao","").strip()
    just      = request.form.get("justificativa","").strip()
    itens     = lancamentos_com_saldo(db, matricula, apenas_vencidos=False)
    if not itens: flash("Sem horas com saldo.","warning"); return redirect(url_for("pagamentos_servidor", matricula=matricula))

    pag_itens=[]; total_base=0; tem_nao_venc=False
    for item in itens:
        v = request.form.get(f"horas_{item['id']}","").strip()
        if not v: continue
        mb_pagar = horas_para_minutos(v)
        if mb_pagar <= 0: continue
        if not item["vencido"]: tem_nao_venc = True
        mc = round(mb_pagar * item["minutos_creditados"] / item["minutos_base"]) if item["minutos_base"]>0 else mb_pagar
        mc = min(mc, item["saldo_minutos"])
        if mc <= 0: continue
        br = round(mc * item["minutos_base"] / item["minutos_creditados"]) if item["minutos_creditados"]>0 else 0
        total_base += br; pag_itens.append((item["id"], mc))

    if (tem_nao_venc or total_base>LIMITE_PAGAMENTO_MINUTOS) and not just:
        flash("Justificativa obrigatória para horas não vencidas ou acima de 45h.","danger")
        return redirect(url_for("pagamentos_servidor", matricula=matricula))
    if not pag_itens: flash("Nenhuma hora informada.","warning"); return redirect(url_for("pagamentos_servidor", matricula=matricula))

    desc_final = descricao + (f" | Justificativa: {just}" if just else "")
    pid = db.insert("INSERT INTO pagamentos (matricula,data_pagamento,descricao) VALUES (?,?,?)", (matricula,data_pag,desc_final))
    for lid, mins in pag_itens:
        db.execute("INSERT INTO consumos (lancamento_id,tipo,referencia_id,minutos) VALUES (?,?,?,?)", (lid,"pagamento",pid,mins))
    registrar_auditoria(
        db, "Criou pagamento", "pagamento", pid, matricula, srv["nome"] if srv else "",
        f"Data {data_pag}; horas base para folha {minutos_para_horas(total_base)}; itens pagos {len(pag_itens)}; descrição: {desc_final or '-'}"
    )
    db.commit()
    aviso = f" ⚠️ Total {minutos_para_horas(total_base)} ultrapassa 45h." if total_base>LIMITE_PAGAMENTO_MINUTOS else ""
    flash(f"Pagamento registrado! Horas base: {minutos_para_horas(total_base)}.{aviso}","success")
    return redirect(url_for("pagamentos_servidor", matricula=matricula))

@app.route("/pagamentos/<int:id>/estornar", methods=["POST"])
def estornar_pagamento(id):
    db = get_db()
    r  = db.execute("""
        SELECT p.*, s.nome AS servidor_nome,
               COALESCE(SUM(ROUND(c.minutos*l.minutos_base*1.0/l.minutos_creditados)),0) AS base_paga
        FROM pagamentos p
        LEFT JOIN servidores s ON s.matricula=p.matricula
        LEFT JOIN consumos c ON c.referencia_id=p.id AND c.tipo='pagamento'
        LEFT JOIN lancamentos l ON l.id=c.lancamento_id
        WHERE p.id=?
        GROUP BY p.id,p.matricula,p.data_pagamento,p.descricao,p.criado_em,s.nome
    """, (id,)).fetchone()
    if r:
        registrar_auditoria(
            db, "Estornou pagamento", "pagamento", id, r["matricula"], r["servidor_nome"],
            f"Data {r['data_pagamento']}; horas base {minutos_para_horas(r['base_paga'])}; descrição: {r['descricao'] or '-'}"
        )
        db.execute("DELETE FROM consumos WHERE tipo='pagamento' AND referencia_id=?", (id,))
        db.execute("DELETE FROM pagamentos WHERE id=?", (id,))
        db.commit(); flash("Pagamento estornado.","warning")
        return redirect(url_for("pagamentos_servidor", matricula=r["matricula"]))
    return redirect(url_for("pagamentos_index"))

@app.route("/admin/auditoria")
@master_required
def admin_auditoria():
    db = get_db()
    desde = (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%d %H:%M:%S")
    eventos = db.execute("""
        SELECT *
        FROM auditoria
        WHERE criado_em >= ?
        ORDER BY criado_em ASC, id ASC
    """, (desde,)).fetchall()
    return render_template("admin/auditoria.html", eventos=eventos, desde=desde)

# â”€â”€â”€ Relatórios â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@app.route("/relatorios")
def relatorios():
    db  = get_db()
    aba = request.args.get("aba","saldos")
    fmt_out = request.args.get("fmt","html")
    mat = request.args.get("matricula","").strip()
    sec = request.args.get("secretaria","").strip()
    set_= request.args.get("setor","").strip()
    di  = request.args.get("data_ini","")
    df  = request.args.get("data_fim","")
    mes = request.args.get("mes","")
    ano = request.args.get("ano",str(date.today().year))
    agr = request.args.get("agrupar","servidor")

    filt_srv, params_srv = _filtro_servidores("", sec, set_, arquivado=0)
    if mat: filt_srv += " AND s.matricula=?"; params_srv.append(mat)

    secs, sets = _listas_filtro(db, 0)
    srvs_lista = db.execute("SELECT * FROM servidores WHERE arquivado=0 ORDER BY nome").fetchall()
    filtros = {"matricula":mat,"secretaria":sec,"setor":set_,"data_ini":di,"data_fim":df,"mes":mes,"ano":ano,"agrupar":agr}
    filtros_qs = urlencode({k:v for k,v in filtros.items() if v})
    data = {}

    if aba == "saldos":
        data["servidores"] = db.execute(f"""
            SELECT s.*,
                (SELECT COALESCE(SUM(minutos_creditados),0) FROM lancamentos WHERE matricula=s.matricula) AS total_credito,
                (SELECT COALESCE(SUM(c.minutos),0) FROM consumos c JOIN lancamentos l ON l.id=c.lancamento_id WHERE l.matricula=s.matricula AND c.tipo='compensacao') AS total_compensado,
                (SELECT COALESCE(SUM(c.minutos),0) FROM consumos c JOIN lancamentos l ON l.id=c.lancamento_id WHERE l.matricula=s.matricula AND c.tipo='pagamento') AS total_pago,
                (SELECT COALESCE(SUM(minutos_creditados),0) FROM lancamentos WHERE matricula=s.matricula)
                -(SELECT COALESCE(SUM(c.minutos),0) FROM consumos c JOIN lancamentos l ON l.id=c.lancamento_id WHERE l.matricula=s.matricula) AS saldo
            FROM servidores s {filt_srv} ORDER BY s.nome""", params_srv).fetchall()
        if fmt_out in ("csv", "xlsx", "pdf"):
            headers = ["Matrícula","Nome","CPF","Email","Secretaria","Departamento","Cargo","Total Creditado","Total Compensado","Total Pago","Saldo","FG"]
            rows = [[s["matricula"],s["nome"],s["cpf"] or "",s["email"] or "",s["secretaria"] or "",s["setor"] or "",s["cargo"] or "",
                     minutos_para_horas(s["total_credito"]),minutos_para_horas(s["total_compensado"]),
                     minutos_para_horas(s["total_pago"]),minutos_para_horas(s["saldo"]),"Sim" if s["funcao_gratificada"] else "Não"]
                    for s in data["servidores"]]
            return _export_response(fmt_out, "saldos", "Relatório de Saldos em Banco de Horas", headers, rows)

    elif aba == "historico":
        mats=[r["matricula"] for r in db.execute(f"SELECT s.matricula FROM servidores s {filt_srv}",params_srv).fetchall()]
        if not mats: data["eventos"]=[]
        else:
            ph=",".join("?"*len(mats)); ev=[]
            def apd(f,p,c):
                if di: f+=f" AND {c}>=?"; p.append(di)
                if df: f+=f" AND {c}<=?"; p.append(df)
                return f,p
            fl,pl=apd(f"WHERE l.matricula IN ({ph})",list(mats),"l.data")
            for r in db.execute(f"SELECT l.*,s.nome,s.secretaria,s.funcao_gratificada FROM lancamentos l JOIN servidores s ON s.matricula=l.matricula {fl} ORDER BY l.data DESC",pl).fetchall():
                ev.append({**dict(r),"tipo_evento":"lancamento","data_ord":r["data"]})
            fc,pc=apd(f"WHERE c.matricula IN ({ph})",list(mats),"c.data")
            for r in db.execute(f"SELECT c.*,s.nome,s.secretaria,s.funcao_gratificada FROM compensacoes c JOIN servidores s ON s.matricula=c.matricula {fc} ORDER BY c.data DESC",pc).fetchall():
                ev.append({**dict(r),"tipo_evento":"compensacao","data_ord":r["data"]})
            fp,pp=apd(f"WHERE p.matricula IN ({ph})",list(mats),"p.data_pagamento")
            for r in db.execute(f"""SELECT p.*,s.nome,s.secretaria,s.funcao_gratificada,
                COALESCE(SUM(ROUND(c.minutos*l.minutos_base*1.0/l.minutos_creditados)),0) AS base_paga,
                COALESCE(SUM(c.minutos),0) AS minutos_pagos
                FROM pagamentos p JOIN servidores s ON s.matricula=p.matricula
                JOIN consumos c ON c.referencia_id=p.id AND c.tipo='pagamento'
                JOIN lancamentos l ON l.id=c.lancamento_id {fp}
                GROUP BY p.id,p.matricula,p.data_pagamento,p.descricao,p.criado_em,
                         s.nome,s.secretaria,s.funcao_gratificada
                ORDER BY p.data_pagamento DESC""",pp).fetchall():
                ev.append({**dict(r),"tipo_evento":"pagamento","data_ord":r["data_pagamento"]})
            ev.sort(key=lambda x:x["data_ord"],reverse=True); data["eventos"]=ev
        if fmt_out in ("csv", "xlsx", "pdf"):
            headers = ["Data","Matrícula","Servidor","Secretaria","FG","Tipo","Detalhes","Horas"]
            rows = []
            for e in data["eventos"]:
                fg_s="Sim" if e.get("funcao_gratificada") else "Não"
                if e["tipo_evento"]=="lancamento":
                    rows.append([e["data"],e["matricula"],e["nome"],e.get("secretaria",""),fg_s,"Lançamento",f"{e['horas_base']} + {e['percentual']}%",minutos_para_horas(e["minutos_creditados"])])
                elif e["tipo_evento"]=="compensacao":
                    rows.append([e["data"],e["matricula"],e["nome"],e.get("secretaria",""),fg_s,"Compensação","Dia inteiro" if e["tipo"]=="dia_inteiro" else "Parcial",minutos_para_horas(e["minutos_compensados"])])
                else:
                    rows.append([e["data_pagamento"],e["matricula"],e["nome"],e.get("secretaria",""),fg_s,"Pagamento Folha",e.get("descricao",""),minutos_para_horas(int(e["base_paga"]))])
            return _export_response(fmt_out, "historico", "Relatório de Histórico Completo", headers, rows)

    elif aba == "pagamentos":
        fp=f"WHERE p.matricula IN (SELECT matricula FROM servidores s {filt_srv})"; pp=list(params_srv)
        if di: fp+=" AND p.data_pagamento>=?"; pp.append(di)
        if df: fp+=" AND p.data_pagamento<=?"; pp.append(df)
        pags=db.execute(f"""SELECT p.*,s.nome,s.secretaria,s.setor,s.funcao_gratificada,
            COALESCE(SUM(ROUND(c.minutos*l.minutos_base*1.0/l.minutos_creditados)),0) AS base_paga,
            COALESCE(SUM(c.minutos),0) AS minutos_pagos
            FROM pagamentos p JOIN servidores s ON s.matricula=p.matricula
            LEFT JOIN consumos c ON c.referencia_id=p.id AND c.tipo='pagamento'
            LEFT JOIN lancamentos l ON l.id=c.lancamento_id {fp}
            GROUP BY p.id,p.matricula,p.data_pagamento,p.descricao,p.criado_em,
                     s.nome,s.secretaria,s.setor,s.funcao_gratificada
            ORDER BY p.data_pagamento DESC""",pp).fetchall()
        dets={p["id"]:db.execute("""SELECT l.data AS data_hora,l.horas_base,l.minutos_base,l.percentual,
            l.minutos_creditados,c.minutos AS minutos_consumidos,
            ROUND(c.minutos*l.minutos_base*1.0/l.minutos_creditados) AS base_paga
            FROM consumos c JOIN lancamentos l ON l.id=c.lancamento_id
            WHERE c.tipo='pagamento' AND c.referencia_id=? ORDER BY l.data ASC""",(p["id"],)).fetchall() for p in pags}
        data["pagamentos"]=pags; data["detalhes"]=dets
        if fmt_out in ("csv", "xlsx", "pdf"):
            headers = ["Pag.ID","Matrícula","Servidor","Secretaria","Departamento","FG","Data Pagamento","Referência","Data Realização","H.Base Realizadas","%","H.Base Pagas"]
            rows = []
            for p in pags:
                fg_s="Sim" if p.get("funcao_gratificada") else "Não"
                for d in dets[p["id"]]:
                    rows.append([p["id"],p["matricula"],p["nome"],p.get("secretaria",""),p.get("setor",""),fg_s,p["data_pagamento"],p.get("descricao",""),d["data_hora"],d["horas_base"],f"{d['percentual']}%",minutos_para_horas(int(d["base_paga"] or 0))])
            return _export_response(fmt_out, "pagamentos", "Relatório de Pagamentos Realizados", headers, rows)

    elif aba == "competencia":
        data.update({"grupos":{},"mes":mes,"ano":ano,"agrupar":agr,"meses":MESES_FULL})
        if mes and ano:
            mats=[r["matricula"] for r in db.execute(f"SELECT s.matricula FROM servidores s {filt_srv}",params_srv).fetchall()]
            if mats:
                ph=",".join("?"*len(mats))
                rows=db.execute(f"""SELECT l.*,s.nome,s.secretaria,s.setor,s.matricula AS mat,s.funcao_gratificada
                    FROM lancamentos l JOIN servidores s ON s.matricula=l.matricula
                    WHERE substr(l.data,6,2)=? AND substr(l.data,1,4)=? AND l.matricula IN ({ph})
                    ORDER BY s.secretaria,s.setor,s.nome,l.data""",[mes.zfill(2),ano]+mats).fetchall()
                grps={}
                for r in rows:
                    chave=(r["secretaria"] or "Sem Secretaria") if agr=="secretaria" else (r["setor"] or "Sem Departamento") if agr=="departamento" else f"{r['nome']} ({r['mat']})"
                    grps.setdefault(chave,[]).append(dict(r))
                data["grupos"]=grps
        if fmt_out in ("csv", "xlsx", "pdf") and data["grupos"]:
            headers = ["Grupo","Matrícula","Servidor","Data","H.Base","%","H.Creditadas","Descrição"]
            rows = []
            for g,its in data["grupos"].items():
                for r in its:
                    rows.append([g,r["matricula"],r["nome"],r["data"],r["horas_base"],f"{r['percentual']}%",minutos_para_horas(r["minutos_creditados"]),r["descricao"] or ""])
            return _export_response(fmt_out, f"competencia_{mes}_{ano}", f"Relatório de Horas por Competência {mes}/{ano}", headers, rows)

    return render_template("relatorios.html", aba=aba, data=data, fmt=minutos_para_horas,
                           secretarias=secs, setores=sets, servidores_lista=srvs_lista,
                           meses=MESES_FULL, filtros=filtros, filtros_qs=filtros_qs)

# â”€â”€â”€ Auth: Setup / Login / Logout â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@app.route('/setup', methods=['GET','POST'])
def setup():
    db = get_db()
    if db.execute("SELECT COUNT(*) FROM usuarios").fetchone()[0] > 0:
        return redirect(url_for('login'))
    if request.method == 'POST':
        cpf   = request.form['cpf'].strip()
        nome  = request.form['nome'].strip()
        email = request.form['email'].strip()
        senha = request.form['senha']
        conf  = request.form['confirmar']
        if senha != conf:
            flash("As senhas não coincidem.", "danger")
        elif len(senha) < 8:
            flash("A senha deve ter pelo menos 8 caracteres.", "danger")
        else:
            db.execute("""INSERT INTO usuarios (cpf,nome,email,senha_hash,nivel,ativo,senha_temporaria)
                          VALUES (?,?,?,?,'master',1,0)""",
                       (cpf, nome, email, generate_password_hash(senha)))
            db.commit()
            flash("Usuário master criado com sucesso! Faça login.", "success")
            return redirect(url_for('login'))
    return render_template('setup.html')


@app.route('/login', methods=['GET','POST'])
def login():
    db = get_db()
    # Sem usuários → setup
    if db.execute("SELECT COUNT(*) FROM usuarios").fetchone()[0] == 0:
        return redirect(url_for('setup'))

    if request.method == 'POST':
        cpf   = request.form['cpf'].strip()
        senha = request.form['senha']
        u = db.execute("SELECT * FROM usuarios WHERE cpf=? AND ativo=1", (cpf,)).fetchone()
        if not u or not check_password_hash(u['senha_hash'], senha):
            flash("CPF ou senha inválidos.", "danger")
            return render_template('login.html')

        # Registra último acesso
        db.execute("UPDATE usuarios SET ultimo_acesso=? WHERE id=?",
                   (datetime.now().strftime('%Y-%m-%d %H:%M'), u['id']))
        db.commit()

        session.clear()
        session['uid']   = u['id']
        session['nivel'] = u['nivel']
        session['nome']  = u['nome']
        session['cpf']   = u['cpf']
        session['temp']  = bool(u['senha_temporaria'])
        session['vinculos'] = get_vinculos(u)
        if u['nivel'] == 'servidor': session['matricula'] = u['matricula']


        if u['senha_temporaria']:
            flash("Sua senha é temporária. Defina uma nova senha.", "warning")
            return redirect(url_for('trocar_senha'))

        return redirect(url_for('portal'))

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash("Sessão encerrada.", "info")
    return redirect(url_for('login'))


@app.route('/trocar-senha', methods=['GET','POST'])
def trocar_senha():
    if 'uid' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        atual = request.form['senha_atual']
        nova  = request.form['senha_nova']
        conf  = request.form['confirmar']
        db = get_db()
        u  = db.execute("SELECT * FROM usuarios WHERE id=?", (session['uid'],)).fetchone()
        if not check_password_hash(u['senha_hash'], atual):
            flash("Senha atual incorreta.", "danger")
        elif nova != conf:
            flash("As novas senhas não coincidem.", "danger")
        elif len(nova) < 8:
            flash("A senha deve ter pelo menos 8 caracteres.", "danger")
        else:
            db.execute("UPDATE usuarios SET senha_hash=?, senha_temporaria=0 WHERE id=?",
                       (generate_password_hash(nova), session['uid']))
            db.commit()
            session['temp'] = False
            flash("Senha alterada com sucesso!", "success")
            return redirect(url_for('portal'))
    return render_template('trocar_senha.html')


@app.route('/meu-cadastro', methods=['GET','POST'])
def meu_cadastro():
    if 'uid' not in session:
        return redirect(url_for('login'))

    db = get_db()
    u = db.execute("SELECT * FROM usuarios WHERE id=?", (session['uid'],)).fetchone()
    if not u:
        session.clear()
        flash("Usuário não encontrado. Faça login novamente.", "warning")
        return redirect(url_for('login'))

    if request.method == 'POST':
        email = request.form.get('email','').strip()
        senha_atual = request.form.get('senha_atual','')
        senha_nova = request.form.get('senha_nova','')
        confirmar = request.form.get('confirmar','')

        alterar_senha = bool(senha_atual or senha_nova or confirmar)
        if alterar_senha:
            if not check_password_hash(u['senha_hash'], senha_atual):
                flash("Senha atual incorreta.", "danger")
                return render_template('meu_cadastro.html', usuario=u)
            if senha_nova != confirmar:
                flash("A nova senha e a confirmação não coincidem.", "danger")
                return render_template('meu_cadastro.html', usuario=u)
            if len(senha_nova) < 8:
                flash("A nova senha deve ter pelo menos 8 caracteres.", "danger")
                return render_template('meu_cadastro.html', usuario=u)
            db.execute(
                "UPDATE usuarios SET email=?, senha_hash=?, senha_temporaria=0 WHERE id=?",
                (email, generate_password_hash(senha_nova), session['uid'])
            )
            session['temp'] = False
            flash("Cadastro e senha atualizados com sucesso.", "success")
        else:
            db.execute("UPDATE usuarios SET email=? WHERE id=?", (email, session['uid']))
            flash("E-mail atualizado com sucesso.", "success")

        db.commit()
        return redirect(url_for('meu_cadastro'))

    return render_template('meu_cadastro.html', usuario=u)


@app.route('/recuperar-senha', methods=['GET','POST'])
def recuperar_senha():
    if request.method == 'POST':
        cpf = request.form['cpf'].strip()
        db  = get_db()
        u   = db.execute("SELECT * FROM usuarios WHERE cpf=? AND ativo=1", (cpf,)).fetchone()
        if u and u['email']:
            token  = secrets.token_urlsafe(32)
            expiry = (datetime.now() + timedelta(hours=1)).isoformat()
            db.execute("UPDATE usuarios SET reset_token=?, reset_expiry=? WHERE id=?",
                       (token, expiry, u['id']))
            db.commit()
            link = url_for('recuperar_senha_token', token=token, _external=True)
            html = f"""<p>Olá, <b>{u['nome']}</b>.</p>
            <p>Clique no link abaixo para redefinir sua senha (válido por 1 hora):</p>
            <p><a href="{link}">{link}</a></p>"""
            ok, err = enviar_email_smtp(u['email'], "Redefinição de senha — Banco de Horas Ibiporã", html)
            if ok:
                flash("E-mail de recuperação enviado! Verifique sua caixa de entrada.", "success")
            else:
                if err == "SMTP_NAO_CONFIGURADO":
                    flash(
                        "O envio de e-mail ainda não foi configurado. Solicite ao RH a redefinição de senha pelo painel "
                        "Admin > Usuários, ou configure o SMTP em Admin > E-mail.",
                        "warning"
                    )
                else:
                    flash(f"Não foi possível enviar o e-mail ({err}). Solicite ao administrador.", "warning")
        else:
            # CPF não encontrado ou sem e-mail — não revelar
            flash("Se o CPF estiver cadastrado com e-mail, você receberá as instruções.", "info")
        return redirect(url_for('login'))
    return render_template('recuperar_senha.html')


@app.route('/recuperar-senha/<token>', methods=['GET','POST'])
def recuperar_senha_token(token):
    db = get_db()
    u  = db.execute("SELECT * FROM usuarios WHERE reset_token=? AND ativo=1", (token,)).fetchone()
    if not u:
        flash("Link inválido ou já utilizado.", "danger")
        return redirect(url_for('login'))
    if datetime.now() > datetime.fromisoformat(u['reset_expiry']):
        flash("Link expirado. Solicite um novo.", "danger")
        return redirect(url_for('recuperar_senha'))
    if request.method == 'POST':
        nova = request.form['senha_nova']
        conf = request.form['confirmar']
        if nova != conf:
            flash("As senhas não coincidem.", "danger")
        elif len(nova) < 8:
            flash("Mínimo de 8 caracteres.", "danger")
        else:
            db.execute("UPDATE usuarios SET senha_hash=?, senha_temporaria=0, reset_token=NULL, reset_expiry=NULL WHERE id=?",
                       (generate_password_hash(nova), u['id']))
            db.commit()
            flash("Senha redefinida! Faça login.", "success")
            return redirect(url_for('login'))
    return render_template('recuperar_senha_token.html', token=token)


# â”€â”€â”€ Portal (redireciona por nível) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@app.route('/portal')
def portal():
    nivel = session.get('nivel')
    if nivel == 'master':    return redirect(url_for('dashboard'))
    if nivel == 'servidor':  return redirect(url_for('meu_banco'))
    return redirect(url_for('consulta'))


# â”€â”€â”€ Meu Banco (Servidor) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@app.route('/meu-banco')
def meu_banco():
    if 'uid' not in session or session.get('nivel') != 'servidor':
        return redirect(url_for('login'))
    mat = session.get('matricula')
    if not mat:
        flash("Matrícula não vinculada ao seu usuário. Contate o RH.", "danger")
        return redirect(url_for('login'))
    db  = get_db()
    srv = db.execute("SELECT * FROM servidores WHERE matricula=?", (mat,)).fetchone()
    if not srv:
        flash("Servidor não encontrado.", "danger")
        return redirect(url_for('login'))
    saldo = calcular_saldo(db, mat)
    lancs = db.execute("""
        SELECT l.*, COALESCE((SELECT SUM(c.minutos) FROM consumos c WHERE c.lancamento_id=l.id),0) AS consumido
        FROM lancamentos l WHERE l.matricula=? ORDER BY l.data DESC""", (mat,)).fetchall()
    comps = db.execute("SELECT * FROM compensacoes WHERE matricula=? ORDER BY data DESC", (mat,)).fetchall()
    pags  = db.execute("""
        SELECT p.*, COALESCE(SUM(ROUND(c.minutos*l.minutos_base*1.0/l.minutos_creditados)),0) AS base_paga
        FROM pagamentos p
        LEFT JOIN consumos c ON c.referencia_id=p.id AND c.tipo='pagamento'
        LEFT JOIN lancamentos l ON l.id=c.lancamento_id
        WHERE p.matricula=?
        GROUP BY p.id,p.matricula,p.data_pagamento,p.descricao,p.criado_em
        ORDER BY p.data_pagamento DESC""", (mat,)).fetchall()
    return render_template('meu_banco.html', servidor=srv, saldo=saldo,
                           lancamentos=lancs, compensacoes=comps, pagamentos=pags,
                           fmt=minutos_para_horas)


# â”€â”€â”€ Consulta (Secretário / Chefia) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@app.route('/consulta')
def consulta():
    if 'uid' not in session or session.get('nivel') not in ('secretario','chefia'):
        return redirect(url_for('login'))
    db    = get_db()
    nivel = session.get('nivel')
    busca = request.args.get('busca','').strip()

    vinculos = session.get('vinculos', [])
    filtro = "WHERE s.arquivado=0"
    params = []

    if vinculos:
        ph = ','.join('?' * len(vinculos))
        if nivel == 'secretario':
            filtro += f" AND s.secretaria IN ({ph})"; params.extend(vinculos)
        elif nivel == 'chefia':
            filtro += f" AND s.setor IN ({ph})";      params.extend(vinculos)
    else:
        # Sem vínculo configurado → nenhum servidor visível
        filtro += " AND 1=0"

    if busca:
        filtro += " AND (s.matricula LIKE ? OR s.nome LIKE ?)"; params += [f"%{busca}%",f"%{busca}%"]

    lista = db.execute(f"""
        SELECT s.*,
            (SELECT COALESCE(SUM(minutos_creditados),0) FROM lancamentos WHERE matricula=s.matricula)
            -(SELECT COALESCE(SUM(c.minutos),0) FROM consumos c JOIN lancamentos l ON l.id=c.lancamento_id WHERE l.matricula=s.matricula)
            AS saldo_minutos
        FROM servidores s {filtro} ORDER BY s.nome""", params).fetchall()

    titulo_vinculos = ' | '.join(vinculos) if vinculos else '(sem vínculo)'
    return render_template('consulta.html', servidores=lista, fmt=minutos_para_horas,
                           busca=busca, nivel=nivel,
                           titulo=f"Secretaria(s): {titulo_vinculos}" if nivel=='secretario'
                                  else f"Departamento(s): {titulo_vinculos}")


# â”€â”€â”€ Admin: Usuários â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@app.route('/admin/usuarios')
@master_required
def admin_usuarios():
    db   = get_db()
    page = request.args.get('nivel','')
    busca = request.args.get('busca','').strip()
    q    = f"WHERE 1=1{' AND u.nivel=?' if page else ''}"
    p    = [page] if page else []
    if busca:
        q += " AND (u.nome LIKE ? OR u.cpf LIKE ? OR u.matricula LIKE ? OR s.nome LIKE ?)"
        like = f"%{busca}%"
        p.extend([like, like, like, like])
    rows = db.execute(f"""
        SELECT u.*, s.nome AS servidor_nome
        FROM usuarios u
        LEFT JOIN servidores s ON s.matricula=u.matricula
        {q}
        ORDER BY u.nivel,u.nome
    """, p).fetchall()
    usrs = []
    for u in rows:
        d = dict(u)
        d["vinculos_lista"] = get_vinculos(u)
        d["ultimas_visualizacoes"] = db.execute("""
            SELECT titulo,caminho,criado_em FROM visualizacoes
            WHERE usuario_id=?
            ORDER BY criado_em DESC, id DESC
            LIMIT 3
        """, (u["id"],)).fetchall()
        usrs.append(d)
    return render_template('admin/usuarios.html', usuarios=usrs, filtro_nivel=page, busca=busca)


@app.route('/admin/usuarios/novo', methods=['GET','POST'])
@master_required
def admin_novo_usuario():
    db = get_db()
    if request.method == 'POST':
        cpf   = request.form['cpf'].strip()
        nome  = request.form['nome'].strip()
        email = request.form['email'].strip()
        nivel = request.form['nivel']
        vinculos = request.form.getlist('vinculos')
        sec   = vinculos[0] if nivel == 'secretario' and vinculos else request.form.get('secretaria','').strip()
        set_  = vinculos[0] if nivel == 'chefia' and vinculos else request.form.get('setor','').strip()
        mat   = request.form.get('matricula','').strip()

        if db.execute("SELECT 1 FROM usuarios WHERE cpf=?", (cpf,)).fetchone():
            flash("CPF já cadastrado.", "danger")
        else:
            senha_temp = gerar_senha_temp()
            db.execute("""INSERT INTO usuarios (cpf,nome,email,senha_hash,nivel,secretaria,setor,matricula,vinculos,ativo,senha_temporaria)
                          VALUES (?,?,?,?,?,?,?,?,?,1,1)""",
                       (cpf, nome, email, generate_password_hash(senha_temp), nivel, sec, set_, mat, json.dumps(vinculos)))
            db.commit()
            flash(f"Usuário criado! Senha temporária: {senha_temp}", "success")
            if email:
                html = f"<p>Olá, <b>{nome}</b>!</p><p>Seu acesso foi criado no sistema Banco de Horas de Ibiporã.</p><p><b>CPF:</b> {cpf}<br><b>Senha temporária:</b> {senha_temp}</p><p>Altere a senha no primeiro acesso.</p>"
                ok, _ = enviar_email_smtp(email, "Acesso ao Banco de Horas — Ibiporã", html)
                if ok: flash("E-mail enviado ao usuário.", "info")
            return redirect(url_for('admin_usuarios'))

    srvs = db.execute("SELECT matricula,nome FROM servidores WHERE arquivado=0 ORDER BY nome").fetchall()
    secs = [r[0] for r in db.execute("SELECT DISTINCT secretaria FROM servidores WHERE secretaria IS NOT NULL AND secretaria!='' ORDER BY secretaria").fetchall()]
    sets = [r[0] for r in db.execute("SELECT DISTINCT setor FROM servidores WHERE setor IS NOT NULL AND setor!='' ORDER BY setor").fetchall()]
    return render_template('admin/usuario_form.html', usuario=None,
                           servidores=srvs, secretarias=secs, setores=sets)


@app.route('/admin/usuarios/<int:uid>/editar', methods=['GET','POST'])
@master_required
def admin_editar_usuario(uid):
    db = get_db()
    u  = db.execute("SELECT * FROM usuarios WHERE id=?", (uid,)).fetchone()
    if not u: flash("Usuário não encontrado.", "danger"); return redirect(url_for('admin_usuarios'))
    if request.method == 'POST':
        nome  = request.form['nome'].strip()
        email = request.form['email'].strip()
        nivel = request.form['nivel']
        vinculos = request.form.getlist('vinculos')
        sec   = vinculos[0] if nivel == 'secretario' and vinculos else request.form.get('secretaria','').strip()
        set_  = vinculos[0] if nivel == 'chefia' and vinculos else request.form.get('setor','').strip()
        mat   = request.form.get('matricula','').strip()
        db.execute("UPDATE usuarios SET nome=?,email=?,nivel=?,secretaria=?,setor=?,matricula=?,vinculos=? WHERE id=?",
                   (nome, email, nivel, sec, set_, mat, json.dumps(vinculos), uid))
        db.commit()
        flash("Usuário atualizado.", "success")
        return redirect(url_for('admin_usuarios'))
    srvs = db.execute("SELECT matricula,nome FROM servidores WHERE arquivado=0 ORDER BY nome").fetchall()
    secs = [r[0] for r in db.execute("SELECT DISTINCT secretaria FROM servidores WHERE secretaria IS NOT NULL AND secretaria!='' ORDER BY secretaria").fetchall()]
    sets = [r[0] for r in db.execute("SELECT DISTINCT setor FROM servidores WHERE setor IS NOT NULL AND setor!='' ORDER BY setor").fetchall()]
    d = dict(u)
    d["vinculos_lista"] = get_vinculos(u)
    return render_template('admin/usuario_form.html', usuario=d,
                           servidores=srvs, secretarias=secs, setores=sets)


@app.route('/admin/usuarios/<int:uid>/toggle', methods=['POST'])
@master_required
def admin_toggle_usuario(uid):
    db = get_db()
    u  = db.execute("SELECT ativo FROM usuarios WHERE id=?", (uid,)).fetchone()
    if u:
        novo = 0 if u['ativo'] else 1
        db.execute("UPDATE usuarios SET ativo=? WHERE id=?", (novo, uid))
        db.commit()
        flash(f"Usuário {'ativado' if novo else 'desativado'}.", "success")
    return redirect(url_for('admin_usuarios'))


@app.route('/admin/usuarios/<int:uid>/reset-senha', methods=['POST'])
@master_required
def admin_reset_senha(uid):
    db   = get_db()
    u    = db.execute("SELECT * FROM usuarios WHERE id=?", (uid,)).fetchone()
    if not u: flash("Usuário não encontrado.", "danger"); return redirect(url_for('admin_usuarios'))
    nova = gerar_senha_temp()
    db.execute("UPDATE usuarios SET senha_hash=?, senha_temporaria=1 WHERE id=?",
               (generate_password_hash(nova), uid))
    db.commit()
    flash(f"Senha de '{u['nome']}' redefinida. Senha temporária: {nova}", "warning")
    if u['email']:
        html = f"<p>Olá, <b>{u['nome']}</b>.</p><p>Sua senha foi redefinida pelo administrador.</p><p><b>Nova senha temporária:</b> {nova}</p><p>Altere no próximo acesso.</p>"
        ok, err = enviar_email_smtp(u['email'], "Senha redefinida — Banco de Horas Ibiporã", html)
        if ok:
            flash("E-mail enviado ao usuário com a nova senha.", "info")
        elif err == "SMTP_NAO_CONFIGURADO":
            flash("E-mail não enviado: SMTP não configurado. A senha temporária foi exibida acima para repasse manual.", "warning")
        else:
            flash(f"E-mail não enviado: {err}. A senha temporária foi exibida acima para repasse manual.", "warning")
    return redirect(url_for('admin_usuarios'))


@app.route('/admin/config-email', methods=['GET','POST'])
@master_required
def admin_config_email():
    db = get_db()
    if request.method == 'POST':
        cfg_atual = obter_config_smtp()
        for chave in ['smtp_host','smtp_port','smtp_user','smtp_from','smtp_tls']:
            valor = request.form.get(chave,'').strip()
            db.upsert(
                "INSERT OR REPLACE INTO config (chave,valor) VALUES (?,?)",
                "INSERT INTO config (chave,valor) VALUES (?,?) ON CONFLICT (chave) DO UPDATE SET valor=EXCLUDED.valor",
                (chave, valor)
            )
        senha = request.form.get('smtp_pass','').strip()
        if senha:
            db.upsert(
                "INSERT OR REPLACE INTO config (chave,valor) VALUES (?,?)",
                "INSERT INTO config (chave,valor) VALUES (?,?) ON CONFLICT (chave) DO UPDATE SET valor=EXCLUDED.valor",
                ('smtp_pass', senha)
            )
        elif not cfg_atual.get('smtp_pass'):
            db.upsert(
                "INSERT OR REPLACE INTO config (chave,valor) VALUES (?,?)",
                "INSERT INTO config (chave,valor) VALUES (?,?) ON CONFLICT (chave) DO UPDATE SET valor=EXCLUDED.valor",
                ('smtp_pass', '')
            )
        db.commit()
        flash("Configurações de e-mail salvas.", "success")
        # Teste de envio
        email_teste = request.form.get('email_teste','').strip()
        if email_teste:
            ok, err = enviar_email_smtp(email_teste, "Teste SMTP — Banco de Horas Ibiporã",
                                        "<p>Configuração de e-mail funcionando corretamente!</p>")
            flash(f"Teste: {'✅ E-mail enviado com sucesso!' if ok else f'❌ Falha: {err}'}", "info" if ok else "danger")
        return redirect(url_for('admin_config_email'))
    cfg = obter_config_smtp()
    return render_template('admin/config_email.html', cfg=cfg)


# â”€â”€â”€ Auto-cadastro â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@app.route('/api/verificar-cpf')
def api_verificar_cpf():
    """AJAX: verifica CPF e retorna dados para o formulário de cadastro."""
    cpf = request.args.get('cpf','').strip()
    db  = get_db()

    # Já tem conta?
    u = db.execute("SELECT ativo FROM usuarios WHERE cpf=?", (cpf,)).fetchone()
    if u:
        msg = "Você já possui acesso. Faça login." if u['ativo'] else "Seu acesso está desativado. Contate o RH."
        return jsonify({"ok": False, "msg": msg})

    # Busca pre-autorização
    pre = db.execute("SELECT * FROM pre_autorizacoes WHERE cpf=?", (cpf,)).fetchone()

    # Busca servidor pelo CPF. Sem pré-autorização, o servidor pode criar conta
    # automaticamente como nível "servidor", usando a própria matrícula.
    srv = db.execute("SELECT * FROM servidores WHERE cpf=? AND arquivado=0", (cpf,)).fetchone()

    if not srv and not pre:
        return jsonify({"ok": False, "msg": "CPF não encontrado no sistema. Solicite liberação de acesso ao RH."})

    nivel     = pre['nivel']     if pre else 'servidor'
    matricula = pre['matricula'] if pre else (srv['matricula'] if srv else '')
    nome      = srv['nome']      if srv else ''

    # Vinculos (multiplos setores/secretarias)
    vinculos = get_vinculos(pre) if pre else []

    nivel_label = {'master':'Master (RH)','secretario':'Secretario',
                   'chefia':'Chefia Imediata','servidor':'Servidor'}.get(nivel, nivel)

    aviso = '' if pre else 'Nenhuma pre-autorizacao. Acesso como Servidor (padrao).'

    return jsonify({'ok': True, 'nome': nome, 'nivel': nivel, 'nivel_label': nivel_label,
                    'vinculos': vinculos, 'matricula': matricula, 'aviso': aviso})


@app.route('/criar-conta', methods=['GET','POST'])
def criar_conta():
    if request.method == 'POST':
        cpf       = request.form['cpf'].strip()
        nome_conf = request.form.get('nome_confirmado','').strip()
        email     = request.form['email'].strip()
        senha     = request.form['senha']
        conf      = request.form['confirmar']
        nivel     = request.form.get('nivel','servidor')
        vinculos  = request.form.getlist('vinculos')
        matricula = request.form.get('matricula','').strip()

        db = get_db()

        if db.execute('SELECT 1 FROM usuarios WHERE cpf=?', (cpf,)).fetchone():
            flash('CPF ja possui acesso. Faca login.', 'warning')
            return redirect(url_for('login'))
        if senha != conf:
            flash('As senhas nao coincidem.', 'danger')
            return render_template('criar_conta.html')
        if len(senha) < 8:
            flash('Minimo 8 caracteres.', 'danger')
            return render_template('criar_conta.html')

        pre = db.execute("SELECT * FROM pre_autorizacoes WHERE cpf=?", (cpf,)).fetchone()
        srv = db.execute("SELECT * FROM servidores WHERE cpf=? AND arquivado=0", (cpf,)).fetchone()
        if not pre and not srv:
            flash('CPF não encontrado no cadastro de servidores. Contate o RH.', 'danger')
            return render_template('criar_conta.html')

        # O backend não confia nos campos hidden: reaplica a regra oficial.
        if pre:
            nivel = pre['nivel'] or 'servidor'
            vinculos = get_vinculos(pre)
            matricula = pre['matricula'] or (srv['matricula'] if srv else '')
        else:
            nivel = 'servidor'
            vinculos = []
            matricula = srv['matricula']

        nome = nome_conf or (srv['nome'] if srv else cpf)

        vj = json.dumps(vinculos)
        db.execute('''INSERT INTO usuarios (cpf,nome,email,senha_hash,nivel,matricula,vinculos,ativo,senha_temporaria)
                      VALUES (?,?,?,?,?,?,?,1,0)''',
                   (cpf, nome, email, generate_password_hash(senha), nivel, matricula, vj))
        db.commit()
        flash(f'Conta criada! Bem-vindo(a), {nome}.', 'success')
        return redirect(url_for('login'))

    return render_template('criar_conta.html')
# â”€â”€â”€ Admin: Gerenciamento de Acessos â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@app.route('/admin/acessos')
@master_required
def admin_acessos():
    db = get_db()

    # Usuários por nível
    usuarios_rows = db.execute("""
        SELECT u.*, COUNT(u.id) OVER () AS total
        FROM usuarios u ORDER BY u.nivel, u.nome
    """).fetchall()
    usuarios = []
    for u in usuarios_rows:
        d = dict(u)
        d['vinculos_lista'] = get_vinculos(u)
        d['vinculos_json'] = json.dumps(d['vinculos_lista'])
        usuarios.append(d)

    # Contadores por nível
    contadores = {r['nivel']: r['qtd'] for r in db.execute(
        "SELECT nivel, COUNT(*) AS qtd FROM usuarios WHERE ativo=1 GROUP BY nivel").fetchall()}

    # Pré-autorizações pendentes (não cadastradas ainda)
    pre_rows = db.execute("""
        SELECT p.*,
               (SELECT nome FROM servidores WHERE cpf=p.cpf LIMIT 1) AS nome_servidor
        FROM pre_autorizacoes p
        WHERE p.cpf NOT IN (SELECT cpf FROM usuarios)
        ORDER BY p.criado_em DESC
    """).fetchall()
    pre = []
    for p in pre_rows:
        d = dict(p)
        d['vinculos_lista'] = get_vinculos(p)
        d['vinculos_json'] = json.dumps(d['vinculos_lista'])
        pre.append(d)

    # Log de últimos acessos
    ultimos = db.execute(
        "SELECT nome,cpf,nivel,ultimo_acesso FROM usuarios WHERE ultimo_acesso IS NOT NULL "
        "ORDER BY ultimo_acesso DESC LIMIT 10").fetchall()

    secs = [r[0] for r in db.execute(
        "SELECT DISTINCT secretaria FROM servidores WHERE secretaria IS NOT NULL AND secretaria!='' ORDER BY secretaria").fetchall()]
    sets = [r[0] for r in db.execute(
        "SELECT DISTINCT setor FROM servidores WHERE setor IS NOT NULL AND setor!='' ORDER BY setor").fetchall()]
    srvs = db.execute("SELECT matricula,nome,cpf FROM servidores WHERE arquivado=0 ORDER BY nome").fetchall()

    return render_template('admin/acessos.html',
                           usuarios=usuarios, contadores=contadores,
                           pre_autorizacoes=pre, ultimos=ultimos,
                           secretarias=secs, setores=sets, servidores=srvs)


@app.route('/admin/acessos/pre/novo', methods=['POST'])
@master_required
def admin_nova_pre_autorizacao():
    db  = get_db()
    cpf = request.form['cpf'].strip()
    if not cpf:
        flash('CPF obrigatorio.', 'danger')
        return redirect(url_for('admin_acessos'))
    if db.execute('SELECT 1 FROM usuarios WHERE cpf=?', (cpf,)).fetchone():
        flash('Este CPF ja possui conta ativa.', 'warning')
        return redirect(url_for('admin_acessos'))
    nivel    = request.form.get('nivel','servidor')
    vinculos = request.form.getlist('vinculos')
    mat      = request.form.get('matricula','').strip()
    obs      = request.form.get('obs','').strip()
    vj = json.dumps(vinculos)
    db.upsert(
        '''INSERT OR REPLACE INTO pre_autorizacoes (cpf,nivel,matricula,obs,vinculos)
           VALUES (?,?,?,?,?)''',
        '''INSERT INTO pre_autorizacoes (cpf,nivel,matricula,obs,vinculos)
           VALUES (?,?,?,?,?)
           ON CONFLICT (cpf) DO UPDATE SET
             nivel=EXCLUDED.nivel,
             matricula=EXCLUDED.matricula,
             obs=EXCLUDED.obs,
             vinculos=EXCLUDED.vinculos''',
        (cpf, nivel, mat, obs, vj)
    )
    db.commit()
    flash(f'Pre-autorizacao criada para CPF {cpf}.', 'success')
    return redirect(url_for('admin_acessos'))


@app.route('/admin/acessos/pre/<int:pid>/excluir', methods=['POST'])
@master_required
def admin_excluir_pre(pid):
    db = get_db()
    db.execute("DELETE FROM pre_autorizacoes WHERE id=?", (pid,))
    db.commit()
    flash("Pré-autorização removida.", "warning")
    return redirect(url_for('admin_acessos'))


@app.route('/admin/acessos/usuario/<int:uid>/alterar-nivel', methods=['POST'])
@master_required
def admin_alterar_nivel(uid):
    db       = get_db()
    nivel    = request.form['nivel']
    vinculos = request.form.getlist('vinculos')
    mat      = request.form.get('matricula','').strip()
    vj = json.dumps(vinculos)
    db.execute('UPDATE usuarios SET nivel=?,matricula=?,vinculos=? WHERE id=?',
               (nivel, mat, vj, uid))
    db.commit()
    flash('Nivel de acesso atualizado.', 'success')
    return redirect(url_for('admin_acessos'))


@app.route('/admin/acessos/usuario/<int:uid>/revogar', methods=['POST'])
@master_required
def admin_revogar_acesso(uid):
    db = get_db()
    u  = db.execute("SELECT nome FROM usuarios WHERE id=?", (uid,)).fetchone()
    if u:
        db.execute("UPDATE usuarios SET ativo=0 WHERE id=?", (uid,))
        db.commit()
        flash(f"Acesso de '{u['nome']}' revogado.", "danger")
    return redirect(url_for('admin_acessos'))


# No Render/Gunicorn o bloco __main__ não executa, então inicializamos o schema
# no import da aplicação. As migrações são idempotentes.
init_db()

if __name__ == "__main__":
    app.run(debug=True, port=5000)
