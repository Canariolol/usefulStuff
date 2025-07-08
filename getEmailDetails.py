import os
import re
from flask import Flask, redirect, request, session, url_for, jsonify
from datetime import datetime, timedelta
import email.utils

from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

app = Flask(__name__)
app.secret_key = 'una-clave-secreta-para-desarrollo'
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

CLIENT_SECRETS_FILE = 'client_secret.json'
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly', 'https://www.googleapis.com/auth/userinfo.email', 'openid']

# --- Rutas de Autenticación ---
@app.route('/')
def index():
    return """
        <h1>Analizador de Correos de Gmail</h1>
        <p>Haz clic en el botón para obtener un análisis de tu bandeja de entrada.</p>
        <a href="/login"><button style="padding: 10px 15px; font-size: 16px;">Iniciar sesión con Google</button></a>
    """

@app.route('/login')
def login():
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES, redirect_uri=url_for('callback', _external=True))
    authorization_url, state = flow.authorization_url(access_type='offline', include_granted_scopes='true')
    session['state'] = state
    return redirect(authorization_url)

@app.route('/callback')
def callback():
    state = session['state']
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES, state=state, redirect_uri=url_for('callback', _external=True))
    authorization_response = request.url
    flow.fetch_token(authorization_response=authorization_response)
    credentials = flow.credentials
    session['credentials'] = {'token': credentials.token, 'refresh_token': credentials.refresh_token, 'token_uri': credentials.token_uri, 'client_id': credentials.client_id, 'client_secret': credentials.client_secret, 'scopes': credentials.scopes}
    return redirect(url_for('results'))

# --- Funciones Auxiliares ---
def get_header_value(headers, name):
    for header in headers:
        if header['name'].lower() == name.lower():
            return header['value']
    return ''

# --- NUEVA FUNCIÓN DE NORMALIZACIÓN ---
def normalize_subject(subject):
    """Limpia un asunto para agrupar temas similares."""
    s = subject.lower()
    # Eliminar prefijos como Re:, Fwd:, Rv:, etc.
    s = re.sub(r'^(re|fw|fwd|aw|rv|vs|enc|reenv|r)[\d\[\]]*:\s*', '', s).strip()
    # Eliminar números entre paréntesis o corchetes al final (ej. " (2)", " [3]")
    s = re.sub(r'\s*\[\d+\]$', '', s).strip()
    s = re.sub(r'\s*\(\d+\)$', '', s).strip()
    return s

# --- Endpoint Principal de Datos (modificado para usar normalización) ---
@app.route('/get-data')
def get_data():
    if 'credentials' not in session:
        return jsonify({'error': 'Usuario no autenticado'}), 401

    start_date_str = request.args.get('start_date')
    end_date_str = request.args.get('end_date')
    SUBJECT_LIMIT = 50
    PROCESSING_LIMIT = 200

    date_query = ""
    if start_date_str:
        date_query += f" after:{start_date_str.replace('-', '/')}"
    
    if end_date_str:
        end_date_obj = datetime.strptime(end_date_str, '%Y-%m-%d')
        inclusive_end_date = end_date_obj + timedelta(days=1)
        end_date_query_str = inclusive_end_date.strftime('%Y/%m/%d')
        date_query += f" before:{end_date_query_str}"

    exclude_sender_query = " -from:correo@correo.com"

    credentials = Credentials(**session['credentials'])
    service = build('gmail', 'v1', credentials=credentials)

    try:
        profile = service.users().getProfile(userId='me').execute()
        user_email = profile.get('emailAddress')

        start_date_obj = datetime.strptime(start_date_str, '%Y-%m-%d').date() if start_date_str else None
        end_date_obj = datetime.strptime(end_date_str, '%Y-%m-%d').date() if end_date_str else None

        # --- LÓGICA PARA CORREOS ENTRANTES ---
        # Usamos un diccionario para guardar el asunto original usando el normalizado como clave
        unique_incoming_subjects = {}
        inbox_threads_request = service.users().threads().list(userId='me', q=f"in:inbox{date_query}{exclude_sender_query}", maxResults=PROCESSING_LIMIT).execute()
        inbox_threads = inbox_threads_request.get('threads', [])

        for thread_info in inbox_threads:
            thread_details = service.users().threads().get(userId='me', id=thread_info['id']).execute()
            messages = thread_details.get('messages', [])
            if not messages: continue

            first_message = messages[0]
            date_str = get_header_value(first_message['payload']['headers'], 'Date')
            if not date_str: continue

            first_message_dt = email.utils.parsedate_to_datetime(date_str)
            first_message_date = first_message_dt.date()
            
            if start_date_obj and end_date_obj and (start_date_obj <= first_message_date <= end_date_obj):
                original_subject = get_header_value(first_message['payload']['headers'], 'Subject')
                normalized = normalize_subject(original_subject)
                # Si el asunto normalizado no está, lo añadimos
                if normalized not in unique_incoming_subjects:
                    unique_incoming_subjects[normalized] = original_subject

        # --- LÓGICA PARA CORREOS SALIENTES ---
        unique_outgoing_subjects = {}
        outgoing_exclude_keywords = ["poner keywords aca"]
        
        sent_threads_request = service.users().threads().list(userId='me', q=f"in:sent{date_query}", maxResults=PROCESSING_LIMIT).execute()
        sent_threads = sent_threads_request.get('threads', [])
        
        for thread_info in sent_threads:
            thread_details = service.users().threads().get(userId='me', id=thread_info['id']).execute()
            messages = thread_details.get('messages', [])
            if not messages: continue

            original_subject = get_header_value(messages[0]['payload']['headers'], 'Subject')
            normalized = normalize_subject(original_subject)
            
            # Aplicar filtro de exclusión por asunto
            if normalized.strip() == 'monitor' or 'alarmas':
                continue
            if any(keyword.lower() in normalized for keyword in outgoing_exclude_keywords):
                continue
            
            # Si el asunto normalizado ya fue contado, saltamos el resto de la lógica
            if normalized in unique_outgoing_subjects:
                continue

            message_count = len(messages)

            if message_count > 1:
                first_message = messages[0]
                date_str = get_header_value(first_message['payload']['headers'], 'Date')
                if not date_str: continue
                
                first_message_dt = email.utils.parsedate_to_datetime(date_str)
                first_message_date = first_message_dt.date()

                if start_date_obj and end_date_obj and (start_date_obj <= first_message_date <= end_date_obj):
                    unique_outgoing_subjects[normalized] = original_subject
            
            elif message_count == 1:
                to_header = get_header_value(messages[0]['payload']['headers'], 'To')
                if 'soporte@west-ingenieria.cl' not in to_header:
                    unique_outgoing_subjects[normalized] = original_subject
        
        # --- CONTEO FINAL ---
        incoming_threads_count = len(unique_incoming_subjects)
        outgoing_threads_count = len(unique_outgoing_subjects)
        
        # --- LÓGICA PARA CORREOS NO RESPONDIDOS ---
        unanswered_emails = []
        query_unanswered = f"in:inbox and -in:sent{date_query}{exclude_sender_query}"
        request_unanswered = service.users().threads().list(userId='me', q=query_unanswered, maxResults=5).execute()
        threads_unanswered = request_unanswered.get('threads', [])
        for thread_info in threads_unanswered:
            thread_details = service.users().threads().get(userId='me', id=thread_info['id']).execute()
            first_message = thread_details['messages'][0]
            subject = get_header_value(first_message['payload']['headers'], 'Subject')
            snippet = first_message['snippet']
            unanswered_emails.append({'subject': subject, 'snippet': snippet})
        
        # --- RESPUESTA JSON FINAL ---
        return jsonify({
            'user_email': user_email,
            'incoming_threads_count': incoming_threads_count,
            'outgoing_threads_count': outgoing_threads_count,
            'incoming_subjects': list(unique_incoming_subjects.values())[:SUBJECT_LIMIT],
            'outgoing_subjects': list(unique_outgoing_subjects.values())[:SUBJECT_LIMIT],
            'unanswered_emails': unanswered_emails
        })
    except HttpError as e:
        return jsonify({'error': f"Error de la API de Gmail: {e}"}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/results')
def results():
    return """
        <html>
            <head>
                <title>Resultados del Análisis</title>
                <style>
                    body { font-family: sans-serif; margin: 2em; background-color: #f4f7f6; }
                    .container { max-width: 800px; margin: auto; }
                    h1, h2 { color: #333; }
                    .card { background-color: white; border: 1px solid #ddd; border-radius: 8px; padding: 20px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); }
                    .unanswered-email { border-left: 4px solid #f44336; padding-left: 15px; margin-bottom: 15px; }
                    strong { color: #0056b3; }
                    em { color: #555; }
                    .filter-section { display: flex; gap: 10px; align-items: center; margin-bottom: 20px; padding: 15px; background-color: #e9ecef; border-radius: 8px;}
                    .subject-list { list-style-type: disc; padding-left: 20px; font-size: 0.9em; max-height: 200px; overflow-y: auto; }
                    .email-display { text-align: right; color: #666; font-size: 0.9em; padding-bottom: 10px; }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="email-display" id="user-email-display"></div>
                    <h1>📊 Tu Análisis de Gmail</h1>
                    <div class="card filter-section">
                        <label for="start_date">Desde:</label>
                        <input type="date" id="start_date">
                        <label for="end_date">Hasta:</label>
                        <input type="date" id="end_date">
                        <button id="filter_button">Filtrar</button>
                    </div>
                    <div class="card">
                        <h2>Conteos Generales</h2>
                        <div id="counts-container"><p>Selecciona un rango de fechas y haz clic en Filtrar.</p></div>
                    </div>
                    <div class="card">
                        <h2>🚨 Correos Entrantes Sin Responder</h2>
                        <div id="unanswered-container"><p>Los resultados se mostrarán aquí.</p></div>
                    </div>
                    <div class="card">
                        <h2>Asuntos de Correos Recibidos (únicos)</h2>
                        <div id="incoming-subjects-container"><p>Los resultados se mostrarán aquí.</p></div>
                    </div>
                    <div class="card">
                        <h2>Asuntos de Correos Enviados (únicos y filtrados)</h2>
                        <div id="outgoing-subjects-container"><p>Los resultados se mostrarán aquí.</p></div>
                    </div>
                    <a href="/">Volver al inicio</a>
                </div>
                <script>
                    document.getElementById('filter_button').addEventListener('click', () => {
                        const startDate = document.getElementById('start_date').value;
                        const endDate = document.getElementById('end_date').value;
                        
                        if (!startDate || !endDate) {
                            alert('Por favor, selecciona una fecha de inicio y una de fin.');
                            return;
                        }

                        const countsContainer = document.getElementById('counts-container');
                        const unansweredContainer = document.getElementById('unanswered-container');
                        const emailDisplay = document.getElementById('user-email-display');
                        const incomingSubjectsContainer = document.getElementById('incoming-subjects-container');
                        const outgoingSubjectsContainer = document.getElementById('outgoing-subjects-container');

                        countsContainer.innerHTML = '<p>Cargando conteos...</p>';
                        unansweredContainer.innerHTML = '<p>Buscando correos...</p>';
                        incomingSubjectsContainer.innerHTML = '<p>Cargando asuntos...</p>';
                        outgoingSubjectsContainer.innerHTML = '<p>Cargando asuntos...</p>';
                        emailDisplay.innerHTML = '';
                        
                        let fetchUrl = `/get-data?start_date=${startDate}&end_date=${endDate}`;

                        fetch(fetchUrl)
                            .then(response => response.json())
                            .then(data => {
                                if (data.error) {
                                    document.querySelector('.container').innerHTML = `<p style="color: red;">Error: ${data.error}</p>`;
                                    return;
                                }
                                if (data.user_email) {
                                    emailDisplay.innerHTML = `Análisis para: <strong>${data.user_email}</strong>`;
                                }

                                countsContainer.innerHTML = `
                                    <p>Conversaciones entrantes (únicas por asunto): <strong>${data.incoming_threads_count}</strong></p>
                                    <p>Conversaciones salientes (únicas y según reglas): <strong>${data.outgoing_threads_count}</strong></p>
                                `;

                                const renderSubjectList = (container, subjects) => {
                                    if (subjects && subjects.length > 0) {
                                        let listHtml = '<ul class="subject-list">';
                                        subjects.forEach(subject => {
                                            const sanitizedSubject = subject.replace(/</g, "&lt;").replace(/>/g, "&gt;");
                                            listHtml += `<li>${sanitizedSubject}</li>`;
                                        });
                                        listHtml += '</ul>';
                                        container.innerHTML = listHtml;
                                    } else {
                                        container.innerHTML = '<p>No se encontraron correos que cumplan los criterios en este periodo.</p>';
                                    }
                                };

                                renderSubjectList(incomingSubjectsContainer, data.incoming_subjects);
                                renderSubjectList(outgoingSubjectsContainer, data.outgoing_subjects);

                                if (data.unanswered_emails && data.unanswered_emails.length > 0) {
                                    let emailsHtml = '';
                                    data.unanswered_emails.forEach(email => {
                                        const sanitizedSubject = email.subject.replace(/</g, "&lt;").replace(/>/g, "&gt;");
                                        const sanitizedSnippet = email.snippet.replace(/</g, "&lt;").replace(/>/g, "&gt;");
                                        emailsHtml += `<div class="unanswered-email"><p><strong>Asunto:</strong> ${sanitizedSubject}</p><p><em>${sanitizedSnippet}...</em></p></div>`;
                                    });
                                    unansweredContainer.innerHTML = emailsHtml;
                                } else {
                                    unansweredContainer.innerHTML = '<p>¡Felicidades! No tienes correos sin responder en este periodo.</p>';
                                }
                            })
                            .catch(error => {
                                console.error('Error al obtener los datos:', error);
                                document.querySelector('.container').innerHTML = '<p style="color: red;">No se pudieron cargar los datos.</p>';
                            });
                    });
                </script>
            </body>
        </html>
    """

if __name__ == '__main__':
    app.run(debug=True)
