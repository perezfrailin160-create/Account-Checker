import json
import base64
import hashlib
import hmac
import secrets
import pyaes
import os
import re
import threading
from datetime import datetime
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

from kivy.app import App
from kivy.clock import Clock
from kivy.metrics import dp
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.scrollview import ScrollView
from kivy.uix.textinput import TextInput
from kivy.utils import platform

EMAIL_RE = re.compile(r'^[^\s@:,]+@[^\s@:,]+\.[^\s@:,]+$')


def clean_lines(raw):
    unique, invalid, seen = [], [], set()
    duplicates = 0
    for number, line in enumerate(raw.splitlines(), 1):
        line = line.strip().lstrip('\ufeff')
        if not line or line.startswith('#'):
            continue
        if ':' not in line:
            invalid.append((number, 'Sin separador'))
            continue
        email, password = line.split(':', 1)
        email = email.strip().lower()
        if not EMAIL_RE.fullmatch(email) or not password.strip():
            invalid.append((number, 'Formato inválido'))
            continue
        if email in seen:
            duplicates += 1
            continue
        seen.add(email)
        unique.append((email, password))
    return unique, invalid, duplicates


def encrypt_accounts(accounts, master):
    """AES-256 CTR + HMAC-SHA256 encrypt-then-MAC, PBKDF2 300k."""
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(16)
    keys = hashlib.pbkdf2_hmac('sha256', master.encode('utf-8'), salt, 300000, dklen=64)
    plaintext = json.dumps(accounts, ensure_ascii=False).encode('utf-8')
    cipher = pyaes.AESModeOfOperationCTR(keys[:32], counter=pyaes.Counter(int.from_bytes(nonce, 'big')))
    ciphertext = cipher.encrypt(plaintext)
    tag = hmac.new(keys[32:], b'AC1' + salt + nonce + ciphertext, hashlib.sha256).digest()
    return b'AC1' + salt + nonce + tag + ciphertext


def decrypt_accounts(payload, master):
    if len(payload) < 67 or payload[:3] != b'AC1':
        raise ValueError('Archivo cifrado no reconocido.')
    salt, nonce, tag, ciphertext = payload[3:19], payload[19:35], payload[35:67], payload[67:]
    keys = hashlib.pbkdf2_hmac('sha256', master.encode('utf-8'), salt, 300000, dklen=64)
    expected = hmac.new(keys[32:], payload[:35] + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected):
        raise ValueError('Contraseña maestra incorrecta o archivo alterado.')
    cipher = pyaes.AESModeOfOperationCTR(keys[:32], counter=pyaes.Counter(int.from_bytes(nonce, 'big')))
    data = json.loads(cipher.decrypt(ciphertext).decode('utf-8'))
    if not isinstance(data, list) or any(not isinstance(item, list) or len(item) != 2 for item in data):
        raise ValueError('Datos inválidos.')
    return [(email, password) for email, password in data]


class AccountChecker(App):
    def build(self):
        self.title = 'Account Checker'
        self.accounts = []
        self.invalid = []
        self.duplicates = 0
        self.results = []
        self.busy = False
        self.output_dir = os.path.join(self.user_data_dir, 'resultados')
        os.makedirs(self.output_dir, exist_ok=True)

        root = BoxLayout(orientation='vertical', padding=dp(12), spacing=dp(8))
        root.add_widget(Label(text='ACCOUNT CHECKER', font_size='23sp', bold=True, size_hint_y=None, height=dp(42)))
        scroll = ScrollView()
        content = BoxLayout(orientation='vertical', spacing=dp(8), size_hint_y=None)
        content.bind(minimum_height=content.setter('height'))
        scroll.add_widget(content)
        root.add_widget(scroll)

        self.url = self.field(content, 'URL de API administrativa (HTTPS)', 'https://mi-plataforma.com/api/admin/accounts/status')
        self.token = self.field(content, 'Token administrativo (no se guarda)', 'Token privado', password=True)
        self.path = self.field(content, 'Ruta del archivo TXT', '/storage/emulated/0/Download/cuentas.txt')
        self.add_button(content, 'Seleccionar archivo TXT', self.pick_file)
        self.add_button(content, 'Cargar y depurar TXT', self.load_file)
        content.add_widget(Label(text='O pega aquí el contenido TXT:', size_hint_y=None, height=dp(28)))
        self.paste = TextInput(multiline=True, hint_text='correo@ejemplo.com:contraseña', size_hint_y=None, height=dp(110))
        content.add_widget(self.paste)
        self.add_button(content, 'Depurar texto pegado', self.load_pasted)
        self.add_button(content, 'Verificar estados por API', self.verify)
        self.master = self.field(content, 'Contraseña maestra (mínimo 12 caracteres)', 'Para cifrar o abrir archivo', password=True)
        self.add_button(content, 'Guardar cuentas cifradas (.acenc)', self.save_encrypted)
        self.encrypted_path = self.field(content, 'Ruta de archivo .acenc para abrir', 'Ruta completa del archivo cifrado')
        self.add_button(content, 'Abrir cuentas cifradas', self.open_encrypted)
        self.add_button(content, 'Guardar resultados TXT (sin contraseñas)', self.save)
        self.status = Label(text='Listo. Carga un TXT o pega tus cuentas.', size_hint_y=None, height=dp(80), halign='left', valign='middle')
        self.status.bind(size=lambda instance, value: setattr(instance, 'text_size', (value[0], None)))
        content.add_widget(self.status)
        self.log = TextInput(readonly=True, multiline=True, size_hint_y=None, height=dp(220))
        content.add_widget(self.log)
        return root

    def field(self, parent, label, hint, password=False):
        parent.add_widget(Label(text=label, size_hint_y=None, height=dp(24), halign='left'))
        item = TextInput(hint_text=hint, multiline=False, password=password, size_hint_y=None, height=dp(46))
        parent.add_widget(item)
        return item

    def add_button(self, parent, title, callback):
        button = Button(text=title, size_hint_y=None, height=dp(48))
        button.bind(on_release=lambda *_: callback())
        parent.add_widget(button)

    def message(self, value):
        self.status.text = value

    def pick_file(self):
        if platform != 'android':
            self.message('En PC escribe la ruta del archivo TXT.')
            return
        try:
            from androidstorage4kivy import Chooser
            Chooser(self.file_chosen).choose_content('text/plain')
        except Exception as exc:
            self.message('No se pudo abrir el selector: ' + str(exc))

    def file_chosen(self, uri_list):
        if not uri_list:
            return
        try:
            from androidstorage4kivy import SharedStorage
            private_path = SharedStorage().copy_from_shared(uri_list[0])
            self.path.text = private_path
            self.load_file()
        except Exception as exc:
            Clock.schedule_once(lambda dt: self.message('Error leyendo archivo: ' + str(exc)), 0)

    def load_file(self):
        try:
            with open(self.path.text.strip(), 'r', encoding='utf-8-sig') as handle:
                self.process(handle.read())
        except Exception as exc:
            self.message('No se pudo leer TXT: ' + str(exc))

    def load_pasted(self):
        self.process(self.paste.text)

    def process(self, raw):
        self.accounts, self.invalid, self.duplicates = clean_lines(raw)
        self.results = []
        self.message(f'Únicas: {len(self.accounts)} | Duplicadas: {self.duplicates} | Inválidas: {len(self.invalid)}')
        self.log.text = '\n'.join(email for email, _ in self.accounts[:150])
        if len(self.accounts) > 150:
            self.log.text += '\n... (vista limitada a 150 cuentas)'

    def verify(self):
        if self.busy:
            self.message('Ya hay una consulta en curso.')
            return
        url = self.url.text.strip()
        parsed = urlparse(url)
        if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
            self.message('Introduce una URL HTTPS válida de tu API administrativa.')
            return
        token = self.token.text.strip()
        if not token or not self.accounts:
            self.message('Necesitas token y cuentas cargadas.')
            return
        self.busy = True
        self.message('Consultando API administrativa...')
        emails = [email for email, _ in self.accounts]
        threading.Thread(target=self._verify_worker, args=(url, token, emails), daemon=True).start()

    def _verify_worker(self, url, token, emails):
        try:
            # Solo se envían correos. Nunca se transmiten contraseñas.
            if len(emails) > 500:
                raise ValueError('Máximo 500 cuentas por consulta.')
            body = json.dumps({'emails': emails}).encode('utf-8')
            request = Request(url, data=body, headers={
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + token,
                'Accept': 'application/json',
            }, method='POST')
            with urlopen(request, timeout=25) as response:
                if response.status != 200:
                    raise ValueError('Respuesta HTTP ' + str(response.status))
                data = json.load(response)
            statuses = data.get('accounts')
            if not isinstance(statuses, list):
                raise ValueError('La API debe devolver {"accounts": [...]}')
            allowed = {'active', 'inactive', 'not_found', 'unknown'}
            lookup = {}
            for entry in statuses:
                if not isinstance(entry, dict):
                    continue
                email = str(entry.get('email', '')).strip().lower()
                state = str(entry.get('status', 'unknown')).lower()
                if email in emails:
                    lookup[email] = state if state in allowed else 'unknown'
            results = [(email, lookup.get(email, 'unknown')) for email in emails]
            Clock.schedule_once(lambda dt: self._done(results), 0)
        except (HTTPError, URLError, ValueError, OSError, TimeoutError) as exc:
            message = str(exc)
            Clock.schedule_once(lambda dt: self._failed(message), 0)
        except Exception as exc:
            message = type(exc).__name__
            Clock.schedule_once(lambda dt: self._failed(message), 0)

    def _done(self, results):
        self.busy = False
        self.results = results
        counts = {key: sum(1 for _, state in results if state == key) for key in ('active', 'inactive', 'not_found', 'unknown')}
        self.message(' | '.join(f'{key}: {value}' for key, value in counts.items()))
        self.log.text = '\n'.join(f'{email} | {state}' for email, state in results[:150])

    def _failed(self, message):
        self.busy = False
        self.message('Error de API: ' + message[:180])

    def save_encrypted(self):
        if not self.accounts:
            self.message('Primero carga las cuentas.')
            return
        master = self.master.text
        if len(master) < 12:
            self.message('Usa una contraseña maestra de al menos 12 caracteres.')
            return
        try:
            stamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            path = os.path.join(self.output_dir, 'cuentas_' + stamp + '.acenc')
            blob = encrypt_accounts(self.accounts, master)
            with open(path, 'xb') as handle:
                handle.write(blob)
            self.encrypted_path.text = path
            self.message('Cuentas guardadas cifradas en: ' + path)
        except Exception as exc:
            self.message('Error al cifrar: ' + str(exc))

    def open_encrypted(self):
        master = self.master.text
        if not master:
            self.message('Escribe la contraseña maestra.')
            return
        try:
            with open(self.encrypted_path.text.strip(), 'rb') as handle:
                payload = handle.read(20 * 1024 * 1024 + 1)
            if len(payload) > 20 * 1024 * 1024:
                raise ValueError('Archivo demasiado grande.')
            accounts = decrypt_accounts(payload, master)
            self.accounts = accounts
            self.invalid, self.duplicates, self.results = [], 0, []
            self.log.text = '\n'.join(email for email, _ in accounts[:150])
            self.message(f'Archivo descifrado: {len(accounts)} cuentas. Las contraseñas no se muestran.')
        except Exception as exc:
            self.message('No se pudo abrir: ' + str(exc))

    def save(self):
        try:
            stamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            folder = os.path.join(self.output_dir, stamp)
            os.makedirs(folder, exist_ok=True)
            # Por seguridad, los reportes no incluyen contraseñas.
            files = {
                'cuentas_unicas.txt': '\n'.join(email for email, _ in self.accounts),
                'lineas_invalidas.txt': '\n'.join(f'Línea {num}: {reason}' for num, reason in self.invalid),
                'estados_api.txt': '\n'.join(f'{email} | {state}' for email, state in self.results),
                'resumen.txt': f'Únicas: {len(self.accounts)}\nDuplicadas: {self.duplicates}\nInválidas: {len(self.invalid)}\n',
            }
            for name, content in files.items():
                with open(os.path.join(folder, name), 'w', encoding='utf-8') as handle:
                    handle.write(content + '\n')
            self.message('Guardado en carpeta privada:\n' + folder)
        except Exception as exc:
            self.message('Error guardando: ' + str(exc))


if __name__ == '__main__':
    AccountChecker().run()
