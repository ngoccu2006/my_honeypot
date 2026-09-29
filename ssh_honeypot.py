# Thư viện
import logging
import socket
import paramiko
import threading
from logging.handlers import RotatingFileHandler

# constants
logging_format = logging.Formatter('%(message)s')
SSH_BANNER = "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13"
PROMPT = b'corporate-jumpbox2$ '

host_key = paramiko.RSAKey(filename='server.key')

# loggers và logging files
funnel_logger = logging.getLogger('funnel_logger')
funnel_logger.setLevel(logging.INFO)
funnel_handler = RotatingFileHandler('audits.log', maxBytes=5*1024*1024, backupCount=5, encoding='utf-8')
funnel_handler.setFormatter(logging_format)
funnel_logger.addHandler(funnel_handler)

creds_logger = logging.getLogger('Creds_logger')
creds_logger.setLevel(logging.INFO)
creds_handler = RotatingFileHandler('cmd_audits.log', maxBytes=5*1024*1024, backupCount=5, encoding='utf-8')
creds_handler.setFormatter(logging_format)
creds_logger.addHandler(creds_handler)


# emulated shell
def emulated_shell(channel, client_ip):
    channel.send(PROMPT)
    command = b''
    while True:
        char = channel.recv(1)
        if not char:                               # client ngắt kết nối
            break

        if char in (b'\x7f', b'\x08'):             # backspace
            if command:
                command = command[:-1]
                channel.send(b'\b \b')
            continue

        if char == b'\x03':                        # Ctrl+C
            channel.send(b'^C\r\n' + PROMPT)
            command = b''
            continue

        if char == b'\x04':                        # Ctrl+D
            if not command:
                channel.send(b'logout\r\n')
                break
            continue

        if char == b'\x1b':                        # chuỗi escape (mũi tên, Delete, Home...)
            nxt = channel.recv(1)
            if nxt == b'[':
                while True:
                    b = channel.recv(1)
                    if not b or b'@' <= b <= b'~':
                        break
            continue

        if char == b'\t' or (char[0] < 0x20 and char != b'\r'):   # Tab và ký tự điều khiển khác
            continue

        channel.send(char)                         # echo
        if char != b'\r':
            command += char
            continue

        cmd = command.strip().decode(errors='replace')
        command = b''
        creds_logger.info(f'Command "{cmd}" executed by {client_ip}')

        if cmd == 'exit':
            channel.send(b'\r\nlogout\r\n')
            break
        elif cmd == 'pwd':
            response = '/usr/local'
        elif cmd == 'whoami':
            response = 'corpuser1'
        elif cmd == 'ls':
            response = 'jumpbox1.conf'
        elif cmd == 'cat jumpbox1.conf':
            response = 'HI, How are you today?'
        elif cmd == '':
            response = None
        else:
            response = f'bash: {cmd.split()[0]}: command not found'

        channel.send(b'\r\n')
        if response:
            channel.send(response.encode() + b'\r\n')
        channel.send(PROMPT)

    channel.close()


# ssh server + socket
class Server(paramiko.ServerInterface):
    def __init__(self, client_ip, input_username=None, input_password=None):
        self.event = threading.Event()
        self.client_ip = client_ip
        self.input_username = input_username
        self.input_password = input_password

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def get_allowed_auths(self, username):
        return 'password'

    def check_auth_password(self, username, password):
        funnel_logger.info(f"Client IP: {self.client_ip} | Username: {username} | Password: {password}")
        creds_logger.info(f'{self.client_ip}, {username}, {password}')
        if self.input_username is not None and self.input_password is not None:
            if username == self.input_username and password == self.input_password:
                return paramiko.AUTH_SUCCESSFUL
            return paramiko.AUTH_FAILED
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_exec_request(self, channel, command):
        if isinstance(command, bytes):
            command = command.decode(errors='replace')
        creds_logger.info(f'Exec command "{command}" executed by {self.client_ip}')
        try:
            name = command.split()[0] if command.split() else ''
            channel.send(f'bash: {name}: command not found\r\n'.encode())
            channel.send_exit_status(127)
            channel.close()
        except Exception:
            pass
        return True


def client_handle(client, addr, username, password):
    client_ip = addr[0]
    print(f"{client_ip} has connected to the server.")
    transport = None

    try:
        transport = paramiko.Transport(client)
        transport.local_version = SSH_BANNER
        server = Server(client_ip=client_ip, input_username=username, input_password=password)

        transport.add_server_key(host_key)
        transport.start_server(server=server)

        channel = transport.accept(100)
        if channel is None:
            print("No channel was opened")
            return

        # chỉ vào shell khi client yêu cầu shell (exec đã được xử lý riêng)
        if not server.event.wait(10):
            return

        standard_banner = "Welcome to Ubuntu 24.04.1 LTS (GNU/Linux 6.8.0-45-generic x86_64)\r\n\r\n"
        channel.send(standard_banner.encode())
        emulated_shell(channel, client_ip=client_ip)

    except Exception as e:
        print(f"ERROR: {e}")
    finally:
        if transport is not None:
            try:
                transport.close()
            except Exception:
                pass
        client.close()


# Provision SSH-based Honeypot
def honeypot(address, port, username, password):
    socks = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socks.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    socks.bind((address, port))
    socks.listen(100)
    socks.settimeout(1.0)          # để vòng lặp kiểm tra Ctrl+C mỗi giây
    print(f"SSH server is listening on port {port}.")

    try:
        while True:
            try:
                client, addr = socks.accept()
            except socket.timeout:
                continue
            except OSError as error:
                print(error)
                break
            t = threading.Thread(target=client_handle,
                                 args=(client, addr, username, password),
                                 daemon=True)
            t.start()
    finally:
        socks.close()