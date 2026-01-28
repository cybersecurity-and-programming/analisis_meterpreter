#!/usr/bin/env python3
import sys, cmd2, os, stat, pwd, grp, locale
from pathlib import Path
from datetime import datetime
from argparse import ArgumentParser
from argparse import Namespace
from datetime import datetime
from MeterpreterExceptions.MeterpreterExceptionClass import *
from modules.meterpreter_reverse_tcp import *

from cmd2 import (
    Color,
    stylize,
)

locale.setlocale(locale.LC_TIME, "es_ES.UTF-8")

COMMANDS_METERPRETER = "Análisis de Meterpreter"
COMMANDS_APP = "Recursos de la aplicacion"

class meterpreter_traffic(cmd2.Cmd):

    BANNER = r"""
    ███╗   ███╗███████╗████████╗███████╗██████╗ ████████╗██████╗ ███████╗██████╗
    ████╗ ████║██╔════╝╚══██╔══╝██╔════╝██╔══██╗╚══██╔══╝██╔══██╗██╔════╝██╔══██╗
    ██╔████╔██║█████╗     ██║   █████╗  ██████╔╝   ██║   ██████╔╝█████╗  ██████╔╝
    ██║╚██╔╝██║██╔══╝     ██║   ██╔══╝  ██╔══██╗   ██║   ██╔══██╗██╔══╝  ██╔══██╗
    ██║ ╚═╝ ██║███████╗   ██║   ███████╗██║  ██║   ██║   ██║  ██║███████╗██║  ██║
    ╚═╝     ╚═╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝

                    Forensic Meterpreter Traffic Analyzer
                        Stream • TLV • AES • Memory
    """
    # Desactivar comandos Python internos
    allow_python_commands = False

    def __init__(self, show_banner=True) -> None:
        super().__init__(include_ipy=True)

        if show_banner:
            self.print_banner()
        self._set_prompt()
        self.shortcuts = {}
        self.temp_history = []

        del cmd2.Cmd.do_macro
        del cmd2.Cmd.do_alias

    def print_banner(self):
        print(self.BANNER)

    def get_all_commands(self):
        return {
            'exit': self.do_exit,
            'meterpreter_reverse_tcp': self.do_meterpreter_reverse_tcp,
            'clear_history': self.do_clear_history,
            'save_package': self.do_save_package,
        }

    def onecmd(self, line, add_to_history=True):
        raw = line.raw.strip()

        try:
            result = result = super().onecmd(line, add_to_history=add_to_history)
            status = "OK"
        except MeterpreterError as e:
            status = f"ERROR: {type(e).__name__}"
            self.perror(str(e))
            result = False

        self.temp_history.append({
            "input": raw,
            "status": status,
            "timestamp": datetime.now().isoformat(timespec="seconds")
        })

        return result

    # ============================
    #  COMANDO HISTORY
    # ============================
    @cmd2.with_category(COMMANDS_APP)
    def do_history(self, _):
        if not self.temp_history:
            self.poutput("Historial vacío.")
            return

        for i, entry in enumerate(self.temp_history, 1):
            self.poutput(f"[{i}] {entry}")

    @cmd2.with_category(COMMANDS_APP)
    def do_clear_history(self, _):
        """
        Limpia el historial temporal de comandos.
        """
        self.temp_history.clear()
        self.poutput("Historial temporal limpiado.")

    # ============================
    #  COMANDO CD
    # ============================
    @cmd2.with_category(COMMANDS_APP)
    @cmd2.with_argument_list
    def do_cd(self, arglist: list[str]) -> None:
        """Change directory.
        Usage:
            cd <new_dir>
            cd        → go to HOME
            cd -      → go to previous directory
        """

        # --- 1) cd sin argumentos → HOME ---
        if not arglist:
            target = os.path.expanduser("~")

        # --- 2) cd - → directorio anterior ---
        elif arglist[0] == "-":
            if hasattr(self, "old_cwd") and self.old_cwd:
                target = self.old_cwd
            else:
                self.perror("No previous directory")
                return

        # --- 3) cd normal ---
        else:
            target = os.path.abspath(os.path.expanduser(arglist[0]))

        # --- Validaciones ---
        if not os.path.isdir(target):
            self.perror(f"{target} is not a directory")
            return

        if not os.access(target, os.R_OK):
            self.perror(f"You do not have read access to {target}")
            return

        # --- Cambiar directorio ---
        try:
            old = os.getcwd()
            os.chdir(target)
        except FileNotFoundError:
            self.perror(f"No such file or directory: {target}")
            self.last_result = None
            return
        except NotADirectoryError:
            self.perror(f"Not a directory: {target}")
            self.last_result = None
            return
        except PermissionError:
            self.perror(f"Permission denied: {target}")
            self.last_result = None
            return
        except OSError as ex:
            # Errores del sistema de archivos (I/O, rutas corruptas, etc.)
            self.perror(f"OS error: {ex}")
            self.last_result = None
            return

        self.old_cwd = old
        self.cwd = target
        self._set_prompt()
        self.last_result = target

    # -----------------------------
    # Ejecucion del comando ls -- ls -l
    # -----------------------------

    dir_parser = cmd2.Cmd2ArgumentParser()
    dir_parser.add_argument('-l', '--long', action='store_true', help="display in long format with one item per line")
    dir_parser.add_argument('-a', '--all', action='store_true', help="mostrar archivos ocultos")

    # colores ANSI estilo ls --color
    BLUE = "\033[34m"
    GREEN = "\033[32m"
    CYAN = "\033[36m"
    RED = "\033[31m"
    RESET = "\033[0m"

    def colorize(self, name, st):
        """Aplicar colores estilo ls --color."""
        mode = st.st_mode
        # directorio
        if stat.S_ISDIR(mode):
            return f"{self.BLUE}{name}{self.RESET}"

        # enlace simbólico
        if stat.S_ISLNK(mode):
            return f"{self.CYAN}{name}{self.RESET}"

        # ejecutable
        if mode & stat.S_IXUSR:
            return f"{self.GREEN}{name}{self.RESET}"

        # archivos comprimidos
        if name.endswith((".zip", ".gz", ".bz2", ".xz", ".tar")):
            return f"{self.RED}{name}{self.RESET}"

        return name

    @cmd2.with_category(COMMANDS_APP)
    @cmd2.with_argparser(dir_parser, with_unknown_args=True)
    def do_ls(self, args, unknown):
        if unknown:
            self.perror("ls no acepta argumentos posicionales")
            return

        cwd = os.getcwd()
        entries = os.listdir(cwd)

        if not args.all:
            entries = [e for e in entries if not e.startswith('.')]

        if not args.long:
            for f in entries:
                self.poutput(f)
            return

        # modo largo
        entries_info = []
        for name in entries:
            full = os.path.join(cwd, name)
            st = os.lstat(full)

            # permisos
            perms = stat.filemode(st.st_mode)

            # enlaces
            links = st.st_nlink

            # propietario y grupo
            owner = pwd.getpwuid(st.st_uid).pw_name
            group = grp.getgrgid(st.st_gid).gr_name

            # tamaño
            size = st.st_size

            # fecha estilo ls
            mtime = datetime.fromtimestamp(st.st_mtime).strftime("%b %d %H:%M")

            entries_info.append({
                "perms": perms,
                "links": links,
                "owner": owner,
                "group": group,
                "size": size,
                "mtime": mtime,
                "name": name,
                "st": st,
            })


        # -----------------------------
        # 2) Calcular anchos máximos
        # -----------------------------
        max_links = max(len(str(e["links"])) for e in entries_info)
        max_owner = max(len(e["owner"]) for e in entries_info)
        max_group = max(len(e["group"]) for e in entries_info)
        max_size  = max(len(str(e["size"])) for e in entries_info)

        # -----------------------------
        # 3) imprimir alineado + colores
        # -----------------------------
        for e in entries_info:
            colored_name = self.colorize(e["name"], e["st"])

            line = (
                f"{e['perms']} "
                f"{e['links']:>{max_links}} "
                f"{e['owner']:<{max_owner}} "
                f"{e['group']:<{max_group}} "
                f"{e['size']:>{max_size}} "
                f"{e['mtime']} "
                f"{colored_name}"
            )
            self.poutput(line)

    def _set_prompt(self) -> None:
        """Set prompt so it displays the current working directory."""
        self.cwd = os.getcwd()
        self.prompt = stylize(f'{self.cwd} $ ', style=Color.CYAN)

    # ============================
    #  COMANDO EXIT
    # ============================

    @cmd2.with_category(COMMANDS_APP)
    @cmd2.with_argument_list
    def do_exit(self, arg_list: list[str]) -> bool:
        """
        Salir de la herramienta.
        Uso: exit [codigo]
        """
        if arg_list:
            try:
                self.exit_code = int(arg_list[0])
            except ValueError:
                self.perror(f"{arg_list[0]} no es un código de salida válido")
                self.exit_code = 1
        return True

    # ============================
    #  COMANDO ANALISIS_METERPRETER
    # ============================

    @cmd2.with_category(COMMANDS_METERPRETER)
    def do_meterpreter_reverse_tcp(self, args):
        """
        Analiza tráfico de Meterpreter.
        Uso:
            analisis_meterpreter -f captura.pcap -m memoria.dmp -o salida.raw -p 4444
        """
        parser = cmd2.Cmd2ArgumentParser()
        parser.add_argument('-f', '--file', required=True, help='Archivo PCAP a analizar')
        parser.add_argument('-m', '--memory', required=True, help='Archivo de memoria dumpeada')
        parser.add_argument('-o', '--output', required=True, help='Archivo de salida')
        parser.add_argument('-p', '--port', required=True, help='Puerto del tráfico')

        try:
            parsed = parser.parse_args(args.split())
        except SystemExit:
            return

        # Validaciones
        if not Path(parsed.file).exists():
            raise FileMissingError(f"El archivo PCAP no existe: {parsed.file}")

        if not Path(parsed.memory).exists():
            raise FileMissingError(f"El archivo de memoria no existe: {parsed.memory}")

        self.poutput("Iniciando análisis de Meterpreter…")
        self.poutput(f"PCAP: {parsed.file}")
        self.poutput(f"Memoria: {parsed.memory}")
        self.poutput(f"Salida: {parsed.output}")
        self.poutput(f"Puerto: {parsed.port}")

        filename = parsed.output

        with open('analisis_trafico.txt', 'w') as f:
            pass

        # Paso 1: reconstruir stream desde PCAP
        resultado = extract_tcp_stream(parsed.file, filename, parsed.port)
        
        if resultado:
            analizar_stream_data(filename, parsed.memory)# Paso 2: si se reconstruyó correctamente, buscar clave AES
            analizar_output_trafico(filename, None)# Paso 3: si se encontró clave AES, mostrar TLVs descifrados

    @cmd2.with_category(COMMANDS_METERPRETER)
    def do_save_package(self, args):
        parser = cmd2.Cmd2ArgumentParser()
        parser.add_argument('-k', '--key', required=True, help='Clave AES encontrada')
        parser.add_argument('-i', '--id', required=True, help='Identificador')
        parser.add_argument('-o', '--output', required=True, help='Archivo con el trafico de red malicioso para analizar')

        try:
            parsed = parser.parse_args(args.split())
        except SystemExit:
            return

        # Validaciones
        if not Path(parsed.output).exists():
            raise FileMissingError(f"El archivo solicitado no existe: {parsed.file}")

        set_clave_aes(parsed.key)
        analizar_output_trafico(parsed.output, int(parsed.id, 16))
    # ============================
    #  COMANDOS NO PERMITIDOS
    # ============================
    # Bloquear shell externo (!comando)
    def do_shell(self, _):
        self.poutput("Comando no permitido.")

    def default(self, line):
        if line.startswith("!"):
            self.poutput("Comando no permitido.")
        else:
            super().default(line)

    def do_edit(self, _):
        self.poutput("Comando no permitido.")

    def do_shortcuts(self, _):
        self.poutput("Comando no permitido.")

# ============================
#  MAIN
# ============================
if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument('--no-banner', action='store_true', help='No mostrar el banner al iniciar')
    args = parser.parse_args()

    app = meterpreter_traffic(show_banner=not args.no_banner)
    sys_exit_code = app.cmdloop()
    app.poutput(f'{sys.argv[0]!r} exiting with code: {sys_exit_code}')
    sys.exit(sys_exit_code)
