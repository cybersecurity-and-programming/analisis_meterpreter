from scapy.all import sniff, TCP
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from modules.msfconsts import tlv_types, cmd_ids
import os, logging
from scapy.error import Scapy_Exception
from modules.pcap_helper import *
from MeterpreterExceptions.MeterpreterExceptionClass import IncorrectLenghtKey
# ============================================================
#  CONSTANTES Y CONFIGURACIÓN
# ============================================================

# Configuración de logging
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

# Tamaños fijos del protocolo (en bytes)
HEADER_SIZE = 16 + 4 + 4 + 4   # GUID (16) + flags (4) + length (4) + type (4)
XOR_KEY_SIZE = 4               # Tamaño típico de clave XOR usada en el canal
AES_BLOCK_SIZE = 16            # Tamaño de bloque estándar de AES

# Variables globales
clave_aes = None
enc_types = {0: "None", 1: "AES256", 2: "AES128"}
packet_types = {0: "Req", 1: "Resp"}
identificador_paquete = None
# ============================================================
#  UTILIDADES DE PARSING BINARIO
# ============================================================

def get_bytes(data: bytes, n: int) -> tuple[bytes, bytes]:
    """
    Extrae los primeros n bytes de un buffer y devuelve también el resto.

    Esta función permite un parseo secuencial limpio sin usar índices
    mágicos. Es útil para interpretar estructuras binarias campo a campo.

    Args:
        data (bytes): Buffer original.
        n (int): Número de bytes a extraer.

    Returns:
        tuple: (primeros_n_bytes, resto_del_buffer)
    """
    return data[:n], data[n:]

# ============================================================
#  UTILIDADES CRIPTOGRÁFICAS Y DE PARSING
# ============================================================

def unpad(data: bytes) -> bytes:
    """
    Elimina padding PKCS#7 de un bloque de datos.

    Si el padding no es válido (longitud 0 o mayor que el tamaño de bloque),
    se devuelve el buffer original sin modificar.

    Args:
        data (bytes): Datos con posible padding.

    Returns:
        bytes: Datos sin padding o buffer original si es inválido.
    """
    if not data:
        logging.error("No se puede eliminar padding: buffer vacío")
        return data

    pad_len = data[-1]

    # Validación del padding
    if pad_len == 0 or pad_len > AES_BLOCK_SIZE:
        logging.warning("Padding inválido detectado, devolviendo datos originales")
        return data

    return data[:-pad_len]


def get_possible_keys(filepath) -> list[bytes]:
    """
    Extrae posibles claves AES de 32 bytes desde un volcado de memoria.

    Este método recorre el archivo byte a byte y devuelve todas las
    secuencias consecutivas de 32 bytes, sin asumir estructura interna.

    Args:
        filepath (str): Ruta al archivo de memoria.

    Returns:
        list[bytes]: Lista de posibles claves de 32 bytes.
    """
    if not os.path.isfile(filepath):
        logging.error(f"Archivo de memoria no encontrado: {filepath}")
        return []

    try:
        with open(filepath, 'rb') as f:
            data = f.read()
    except OSError as e:
        logging.error(f"Error al leer '{filepath}': {e}")
        return []

    keys = []
    max_index = len(data) - 32

    for i in range(max_index + 1):
        keys.append(data[i:i + 32])
    return keys


def xor(data: bytes, key: bytes) -> bytes:
    """
    Aplica XOR entre un buffer de datos y una clave.

    Args:
        data (bytes): Datos a procesar.
        key (bytes): Clave XOR.

    Returns:
        bytes: Resultado del XOR.
    """
    if not key:
        logging.error("Clave XOR vacía")
        return data

    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

def parse_tlv(data: bytes) -> list[tuple[int, int, bytes]]:
    """
    Parsea estructuras TLV (Type-Length-Value) desde un buffer binario.

    Cada entrada TLV debe tener al menos 8 bytes:
        - 4 bytes: longitud total del TLV
        - 4 bytes: identificador de tipo
        - N bytes: valor

    Args:
        data (bytes): Buffer que contiene TLVs consecutivos.

    Returns:
        list[tuple[int, int, bytes]]: Lista de tuplas (type_id, length, value).
    """
    result = []

    while len(data) >= 8:
        length = int.from_bytes(data[:4], 'big')
        type_id = int.from_bytes(data[4:8], 'big')

        # Validación de longitud
        if length < 8 or len(data) < length:
            logging.warning(f"TLV malformado: length={length}, disponible={len(data)}")
            break

        value = data[8:length]
        result.append((type_id, length, value))

        data = data[length:]

    return result

def process_packet(packet_data: bytes, keys: list[bytes]) -> tuple[object, bytes]:
    """
    Procesa un paquete individual del stream ya reconstruido.

    Extrae la clave XOR, descifra el encabezado, interpreta los campos
    estructurales del protocolo y determina si es necesario buscar la clave AES
    o si ya se puede decodificar el contenido TLV.

    Args:
        packet_data (bytes): Datos binarios del paquete.
        keys (list[bytes]): Lista de posibles claves AES extraídas de memoria.

    Returns:
        tuple: (resultado, resto_del_stream)
               - resultado puede ser None o un objeto devuelto por funciones posteriores.
               - resto_del_stream es el buffer restante tras procesar este paquete.
    """

    # Extraer clave XOR
    xor_key, packet_data = get_bytes(packet_data, XOR_KEY_SIZE)

    # Validación mínima del tamaño del paquete
    if len(packet_data) < HEADER_SIZE:
        logging.warning("Paquete incompleto: tamaño insuficiente para el encabezado")
        return None, b''

    # Extraer y descifrar encabezado
    header, packet_data = get_bytes(packet_data, HEADER_SIZE)
    header = xor(header, xor_key)

    # Interpretar campos del encabezado
    try:
        session_guid = int.from_bytes(header[0:16], 'big')
        encr_flags   = int.from_bytes(header[16:20], 'big')
        pack_len     = int.from_bytes(header[20:24], 'big')
        pack_type    = int.from_bytes(header[24:28], 'big')

        ptype_desc = packet_types.get(pack_type, f"Unknown({pack_type})")
        enc_desc   = enc_types.get(encr_flags, f"Unknown({encr_flags})")

        with open('analisis_trafico.txt', 'a', encoding='utf-8') as f:
            f.write(f"Packet: type={ptype_desc:<4} len={pack_len:<8} enc={enc_desc} sess=0x{session_guid:x}\n")
    except (ValueError, IndexError, TypeError) as e:
        logging.error(f"Encabezado corrupto o incompleto: {e}")
        return None, b''
    except OSError as e:
        logging.error(f"Error guardando archivo: {e}")

    # Longitud del bloque TLV
    tlv_len = pack_len - 8

    if tlv_len < 0:
        logging.warning(f"Longitud TLV inválida: {tlv_len}")
        return None, b''

    if len(packet_data) < tlv_len:
        logging.warning(f"Datos insuficientes para TLV: requeridos={tlv_len}, disponibles={len(packet_data)}")
        return None, b''

    # Si aún no tenemos clave AES, intentar encontrarla
    if clave_aes is None:
        return search_aes_key(encr_flags=encr_flags, tlv_len=tlv_len, xor_key=xor_key, keys=keys, pack_len=pack_len, packet_data=packet_data)

    # Si ya tenemos clave AES, procesar normalmente
    return mostrar_output(packet_data=packet_data, tlv_len=tlv_len, xor_key=xor_key, encr_flags=encr_flags, aes_key=keys)

def search_aes_key(encr_flags: int, tlv_len: int, xor_key: bytes, keys: list[bytes], pack_len: int, packet_data: bytes) -> tuple[bytes | None, bytes]:
    """
    Intenta identificar una clave AES válida probando todas las claves
    extraídas del volcado de memoria. Solo se ejecuta si aún no se ha
    encontrado una clave AES global.

    Args:
        encr_flags (int): Indicador de si el paquete está cifrado.
        tlv_len (int): Longitud del bloque TLV.
        xor_key (bytes): Clave XOR usada para descifrar el encabezado.
        keys (list[bytes]): Lista de posibles claves AES (32 bytes).
        pack_len (int): Longitud total del paquete.
        packet_data (bytes): Datos restantes del paquete.

    Returns:
        tuple:
            - (None, tlv_data) si se encuentra clave AES.
            - (packet_data_restante, tlv_data) si no se encuentra.
    """

    # Extraer TLV y descifrarlo con XOR
    tlv_data, packet_data = get_bytes(packet_data, tlv_len)
    tlv_data = xor(tlv_data, xor_key)

    # Solo intentamos AES si el flag indica cifrado
    if encr_flags == 1: #clave AES256
        if len(tlv_data) < AES_BLOCK_SIZE:
            logging.warning("TLV demasiado pequeño para contener IV AES")
            return packet_data, tlv_data

        aes_iv = tlv_data[:AES_BLOCK_SIZE]
        encrypted = tlv_data[AES_BLOCK_SIZE:]

        for aes_key in keys:
            # Validación mínima de clave
            if len(aes_key) != 32:
                continue

            try:
                cipher = AES.new(aes_key, AES.MODE_CBC, iv=aes_iv)
                pt = cipher.decrypt(encrypted)
                length = int.from_bytes(pt[:4], 'big')
            except (ValueError, KeyError, IndexError, TypeError):
                continue

            # Heurística mínima: la longitud debe ser coherente
            if 0 < length < pack_len:

                global clave_aes
                clave_aes = aes_key.hex()
                logging.info(f"Clave AES válida encontrada: {clave_aes}")
                return None, b''  # No queda stream que procesar en este paquete

    # Si no se encontró clave AES
    return packet_data, tlv_data

def mostrar_output(packet_data: bytes, tlv_len: int, xor_key: bytes, encr_flags: int, aes_key: bytes) -> tuple[bytes, bytes]:
    """
    Procesa y muestra el contenido TLV de un paquete ya descifrado o sin cifrar.

    Args:
        packet_data (bytes): Datos restantes del paquete.
        tlv_len (int): Longitud del bloque TLV.
        xor_key (bytes): Clave XOR usada para descifrar el TLV.
        encr_flags (int): Indicador de cifrado (0 = sin cifrar, 1 = AES).
        aes_key (bytes): Clave AES en bruto (32 bytes).

    Returns:
        bytes: Resto del stream tras consumir el TLV.
    """

    # Extraer TLV y descifrar con XOR
    global identificador_paquete

    tlv_data, data = get_bytes(packet_data, tlv_len)
    tlv_data = xor(tlv_data, xor_key)

    # TLV sin cifrado
    if encr_flags == 0:
        for type_id, length, value in parse_tlv(tlv_data):
            v = value
            t_name = tlv_types.get(type_id, f"TLV_TYPE_UNK")

            if t_name == "TLV_TYPE_RSA_PUB_KEY" and identificador_paquete == None:
                #Si encuentra clave publica
                key = RSA.importKey(bytes(value))
                pubkey = key.publickey().exportKey("PEM")

                logging.info("Mostrando clave RSA publica")
                print(pubkey.decode('utf-8'))

            try:
                with open('analisis_trafico.txt', 'a', encoding='utf-8') as f:
                    f.write(f"TLV sin cifrado → type=0x{type_id:x}, length=0x{length:x}\n")
            except OSError as e:
                logging.error(f"Error guardando archivo: {e}")
        return data, tlv_data

    # TLV cifrado con AES
    if encr_flags == 1:
        if len(tlv_data) < AES_BLOCK_SIZE:
            logging.warning("TLV demasiado pequeño para contener IV AES")
            return data, tlv_data

        aes_iv = tlv_data[:AES_BLOCK_SIZE]
        encrypted = tlv_data[AES_BLOCK_SIZE:]

        try:
            cipher = AES.new(aes_key, AES.MODE_CBC, iv=aes_iv)
            pt = unpad(cipher.decrypt(encrypted))
        except (ValueError, KeyError) as e:
            logging.error(f"Error descifrando TLV con AES: {e}")
            return data, tlv_data

        for type_id, length, value in parse_tlv(pt):
            v = value

            if type_id == 0x20001:
                cmd_id = int.from_bytes(v[:4], "big")
                v = cmd_ids.get(cmd_id, f"UNKNOWN_CMD_ID({cmd_id})")
            t_name = tlv_types.get(type_id, f"TLV_TYPE_UNK")

            try:
                with open('analisis_trafico.txt', 'a', encoding='utf-8') as f:
                    f.write(f"TLV l={length:<8} t={t_name:<26}(0x{type_id:08x}) v={v}\n")

                if type_id == identificador_paquete:
                    with open('output_file', 'ab') as f:
                        f.write(v)
            except OSError as e:
                logging.error(f"Error guardando archivo: {e}")

        return data, pt

    # Flag desconocido
    logging.warning(f"Flag de cifrado desconocido: {encr_flags}")
    return data, tlv_data

# ============================================================
#  ANÁLISIS DE STREAM Y SALIDA FINAL
# ============================================================

def set_clave_aes(clave_aes_256:str):
    """
    Actualiza el valor de la clave AES 256
    """
    global clave_aes
    clave_aes = clave_aes_256

def analizar_output_trafico(file: str, type_id: int) -> None:
    """
    Analiza el tráfico ya procesado (stream reconstruido) y muestra
    los TLVs interpretados en consola usando la clave AES encontrada.

    Args:
        file (str): Ruta al archivo con el stream reconstruido.
    """
    global clave_aes
    global identificador_paquete

    identificador_paquete = type_id
    if clave_aes is None:
        logging.error("No se ha encontrado clave AES. No se puede analizar el tráfico.")
        return

    try:
        aes_key = bytes.fromhex(clave_aes)
        if len(aes_key) != 32:
            raise IncorrectLenghtKey("tamaño de clave AES 256 incorrecta")

        with open(file, 'rb') as f:
            stream_data = f.read()
    except ValueError:
        logging.error(f"Clave AES inválida: {clave_aes}")
        return
    except FileNotFoundError:
        logging.error(f"Archivo no encontrado: {file}")
        return
    except OSError as e:
        logging.error(f"Error al leer '{file}': {e}")
        return

    # Procesar paquetes hasta agotar el stream
    while stream_data:
        result = process_packet(stream_data, aes_key)
        if result is None:
            break
        stream_data, _ = result
    clave_aes = None

def analizar_stream_data(output_file: str, memory_dump: str) -> None:
    """
    Analiza el stream reconstruido para intentar identificar la clave AES
    usando un volcado de memoria.

    Args:
        output_file (str): Archivo con el stream reconstruido.
        memory_dump (str): Archivo de memoria dumpeada.
    """
    try:
        with open(output_file, 'rb') as f:
            stream_data = f.read()
    except FileNotFoundError:
        logging.error(f"Archivo no encontrado: {output_file}")
        return
    except OSError as e:
        logging.error(f"Error al leer '{output_file}': {e}")
        return

    keys = get_possible_keys(memory_dump)

    while stream_data:
        result = process_packet(stream_data, keys)
        if result is None:
            break
        stream_data, _ = result
