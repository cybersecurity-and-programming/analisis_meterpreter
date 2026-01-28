from scapy.all import sniff, TCP
import logging,os

# Configuración de logging
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
# ============================================================
#  EXTRACCIÓN DE TRÁFICO DESDE PCAP
# ============================================================
def extract_tcp_stream(pcap_file: str, output_file: str, target_port_str: str) -> bool:
    """
    Extrae el flujo TCP asociado a un puerto concreto desde un archivo PCAP.

    Este método no reconstruye sesiones ni reordena paquetes; simplemente
    concatena los payloads tal y como aparecen en el PCAP. Para análisis
    de ciertos payloads es suficiente porque el canal es secuencial.

    Args:
        pcap_file (str): Ruta al archivo PCAP.
        output_file (str): Archivo donde se guardará el stream crudo.
        target_port (int): Puerto TCP usado por el payload.

    Returns:
        None. Escribe el resultado en disco.
    """

    # Validación temprana del puerto
    try:
        target_port = int(target_port_str)
    except ValueError:
        logging.error(f"El puerto debe ser un número entero: {target_port_str}")
        return False

    if target_port <= 0:
        logging.error(f"Puerto inválido: {target_port}")
        return False

    # Validación del archivo PCAP
    if not os.path.isfile(pcap_file):
        logging.error(f"El archivo PCAP no existe: {pcap_file}")
        return False

    tcp_stream = bytearray()

    def get_stream(pkt) -> None:
        """
        Callback interno para procesar cada paquete del PCAP.
        """
        if not pkt.haslayer(TCP):
            return

        tcp = pkt[TCP]

        if target_port not in (tcp.sport, tcp.dport):
            return

        payload = bytes(tcp.payload)
        if payload:
            tcp_stream.extend(payload)

    try:
        sniff(offline=pcap_file, prn=get_stream, store=False)
    except FileNotFoundError:
        logging.error(f"No se pudo abrir el archivo PCAP: {pcap_file}")
        return False
    except Scapy_Exception as e:
        logging.error(f"Error al procesar el PCAP (Scapy): {e}")
        return False
    except OSError as e:
        logging.error(f"Error de E/S al leer el PCAP: {e}")
        return False

    if len(tcp_stream) == 0:
        logging.warning("No se encontró tráfico en el puerto especificado.")
        return False

    # Guardar el resultado
    try:
        with open(output_file, 'wb') as f:
            f.write(tcp_stream)
    except PermissionError:
        logging.error(f"Permiso denegado al escribir en '{output_file}'")
        return False
    except FileNotFoundError:
        logging.error(f"Ruta inválida para '{output_file}'")
        return False
    except OSError as e:
        logging.error(f"Error de E/S al escribir '{output_file}': {e}")
        return False

    logging.info(f"Flujo TCP reconstruido: {len(tcp_stream)} bytes escritos en '{output_file}'")
    return True
