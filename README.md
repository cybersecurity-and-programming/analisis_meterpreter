# 🕵️‍♂️ Forensic Meterpreter Traffic Analyzer

Aplicación forense diseñada para analizar, clasificar y visualizar tráfico generado por sesiones Meterpreter. Permite identificar patrones, comandos y comportamientos característicos del payload, facilitando investigaciones de intrusión y ejercicios de respuesta ante incidentes.

El proyecto ha sido testeado en entornos reales de entrenamiento, incluyendo:

La máquina Response de Hack The Box
El challenge Shadow of the Undead

Su objetivo es ofrecer una herramienta ligera y comprensible para analistas que necesiten estudiar tráfico malicioso sin depender de soluciones complejas o propietarias.

✨ Características principales
Detección y parsing de tráfico asociado a Meterpreter
Identificación de comandos y fases de interacción
Visualización clara de eventos relevantes
Pensado para entornos de DFIR y análisis educativo

La siguiente imagen muestra la ejecución de la herramienta analisis_meterpreter.py en un entorno Kali Linux, durante una simulación de respuesta ante incidentes basada en la máquina Response de Hack The Box.

Tras invocar el modo meterpreter_reverse_tcp, se realiza un análisis completo del tráfico capturado en el archivo dump.pcap, correlacionado con una muestra de memoria (core.update). El proceso reconstruye el flujo TCP, identifica la clave AES utilizada en la sesión y extrae la clave pública RSA del payload.

Este tipo de análisis permite validar la presencia de una sesión Meterpreter activa, identificar el canal de comunicación cifrado y extraer artefactos relevantes para el estudio forense.

<p align="center">
<img src="assets/1.png" width="700">
</p>

Este escenario reproduce condiciones reales de intrusión y demuestra la capacidad de la herramienta para operar sobre evidencia en crudo, sin depender de frameworks externos.
