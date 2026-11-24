# TP D – Desarrollo de aplicaciones distribuidas con BSD sockets

**I310 – Redes y Comunicación · grupo10**
Iñaki Etchegaray · Alejandro Orozco Lopez

Cliente en C con BSD sockets que resuelve los dos desafíos del TP en una sola ejecución:

1. Obtiene la IP pública con un pedido HTTP escrito a mano sobre TCP a `api.ipify.org:80`.
2. Se autentica por UDP contra `167.114.129.206:20262` con un mensaje firmado con MD5.
3. Se conecta por TCP al puerto que asigna el servidor y recibe las PDUs.
4. Delimita cada PDU por `\r\n` (framing), le asigna un código de parseo y la reenvía firmada por UDP.

## Archivos

| Archivo | Descripción |
|---|---|
| `cliente/cliente.c` | Programa principal. |
| `cliente/md5.c`, `cliente/md5.h` | Implementación de MD5 provista por la cátedra. |
| `cliente/Makefile` | Compilación. |
| `desafio1_grupo10_filtrado.pcapng` | Captura del desafío 1 (IP pública y autenticación UDP). |
| `desafio2_grupo10_filtrado.pcapng` | Captura del desafío 2 completo. |
| `TP_D_Redes.pdf` | Informe con el funcionamiento, la ejecución, el análisis de las capturas y las respuestas a las preguntas. |

## Requisitos

- Linux, o Windows con WSL (probado en Ubuntu 20.04 sobre WSL).
- `gcc` y `make`. En Ubuntu/Debian se instalan con:
  ```bash
  sudo apt update && sudo apt install -y build-essential
  ```
- Conexión a Internet que permita:
  - TCP saliente al puerto 80 (`api.ipify.org`);
  - UDP saliente al puerto 20262 y TCP saliente al puerto asignado (`167.114.129.206`).
- Reloj de la PC sincronizado. El código 406 compara el timestamp de cada PDU con la hora local.

## Compilación

El código está en la carpeta `cliente/`:

```bash
cd cliente
make
```

Compila con `gcc -Wall -Wextra` y no genera warnings. Para borrar los archivos generados:

```bash
make clean
```

## Uso

Desde la carpeta `cliente/`:

```bash
./cliente
```

No recibe argumentos. El usuario (`USUARIO`), el secreto (`SECRETO`) y la dirección del servidor (`SERVER_IP`, `SERVER_PORT`) están definidos como constantes al principio de `cliente/cliente.c`. Para usar otras credenciales, hay que cambiarlas ahí y recompilar.

El puerto TCP que asigna el servidor queda abierto solo 10 segundos. El programa se conecta apenas lo recibe, así que no hace falta hacer nada a mano.

### Salida esperada (resumida)

```
IP publica: [186.130.7.170]
Mensaje a enviar: [grupo10|186.130.7.170|<firma>]
Enviado por UDP a 167.114.129.206:20262
Recibido (47 bytes): [200|Port|30056|<firma>]
Firma OK. Puerto asignado: 30056
Conectado por TCP al puerto 30056
PDU: [1795038786&Primer mensaje] -> 200
  UDP -> [grupo10|1795038786&Primer mensaje|200|<firma>]
...
PDU: [17x0000000&Mensaje | invalido] -> 405
  contiene '|', no se envia
...
El servidor cerro la conexion
```

Para cada PDU se imprime el código asignado y el mensaje UDP que se reenvía. Las PDUs que contienen `|` no se reenvían, porque ese carácter es el separador de campos del protocolo.

### Códigos de parseo

| Código | Condición |
|---|---|
| 200 | PDU válida |
| 400 | No tiene el separador `&` |
| 405 | Timestamp vacío o con caracteres que no son dígitos |
| 406 | Timestamp con más de 300 segundos de antigüedad |
| 407 | Timestamp de más de 11 caracteres |
| 408 | Mensaje con caracteres fuera de 0x20–0x7D, o con `&` o `\|` |
| 409 | Mensaje vacío |
| 410 | Mensaje de más de 100 caracteres |

## Problemas comunes

| Síntoma | Causa probable |
|---|---|
| `Timeout: no llego respuesta en 10 segundos` | La red bloquea UDP (pasa en algunas redes institucionales). Probar desde otra red, por ejemplo con datos del celular. |
| `Error 401: Unauthorized` | La IP enviada no coincide con la que ve el servidor (VPN, IPv6) o la firma/secreto es incorrecta. |
| `Error 400: Bad format` | El mensaje de autenticación tiene un formato incorrecto. |
| Muchas PDUs con 406 | El reloj de la PC está desfasado. |
| `getaddrinfo fallo` | No hay DNS o Internet. Probar `ping -c 2 google.com`. |

## Capturas de tráfico

Se tomaron con Wireshark 4.6.9 en la interfaz Wi-Fi (en Windows, que también captura el tráfico de WSL). Para reducir el tráfico no deseado se exportaron solo los paquetes filtrados:

- **Desafío 1:**
  ```
  udp.port == 20262 || (tcp.port == 80 && (ip.addr == 104.26.12.205 || ip.addr == 104.26.13.205))
  ```
  Las IPs 104.26.x.x son las de `api.ipify.org`. Esta captura se tomó desde otra computadora y red, por eso las IPs locales y públicas difieren de las del desafío 2.
- **Desafío 2:**
  ```
  ip.addr == 167.114.129.206
  ```

El análisis paquete por paquete está en `TP_D_Redes.pdf`.
