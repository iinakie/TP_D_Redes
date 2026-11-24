/* =====================================================================
 * cliente.c - TP D grupo10
 * Hace los dos desafíos en una sola ejecución:
 *   1) Pide la IP pública a ipify (TCP + HTTP a mano) y se autentica por UDP
 *      con una firma MD5 -> el server responde con un puerto TCP.
 *   2) Se conecta por TCP a ese puerto, recibe las PDUs, las separa (framing)
 *      buscando \r\n, las valida y las reenvía firmadas por UDP.
 * ===================================================================== */

#include "md5.h"          // ya incluye stdio, stdlib, string y stdint
#include <unistd.h>       // close()
#include <errno.h>        // errno (para saber si recvfrom falló por timeout)
#include <netdb.h>        // getaddrinfo() (DNS)
#include <sys/socket.h>   // socket, send, recv, sendto, recvfrom
#include <netinet/in.h>   // struct sockaddr_in (dirección IPv4 + puerto)
#include <arpa/inet.h>    // htons, inet_pton
#include <sys/time.h>     // struct timeval (para el timeout)
#include <time.h>         // time() para comparar timestamps

/* Datos que nos dio la cátedra por mail.
   El SECRETO solo se usa para calcular firmas: nunca se manda por la red. */
#define USUARIO     "grupo10"
#define SECRETO     "bPjlHDa8"
#define SERVER_IP   "167.114.129.206"
#define SERVER_PORT 20262          /* puerto UDP fijo del server */

/* ---------------------------------------------------------------------
 * md5_hex: calcula el MD5 de 'texto' y lo deja en 'salida' como
 * 32 caracteres hexadecimales en minúscula (el formato que pide la consigna).
 * --------------------------------------------------------------------- */
static void md5_hex(const char *texto, char salida[33]) {
    uint8_t digest[16];                 /* MD5 da 16 bytes (128 bits) */
    md5((const uint8_t *)texto, strlen(texto), digest);
    for (int i = 0; i < 16; i++)
        sprintf(salida + i * 2, "%02x", digest[i]);  /* cada byte -> 2 caracteres hex */
    salida[32] = '\0';                  /* 16 bytes x 2 = 32 caracteres + fin de string */
}

/* ---------------------------------------------------------------------
 * skip_single (de la cátedra): corta el texto en el primer delimitador.
 * Devuelve la palabra y deja *buf apuntando justo después del delimitador,
 * así llamándola varias veces se sacan los campos uno por uno.
 * Ejemplo: "200|Port|30056|abc" -> "200", después "Port", etc.
 * --------------------------------------------------------------------- */
static char *skip_single(char **buf, const char *delimiters)
{
  char *p, *begin_word, *end_word, *end_delimiters;

  begin_word = *buf;
  end_word = begin_word + strcspn(begin_word, delimiters); /* busca el primer '|' */
  end_delimiters = end_word + 1;
  for (p = end_word; p < end_delimiters; p++) {
    *p = '\0';                          /* reemplaza el '|' por fin de string */
  }
  *buf = end_delimiters;                /* el próximo campo arranca después del '|' */
  return begin_word;
}

/* ---------------------------------------------------------------------
 * obtener_ip_publica: le pregunta a api.ipify.org nuestra IP pública
 * con un pedido HTTP escrito a mano sobre TCP (prohibido usar libcurl).
 * Hace falta porque por el NAT nuestra PC solo conoce su IP privada,
 * y el server valida la firma con la IP pública (la que ve).
 * Devuelve 0 si salió bien, -1 si hubo error.
 * --------------------------------------------------------------------- */
static int obtener_ip_publica(char *ip, size_t ip_len) {
    /* 1) DNS: traducir el nombre api.ipify.org a una dirección IP */
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof hints);
    hints.ai_family   = AF_INET;      /* forzar IPv4: si fuera IPv6, ipify nos daría
                                         una IPv6 y el server espera IPv4 (daría 401) */
    hints.ai_socktype = SOCK_STREAM;  /* TCP */
    if (getaddrinfo("api.ipify.org", "80", &hints, &res) != 0) {
        fprintf(stderr, "getaddrinfo fallo\n");
        return -1;
    }

    /* 2) Crear el socket TCP y conectarse al puerto 80 (HTTP).
          connect() hace el three-way handshake. */
    int s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s < 0) { perror("socket"); freeaddrinfo(res); return -1; }
    if (connect(s, res->ai_addr, res->ai_addrlen) < 0) {
        perror("connect"); close(s); freeaddrinfo(res); return -1;
    }
    freeaddrinfo(res);                /* liberar la memoria que reservó getaddrinfo */

    /* 3) Mandar el pedido HTTP: es solo texto.
          La línea vacía final (\r\n\r\n) marca el fin del pedido.
          HTTP/1.0 -> el server cierra la conexión al terminar de responder. */
    const char *pedido = "GET / HTTP/1.0\r\nHost: api.ipify.org\r\n\r\n";
    if (send(s, pedido, strlen(pedido), 0) < 0) {
        perror("send"); close(s); return -1;
    }

    /* 4) Leer TODO hasta que el server cierre la conexión (recv devuelve 0).
          Loop porque TCP es un flujo de bytes: la respuesta puede llegar
          en varios pedazos, cada recv trae lo que llegó hasta ese momento. */
    char resp[4096];
    size_t total = 0;
    ssize_t n;
    while ((n = recv(s, resp + total, sizeof(resp) - 1 - total, 0)) > 0)
        total += (size_t)n;           /* cada pedazo se agrega después del anterior */
    resp[total] = '\0';               /* -1 arriba: dejamos lugar para este \0 */
    close(s);

    /* 5) La respuesta es: headers + línea vacía + cuerpo.
          El cuerpo (la IP) empieza después de "\r\n\r\n". */
    char *cuerpo = strstr(resp, "\r\n\r\n");
    if (cuerpo == NULL) {
        fprintf(stderr, "Respuesta HTTP sin cuerpo:\n%s\n", resp);
        return -1;
    }
    cuerpo += 4;                              /* saltear los 4 caracteres \r\n\r\n */
    cuerpo[strcspn(cuerpo, "\r\n ")] = '\0';  /* cortar saltos de línea/espacios del final */
    snprintf(ip, ip_len, "%s", cuerpo);       /* copiar la IP al resultado */
    return 0;
}

/* ---------------------------------------------------------------------
 * conectar_tcp: se conecta por TCP al puerto dinámico que nos dio el server.
 * Hay que hacerlo enseguida: el server deja ese puerto abierto solo 10 s.
 * Devuelve el socket conectado, o -1 si falla.
 * --------------------------------------------------------------------- */
static int conectar_tcp(int puerto) {
    int t = socket(AF_INET, SOCK_STREAM, 0);   /* SOCK_STREAM = TCP */
    if (t < 0) { perror("socket TCP"); return -1; }

    struct sockaddr_in srv;                    /* dirección del server: IP + puerto */
    memset(&srv, 0, sizeof srv);
    srv.sin_family = AF_INET;                  /* IPv4 */
    srv.sin_port   = htons(puerto);            /* htons: pasa el puerto al orden de
                                                  bytes de la red (big-endian) */
    inet_pton(AF_INET, SERVER_IP, &srv.sin_addr); /* texto "167.114..." -> binario */

    /* connect() dispara el three-way handshake (SYN, SYN-ACK, ACK).
       En la captura: paquetes 398, 405 y 406. Los arma el SO, no nosotros. */
    if (connect(t, (struct sockaddr *)&srv, sizeof srv) < 0) {
        perror("connect TCP"); close(t); return -1;
    }
    return t;
}

/* ---------------------------------------------------------------------
 * buscar_crlf: busca "\r\n" (fin de PDU) en los primeros 'len' bytes de 'buf'.
 * Devuelve la posición del '\r', o -1 si todavía no hay un \r\n completo.
 * Se busca en TODO el buffer acumulado, así funciona aunque el \r y el \n
 * hayan llegado en recv distintos.
 * --------------------------------------------------------------------- */
static long buscar_crlf(const char *buf, size_t len) {
    for (size_t i = 0; i + 1 < len; i++)       /* i+1 < len: para poder mirar buf[i+1] */
        if (buf[i] == '\r' && buf[i + 1] == '\n')
            return (long)i;
    return -1;
}

/* ---------------------------------------------------------------------
 * validar_pdu: recibe una PDU (ya sin el \r\n) y devuelve el código.
 * Formato válido: <TIMESTAMP>&<MESSAGE>
 * Si hay más de un error, devuelve el primero que encuentra en este orden
 * (la consigna no dice cuál va primero).
 * --------------------------------------------------------------------- */
static int validar_pdu(const char *pdu) {
    /* 1) Tiene que haber un '&' separando TIMESTAMP y MESSAGE */
    const char *amp = strchr(pdu, '&');        /* busca el primer '&' */
    if (amp == NULL) return 400;               /* no hay 2 campos -> 400 */

    size_t ts_len = (size_t)(amp - pdu);       /* largo del timestamp = distancia al & */
    const char *msg = amp + 1;                 /* el mensaje empieza después del & */
    size_t msg_len = strlen(msg);

    /* 2) TIMESTAMP: solo dígitos ASCII 0x30-0x39 ('0' a '9') -> si no, 405 */
    if (ts_len == 0) return 405;
    for (size_t i = 0; i < ts_len; i++)
        if (pdu[i] < '0' || pdu[i] > '9') return 405;

    /* 3) TIMESTAMP: máximo 11 caracteres -> si no, 407 */
    if (ts_len > 11) return 407;

    /* 4) TIMESTAMP: no puede tener más de 300 s de antigüedad -> si no, 406.
          Se copia a un string aparte para convertirlo a número.
          long long: 11 dígitos no entran en un int de 32 bits. */
    char ts_str[12];                           /* 11 dígitos + \0 */
    memcpy(ts_str, pdu, ts_len);
    ts_str[ts_len] = '\0';
    long long ts = strtoll(ts_str, NULL, 10);  /* texto -> número */
    if ((long long)time(NULL) - ts > 300) return 406; /* time(NULL) = hora actual */

    /* 5) MESSAGE: solo 0x20-0x7D, excluyendo '&' (0x26) y '|' (0x7C) -> si no, 408.
          unsigned char: así un byte >= 0x80 (ej. UTF-8 del símbolo ⁰) no queda
          negativo y la comparación funciona bien. */
    for (size_t i = 0; i < msg_len; i++) {
        unsigned char c = (unsigned char)msg[i];
        if (c < 0x20 || c > 0x7D || c == 0x26 || c == 0x7C) return 408;
    }

    /* 6) MESSAGE: entre 1 y 100 caracteres -> vacío 409, largo 410 */
    if (msg_len == 0)  return 409;
    if (msg_len > 100) return 410;

    return 200;                                /* pasó todo: PDU válida */
}

/* ---------------------------------------------------------------------
 * enviar_pdu: arma "USUARIO|PDU|CODE|firma" y lo manda por UDP al server
 * (puerto 20262). La firma es md5("USUARIO|PDU|CODE|SECRETO"): el secreto
 * no viaja. Reusa el mismo socket UDP 'u' de la autenticación.
 * El server no responde estos mensajes: si uno se pierde, no nos enteramos.
 * --------------------------------------------------------------------- */
static void enviar_pdu(int u, const struct sockaddr_in *srv,
                       const char *pdu, int code) {
    char a_firmar[1200], firma[33], mensaje[1200];

    /* Lo que se firma (incluye el secreto, no se manda) */
    snprintf(a_firmar, sizeof a_firmar, "%s|%s|%d|%s", USUARIO, pdu, code, SECRETO);
    md5_hex(a_firmar, firma);

    /* Lo que se manda (con la firma en lugar del secreto) */
    snprintf(mensaje, sizeof mensaje, "%s|%s|%d|%s", USUARIO, pdu, code, firma);

    /* sendto: manda un datagrama UDP completo a la dirección 'srv' */
    if (sendto(u, mensaje, strlen(mensaje), 0,
               (const struct sockaddr *)srv, sizeof *srv) < 0)
        perror("sendto PDU");
    else
        printf("  UDP -> [%s]\n", mensaje);
}

/* =====================================================================
 * main: arma todo en orden: IP pública -> autenticación UDP ->
 * conexión TCP -> framing + validación + reenvío.
 * ===================================================================== */
int main(void) {
    /* ========== DESAFÍO 1 ========== */

    /* --- IP pública (ipify) --- */
    char ip[64];
    if (obtener_ip_publica(ip, sizeof ip) != 0) {
        fprintf(stderr, "No pude obtener la IP publica\n");
        return 1;
    }
    printf("IP publica: [%s]\n", ip);

    /* --- Mensaje firmado --- */
    char a_firmar[256], firma[33], mensaje[256];

    /* Lo que se FIRMA: usuario|ip|secreto  (esto nunca se manda) */
    snprintf(a_firmar, sizeof a_firmar, "%s|%s|%s", USUARIO, ip, SECRETO);
    md5_hex(a_firmar, firma);

    /* Lo que se MANDA: usuario|ip|firma  (el secreto NO viaja) */
    snprintf(mensaje, sizeof mensaje, "%s|%s|%s", USUARIO, ip, firma);
    printf("Mensaje a enviar: [%s]\n", mensaje);

        /* --- Enviar por UDP y esperar respuesta --- */

    /* 1) Crear socket UDP (SOCK_DGRAM = datagramas). Este socket 'u' se usa
          para todo lo UDP del programa: autenticación y reenvíos. Por eso
          siempre sale del mismo puerto (el SO se lo asigna en el primer envío). */
    int u = socket(AF_INET, SOCK_DGRAM, 0);
    if (u < 0) { perror("socket UDP"); return 1; }

    /* 2) Cargar la dirección del servidor (IP + puerto 20262) */
    struct sockaddr_in srv;
    memset(&srv, 0, sizeof srv);
    srv.sin_family = AF_INET;
    srv.sin_port   = htons(SERVER_PORT);   /* puerto en network byte order */
    if (inet_pton(AF_INET, SERVER_IP, &srv.sin_addr) != 1) {
        fprintf(stderr, "IP del servidor invalida\n");
        close(u);
        return 1;
    }

    /* 3) Timeout de 10 segundos para recvfrom.
          UDP no garantiza la entrega: si el mensaje o la respuesta se pierden,
          sin timeout recvfrom quedaría bloqueado para siempre. */
    struct timeval tv;
    tv.tv_sec  = 10;
    tv.tv_usec = 0;
    setsockopt(u, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

    /* 4) Mandar el datagrama. UDP no tiene handshake: sale directo.
          En la captura: paquete 381 (Len=54). */
    if (sendto(u, mensaje, strlen(mensaje), 0,
               (struct sockaddr *)&srv, sizeof srv) < 0) {
        perror("sendto");
        close(u);
        return 1;
    }
    printf("Enviado por UDP a %s:%d\n", SERVER_IP, SERVER_PORT);

    /* 5) Esperar la respuesta (paquete 397). Es un loop porque si llega un
          mensaje con firma mala lo descartamos y seguimos esperando. */
    char buf[1024];
    int puerto = -1;                   /* -1 = todavía no tenemos puerto */
    while (1) {
        ssize_t n = recvfrom(u, buf, sizeof(buf) - 1, 0, NULL, NULL);
        if (n < 0) {
            /* EAGAIN/EWOULDBLOCK = venció el timeout de 10 s */
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                printf("Timeout: no llego respuesta en 10 segundos\n");
            else
                perror("recvfrom");
            break;
        }
        buf[n] = '\0';   /* UDP entrega bytes, no strings: el \0 lo ponemos nosotros */
        printf("Recibido (%zd bytes): [%s]\n", n, buf);

            /* --- Parsear y validar la respuesta --- */

        /* a) Tiene que tener exactamente 3 '|' (4 campos); si no, se descarta */
        int barras = 0;
        for (char *p = buf; *p; p++)
            if (*p == '|') barras++;
        if (barras != 3) {
            printf("Formato invalido, descartado\n");
            continue;   /* volver a esperar otro mensaje */
        }

        /* b) Partir en CODE | ACTION | TEXT | SIGNATURE */
        char *cursor = buf;
        char *code   = skip_single(&cursor, "|");
        char *action = skip_single(&cursor, "|");
        char *text   = skip_single(&cursor, "|");
        char *sig    = skip_single(&cursor, "|");

        /* c) Errores 400/401: traen firma de 32 ceros (el server no puede
              firmar si no validó quiénes somos). Se informa y se termina. */
        if (strcmp(code, "400") == 0 || strcmp(code, "401") == 0) {
            printf("Error %s: %s\n", code, text);
            break;
        }

        /* d) 200: verificar que la firma sea md5(code|action|text|secreto).
              Así sabemos que la respuesta es del server real y no fue modificada. */
        if (strcmp(code, "200") == 0 && strcmp(action, "Port") == 0) {
            char a_verificar[256], esperada[33];
            snprintf(a_verificar, sizeof a_verificar, "%s|%s|%s|%s",
                     code, action, text, SECRETO);
            md5_hex(a_verificar, esperada);

            if (strcmp(esperada, sig) == 0) {      /* strcmp == 0 -> son iguales */
                printf("Firma OK. Puerto asignado: %s\n", text);
                puerto = atoi(text);               /* texto "30056" -> número */
                break;
            }
        }

        /* e) Firma mala o mensaje raro: descartar en silencio y seguir esperando
              (la consigna lo pide así; en UDP no hay conexión que cerrar) */
    }
        if (puerto < 0) { close(u); return 1; }   /* no conseguimos puerto: fin */

    /* ========== DESAFÍO 2 ========== */

    /* Conectarse enseguida (el puerto dura 10 s). Ojo: NO cerramos 'u',
       lo reusamos para reenviar las PDUs. */
    int t = conectar_tcp(puerto);
    if (t < 0) { close(u); return 1; }
    printf("Conectado por TCP al puerto %d\n", puerto);

        /* Framing: TCP entrega un flujo de bytes, no mensajes.
       Un recv puede traer media PDU, varias juntas o una mezcla.
       Acumulamos lo recibido en 'acum' y cortamos una PDU en cada \r\n. */
    char acum[1024];   /* bytes recibidos que todavía no forman una PDU completa */
    size_t len = 0;    /* cuántos bytes válidos hay en acum */
    char chunk[512];   /* lo que trae cada recv */
    ssize_t n;

    /* recv devuelve > 0 mientras lleguen datos, y 0 cuando el server cierra
       la conexión (manda FIN, paquete 470). Ahí termina el loop. */
    while ((n = recv(t, chunk, sizeof chunk, 0)) > 0) {
        /* Si no entra, hay basura sin \r\n (mucho más que 122 bytes): se descarta */
        if (len + (size_t)n > sizeof acum) {
            printf("Buffer lleno sin \\r\\n, descarto %zu bytes\n", len);
            len = 0;
        }
        memcpy(acum + len, chunk, (size_t)n);   /* agregar lo nuevo al final */
        len += (size_t)n;

        /* Sacar TODAS las PDUs completas que haya (puede haber 0, 1 o varias).
           Ej. paquete 414: trae 2 PDUs juntas -> este while corre 2 veces. */
        long pos;
        while ((pos = buscar_crlf(acum, len)) >= 0) {
            char pdu[1024];
            memcpy(pdu, acum, (size_t)pos);   /* copiar la PDU sin el \r\n */
            pdu[pos] = '\0';                  /* convertirla en string */
            int code = validar_pdu(pdu);
            printf("PDU: [%s] -> %d\n", pdu, code);

            /* Consigna: solo se envían las PDUs que NO contienen '|' (0x7C),
               porque el '|' es el delimitador del mensaje UDP (no hay byte stuffing) */
            if (strchr(pdu, '|') != NULL)
                printf("  contiene '|', no se envia\n");
            else
                enviar_pdu(u, &srv, pdu, code);

            /* Correr lo que sobra al principio del buffer.
               memmove (y no memcpy) porque origen y destino se superponen. */
            size_t consumido = (size_t)pos + 2;   /* PDU + \r\n */
            memmove(acum, acum + consumido, len - consumido);
            len -= consumido;
        }
        /* Lo que queda en acum es una PDU incompleta (sin \r\n):
           espera al próximo recv. Ej. paquetes 420 y 432. */
    }
    if (n < 0) perror("recv");
    /* El server cerró: si quedaron bytes sin \r\n, esa PDU ya no se va a completar */
    if (len > 0)
        printf("Quedaron %zu bytes sin \\r\\n (PDU incompleta, se descarta)\n", len);
    printf("El servidor cerro la conexion\n");

    close(t);   /* close del TCP -> nuestro FIN (paquete 471) */
    close(u);   /* recién ahora cerramos el UDP: ya no hay más reenvíos */
    return 0;

}