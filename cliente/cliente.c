#include "md5.h"          // ya incluye stdio, stdlib, string y stdint
#include <unistd.h>       // close()
#include <errno.h>        // errno
#include <netdb.h>        // getaddrinfo()
#include <sys/socket.h>   // socket, send, recv, sendto, recvfrom
#include <netinet/in.h>   // struct sockaddr_in
#include <arpa/inet.h>    // htons, inet_pton
#include <sys/time.h>     // struct timeval
#include <time.h>         // time() para comparar timestamps

#define USUARIO     "grupo10"
#define SECRETO     "bPjlHDa8"
#define SERVER_IP   "167.114.129.206"
#define SERVER_PORT 20262

/* Calcula el MD5 de 'texto' y lo deja en 'salida' como 32 caracteres hex en minuscula */
static void md5_hex(const char *texto, char salida[33]) {
    uint8_t digest[16];
    md5((const uint8_t *)texto, strlen(texto), digest);
    for (int i = 0; i < 16; i++)
        sprintf(salida + i * 2, "%02x", digest[i]);
    salida[32] = '\0';
}

/* De la catedra (test_skip_single.c): corta *buf en el primer delimitador,
   devuelve la palabra y deja *buf apuntando justo despues del delimitador */
static char *skip_single(char **buf, const char *delimiters)
{
  char *p, *begin_word, *end_word, *end_delimiters;

  begin_word = *buf;
  end_word = begin_word + strcspn(begin_word, delimiters);
  end_delimiters = end_word + 1;
  for (p = end_word; p < end_delimiters; p++) {
    *p = '\0';
  }
  *buf = end_delimiters;
  return begin_word;
}

/* Obtiene la IP publica preguntandole a api.ipify.org por HTTP (TCP a mano).
   Devuelve 0 si salio bien, -1 si hubo error. */
static int obtener_ip_publica(char *ip, size_t ip_len) {
    /* 1) Resolver el nombre api.ipify.org -> direccion IP (forzando IPv4) */
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof hints);
    hints.ai_family   = AF_INET;      /* IPv4: si usas IPv6 el server te da 401 */
    hints.ai_socktype = SOCK_STREAM;  /* TCP */
    if (getaddrinfo("api.ipify.org", "80", &hints, &res) != 0) {
        fprintf(stderr, "getaddrinfo fallo\n");
        return -1;
    }

    /* 2) Crear el socket TCP y conectarse al puerto 80 */
    int s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s < 0) { perror("socket"); freeaddrinfo(res); return -1; }
    if (connect(s, res->ai_addr, res->ai_addrlen) < 0) {
        perror("connect"); close(s); freeaddrinfo(res); return -1;
    }
    freeaddrinfo(res);

    /* 3) Mandar el pedido HTTP escrito a mano */
    const char *pedido = "GET / HTTP/1.0\r\nHost: api.ipify.org\r\n\r\n";
    if (send(s, pedido, strlen(pedido), 0) < 0) {
        perror("send"); close(s); return -1;
    }

    /* 4) Leer TODO hasta que el servidor cierre la conexion (recv devuelve 0) */
    char resp[4096];
    size_t total = 0;
    ssize_t n;
    while ((n = recv(s, resp + total, sizeof(resp) - 1 - total, 0)) > 0)
        total += (size_t)n;
    resp[total] = '\0';
    close(s);

    /* 5) El cuerpo (la IP) empieza despues de la linea vacia "\r\n\r\n" */
    char *cuerpo = strstr(resp, "\r\n\r\n");
    if (cuerpo == NULL) {
        fprintf(stderr, "Respuesta HTTP sin cuerpo:\n%s\n", resp);
        return -1;
    }
    cuerpo += 4;                              /* saltear los 4 caracteres \r\n\r\n */
    cuerpo[strcspn(cuerpo, "\r\n ")] = '\0';  /* cortar basura al final */
    snprintf(ip, ip_len, "%s", cuerpo);
    return 0;
}


/* Se conecta por TCP al server en 'puerto'. Devuelve el socket o -1. */
static int conectar_tcp(int puerto) {
    int t = socket(AF_INET, SOCK_STREAM, 0);   /* SOCK_STREAM = TCP */
    if (t < 0) { perror("socket TCP"); return -1; }

    struct sockaddr_in srv;
    memset(&srv, 0, sizeof srv);
    srv.sin_family = AF_INET;
    srv.sin_port   = htons(puerto);
    inet_pton(AF_INET, SERVER_IP, &srv.sin_addr);

    /* connect() dispara el three-way handshake (SYN, SYN-ACK, ACK) */
    if (connect(t, (struct sockaddr *)&srv, sizeof srv) < 0) {
        perror("connect TCP"); close(t); return -1;
    }
    return t;
}

/* Busca "\r\n" en los primeros 'len' bytes de 'buf'.
   Devuelve la posicion del '\r', o -1 si todavia no hay un CRLF completo. */
static long buscar_crlf(const char *buf, size_t len) {
    for (size_t i = 0; i + 1 < len; i++)
        if (buf[i] == '\r' && buf[i + 1] == '\n')
            return (long)i;
    return -1;
}

/* Valida una PDU (ya sin el \r\n) y devuelve el PARSE_CODE segun la consigna */
static int validar_pdu(const char *pdu) {
    /* 1) Tiene que haber un '&' separando TIMESTAMP y MESSAGE */
    const char *amp = strchr(pdu, '&');
    if (amp == NULL) return 400;               /* no hay 2 campos */

    size_t ts_len = (size_t)(amp - pdu);       /* largo del timestamp */
    const char *msg = amp + 1;                 /* el mensaje empieza despues del & */
    size_t msg_len = strlen(msg);

    /* 2) TIMESTAMP: solo digitos ASCII 0x30-0x39 */
    if (ts_len == 0) return 405;
    for (size_t i = 0; i < ts_len; i++)
        if (pdu[i] < '0' || pdu[i] > '9') return 405;

    /* 3) TIMESTAMP: maximo 11 caracteres */
    if (ts_len > 11) return 407;

    /* 4) TIMESTAMP: no puede tener mas de 300 s de antiguedad */
    char ts_str[12];
    memcpy(ts_str, pdu, ts_len);
    ts_str[ts_len] = '\0';
    long long ts = strtoll(ts_str, NULL, 10);
    if ((long long)time(NULL) - ts > 300) return 406;

    /* 5) MESSAGE: solo 0x20-0x7D, excluyendo '&' (0x26) y '|' (0x7C).
          unsigned char: asi un byte >= 0x80 (ej. UTF-8 del simbolo ⁰) no queda negativo */
    for (size_t i = 0; i < msg_len; i++) {
        unsigned char c = (unsigned char)msg[i];
        if (c < 0x20 || c > 0x7D || c == 0x26 || c == 0x7C) return 408;
    }

    /* 6) MESSAGE: entre 1 y 100 caracteres */
    if (msg_len == 0)  return 409;
    if (msg_len > 100) return 410;

    return 200;
}

/* Arma "USUARIO|PDU|CODE|firma" y lo manda por UDP al server.
   La firma es md5("USUARIO|PDU|CODE|SECRETO"): el secreto no viaja. */
static void enviar_pdu(int u, const struct sockaddr_in *srv,
                       const char *pdu, int code) {
    char a_firmar[1200], firma[33], mensaje[1200];

    snprintf(a_firmar, sizeof a_firmar, "%s|%s|%d|%s", USUARIO, pdu, code, SECRETO);
    md5_hex(a_firmar, firma);

    snprintf(mensaje, sizeof mensaje, "%s|%s|%d|%s", USUARIO, pdu, code, firma);

    if (sendto(u, mensaje, strlen(mensaje), 0,
               (const struct sockaddr *)srv, sizeof *srv) < 0)
        perror("sendto PDU");
    else
        printf("  UDP -> [%s]\n", mensaje);
}

int main(void) {
    /* --- Paso 4: IP publica --- */
    char ip[64];
    if (obtener_ip_publica(ip, sizeof ip) != 0) {
        fprintf(stderr, "No pude obtener la IP publica\n");
        return 1;
    }
    printf("IP publica: [%s]\n", ip);

    /* --- Paso 5: mensaje firmado --- */
    char a_firmar[256], firma[33], mensaje[256];

    /* Lo que se FIRMA: usuario|ip|secreto  (esto nunca se manda) */
    snprintf(a_firmar, sizeof a_firmar, "%s|%s|%s", USUARIO, ip, SECRETO);
    md5_hex(a_firmar, firma);

    /* Lo que se MANDA: usuario|ip|firma  (el secreto NO viaja) */
    snprintf(mensaje, sizeof mensaje, "%s|%s|%s", USUARIO, ip, firma);
    printf("Mensaje a enviar: [%s]\n", mensaje);

        /* --- Paso 6: enviar por UDP y esperar respuesta --- */

    /* 1) Crear socket UDP (SOCK_DGRAM = datagramas) */
    int u = socket(AF_INET, SOCK_DGRAM, 0);
    if (u < 0) { perror("socket UDP"); return 1; }

    /* 2) Cargar la direccion del servidor */
    struct sockaddr_in srv;
    memset(&srv, 0, sizeof srv);
    srv.sin_family = AF_INET;
    srv.sin_port   = htons(SERVER_PORT);   /* puerto en network byte order */
    if (inet_pton(AF_INET, SERVER_IP, &srv.sin_addr) != 1) {
        fprintf(stderr, "IP del servidor invalida\n");
        close(u);
        return 1;
    }

    /* 3) Timeout de 10 segundos para recvfrom */
    struct timeval tv;
    tv.tv_sec  = 10;
    tv.tv_usec = 0;
    setsockopt(u, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

    /* 4) Mandar el datagrama (sin \n, solo los bytes del mensaje) */
    if (sendto(u, mensaje, strlen(mensaje), 0,
               (struct sockaddr *)&srv, sizeof srv) < 0) {
        perror("sendto");
        close(u);
        return 1;
    }
    printf("Enviado por UDP a %s:%d\n", SERVER_IP, SERVER_PORT);

    /* 5) Esperar la respuesta */
    char buf[1024];
    int puerto = -1;
    while (1) {
        ssize_t n = recvfrom(u, buf, sizeof(buf) - 1, 0, NULL, NULL);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                printf("Timeout: no llego respuesta en 10 segundos\n");
            else
                perror("recvfrom");
            break;
        }
        buf[n] = '\0';   /* UDP entrega bytes, no strings: el \0 lo ponemos nosotros */
        printf("Recibido (%zd bytes): [%s]\n", n, buf);

            /* --- Paso 7: parsear y validar --- */

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

        /* c) Errores 400/401: traen firma de ceros, se informa y se termina */
        if (strcmp(code, "400") == 0 || strcmp(code, "401") == 0) {
            printf("Error %s: %s\n", code, text);
            break;
        }

        /* d) 200: verificar firma = md5(code|action|text|secreto) */
        if (strcmp(code, "200") == 0 && strcmp(action, "Port") == 0) {
            char a_verificar[256], esperada[33];
            snprintf(a_verificar, sizeof a_verificar, "%s|%s|%s|%s",
                     code, action, text, SECRETO);
            md5_hex(a_verificar, esperada);

            if (strcmp(esperada, sig) == 0) {
                printf("Firma OK. Puerto asignado: %s\n", text);
                puerto = atoi(text);
                break;
            }
        }

        /* e) Firma mala o mensaje raro: descartar en silencio y seguir esperando */
    }
        if (puerto < 0) { close(u); return 1; }

    int t = conectar_tcp(puerto);
    if (t < 0) { close(u); return 1; }
    printf("Conectado por TCP al puerto %d\n", puerto);

    /* Por ahora solo mostramos cada recv crudo, con \r y \n visibles */
        /* Framing: TCP entrega un flujo de bytes, no mensajes.
       Acumulamos lo recibido y cortamos una PDU en cada \r\n. */
    char acum[1024];   /* bytes recibidos que todavia no forman una PDU completa */
    size_t len = 0;    /* cuantos bytes validos hay en acum */
    char chunk[512];
    ssize_t n;

    while ((n = recv(t, chunk, sizeof chunk, 0)) > 0) {
        /* Si no entra, hay basura sin \r\n (mucho mas que 122 bytes): se descarta */
        if (len + (size_t)n > sizeof acum) {
            printf("Buffer lleno sin \\r\\n, descarto %zu bytes\n", len);
            len = 0;
        }
        memcpy(acum + len, chunk, (size_t)n);   /* agregar al final */
        len += (size_t)n;

        /* Sacar TODAS las PDUs completas que haya (puede haber 0, 1 o varias) */
        long pos;
        while ((pos = buscar_crlf(acum, len)) >= 0) {
            char pdu[1024];
            memcpy(pdu, acum, (size_t)pos);   /* la PDU sin el \r\n */
            pdu[pos] = '\0';
            int code = validar_pdu(pdu);
            printf("PDU: [%s] -> %d\n", pdu, code);

            /* Consigna: solo se envian las PDUs que NO contienen '|' (0x7C),
               porque el '|' es el delimitador del mensaje UDP (no hay byte stuffing) */
            if (strchr(pdu, '|') != NULL)
                printf("  contiene '|', no se envia\n");
            else
                enviar_pdu(u, &srv, pdu, code);
                
            /* Correr lo que sobra al principio del buffer */
            size_t consumido = (size_t)pos + 2;   /* PDU + \r\n */
            memmove(acum, acum + consumido, len - consumido);
            len -= consumido;
        }
        /* Lo que queda en acum es una PDU incompleta: espera al proximo recv */
    }
    if (n < 0) perror("recv");
    if (len > 0)
        printf("Quedaron %zu bytes sin \\r\\n (PDU incompleta, se descarta)\n", len);
    printf("El servidor cerro la conexion\n");

    close(t);
    close(u);   /* el UDP lo vamos a reusar en el paso siguiente */
    return 0;

}