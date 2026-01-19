#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdint.h>
#include <fcntl.h>
#include <errno.h>
#include <endian.h>

#include "ed25519.h"

#define KEY_DIR     "/etc/wifi-secure"
#define KEY_PATH    KEY_DIR "/ed25519.key"
#define PUBKEY_PATH KEY_DIR "/ed25519.pub"

#define OUI0 0x00
#define OUI1 0x11
#define OUI2 0x22
#define VSIE_TYPE 0x01

#define VSIE_LEN (4 + 32 + 8 + 64)

static void die(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

static void secure_bzero(void *p, size_t n) {
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n--) *v++ = 0;
}

static int file_exists(const char *path) {
    return access(path, F_OK) == 0;
}

static void get_random(uint8_t *buf, size_t len) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) die("open urandom");
    ssize_t r = read(fd, buf, len);
    close(fd);
    if (r != (ssize_t)len) die("read urandom");
}

static void generate_keypair(void) {
    uint8_t pub[32];
    uint8_t priv[64];
    uint8_t seed[32];

    get_random(seed, sizeof(seed));
    ed25519_create_keypair(pub, priv, seed);

    FILE *f = fopen(KEY_PATH, "wb");
    if (!f) die("fopen priv");
    if (fwrite(priv, 1, sizeof(priv), f) != sizeof(priv))
        die("write priv");
    fclose(f);
    chmod(KEY_PATH, 0600);

    f = fopen(PUBKEY_PATH, "wb");
    if (!f) die("fopen pub");
    if (fwrite(pub, 1, sizeof(pub), f) != sizeof(pub))
        die("write pub");
    fclose(f);

    secure_bzero(priv, sizeof(priv));
    secure_bzero(seed, sizeof(seed));

    fprintf(stderr, "[+] Ed25519 keypair generated\n");
}

static int parse_mac(const char *str, uint8_t mac[6]) {
    return sscanf(str,
        "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
        &mac[0], &mac[1], &mac[2],
        &mac[3], &mac[4], &mac[5]) == 6;
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <ssid> <mac> <iface>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *ssid = argv[1];
    const char *mac_str = argv[2];
    (void)argv[3]; // iface зарезервирован на будущее

    size_t ssid_len = strlen(ssid);
    if (ssid_len == 0 || ssid_len > 32)
        die("invalid SSID length");

    uint8_t mac[6];
    if (!parse_mac(mac_str, mac))
        die("invalid MAC format");

    if (!file_exists(KEY_DIR)) {
        if (mkdir(KEY_DIR, 0700) < 0 && errno != EEXIST)
            die("mkdir");
    }

    if (!file_exists(KEY_PATH) || !file_exists(PUBKEY_PATH)) {
        generate_keypair();
    }

    /* Load private key */
    uint8_t priv[64];
    FILE *f = fopen(KEY_PATH, "rb");
    if (!f) die("open privkey");
    if (fread(priv, 1, sizeof(priv), f) != sizeof(priv))
        die("read privkey");
    fclose(f);

    /* Load public key */
    uint8_t pub[32];
    f = fopen(PUBKEY_PATH, "rb");
    if (!f) die("open pubkey");
    if (fread(pub, 1, sizeof(pub), f) != sizeof(pub))
        die("read pubkey");
    fclose(f);

    /* Timestamp */
    uint64_t ts = htobe64((uint64_t)time(NULL));

    /* Build signing buffer */
    size_t sign_len = ssid_len + sizeof(mac) + sizeof(ts);
    uint8_t *sign_buf = malloc(sign_len);
    if (!sign_buf) die("malloc");

    size_t off = 0;
    memcpy(sign_buf + off, ssid, ssid_len); off += ssid_len;
    memcpy(sign_buf + off, mac, sizeof(mac)); off += sizeof(mac);
    memcpy(sign_buf + off, &ts, sizeof(ts));

    /* Sign */
    // Объявляем буфер для хранения цифровой подписи.
    uint8_t sig[64];

    // Выполняем криптографическую подпись данных:
    // - sig: буфер, куда будет записана результирующая подпись;
    // - sign_buf: указатель на данные, которые нужно подписать;
    // - sign_len: длина этих данных в байтах;
    // - pub: публичный ключ;
    // - priv: секретный ключ.
    ed25519_sign(sig, sign_buf, sign_len, pub, priv);

    // Очищаем секретный ключ из памяти после использования. 
    // Это предотвращает утечку ключа через дамп памяти, своп или атаки по сторонним каналам.
    secure_bzero(priv, sizeof(priv));

    // Аналогично очищаем буфер с подписываемыми данными.
    secure_bzero(sign_buf, sign_len);

    // Освобождаем динамически выделенную память под буфер данных.
    free(sign_buf);

    /* Build VSIE */
    uint8_t vsie[VSIE_LEN];
    vsie[0] = OUI0;
    vsie[1] = OUI1;
    vsie[2] = OUI2;
    vsie[3] = VSIE_TYPE;

    memcpy(vsie + 4,  pub, 32);
    memcpy(vsie + 36, &ts, 8);
    memcpy(vsie + 44, sig, 64);

    /* Output hex */
    for (size_t i = 0; i < VSIE_LEN; i++)
        printf("%02x", vsie[i]);
    printf("\n");

    return EXIT_SUCCESS;
}
