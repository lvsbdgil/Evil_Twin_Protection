#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <time.h>
#include <errno.h>

#include <sodium.h>

#define KEY_DIR     "/etc/wifi-secure"
#define KEY_PATH    "/etc/wifi-secure/ed25519.key"
#define PUBKEY_PATH "/etc/wifi-secure/ed25519.pub"

#define VSIE_LEN (4 + crypto_sign_PUBLICKEYBYTES + 8 + crypto_sign_BYTES)

/* ------------------------------------------------ */

static void die(const char *msg) {
    perror(msg);
    exit(1);
}

static int file_exists(const char *path) {
    return access(path, F_OK) == 0;
}

static void get_random(uint8_t *buf, size_t len) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) die("open urandom");
    if (read(fd, buf, len) != (ssize_t)len) die("read urandom");
    close(fd);
}

/* ------------------------------------------------ */
/* Key generation                                   */
/* ------------------------------------------------ */

static void generate_keypair(void) {
    uint8_t seed[crypto_sign_SEEDBYTES];
    uint8_t pub[crypto_sign_PUBLICKEYBYTES];
    uint8_t priv[crypto_sign_SECRETKEYBYTES];

    get_random(seed, sizeof(seed));

    if (crypto_sign_seed_keypair(pub, priv, seed) != 0) {
        fprintf(stderr, "keypair generation failed\n");
        exit(1);
    }

    if (mkdir(KEY_DIR, 0700) < 0 && errno != EEXIST)
        die("mkdir");

    FILE *f = fopen(KEY_PATH, "wb");
    if (!f) die("fopen priv");
    fwrite(priv, 1, sizeof(priv), f);
    fclose(f);
    chmod(KEY_PATH, 0600);

    f = fopen(PUBKEY_PATH, "wb");
    if (!f) die("fopen pub");
    fwrite(pub, 1, sizeof(pub), f);
    fclose(f);

    sodium_memzero(seed, sizeof(seed));
    sodium_memzero(priv, sizeof(priv));

    fprintf(stderr, "[+] Ed25519 keys generated\n");
}

/* ------------------------------------------------ */
/* Main                                             */
/* ------------------------------------------------ */

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <ssid> <mac> <iface>\n", argv[0]);
        return 1;
    }

    const char *ssid = argv[1];
    const char *mac  = argv[2];

    if (sodium_init() < 0) {
        fprintf(stderr, "libsodium init failed\n");
        return 1;
    }

    if (!file_exists(KEY_PATH) || !file_exists(PUBKEY_PATH)) {
        generate_keypair();
    }

    /* Load keys */
    uint8_t pub[crypto_sign_PUBLICKEYBYTES];
    uint8_t priv[crypto_sign_SECRETKEYBYTES];

    FILE *f = fopen(KEY_PATH, "rb");
    if (!f) die("open priv");
    fread(priv, 1, sizeof(priv), f);
    fclose(f);

    f = fopen(PUBKEY_PATH, "rb");
    if (!f) die("open pub");
    fread(pub, 1, sizeof(pub), f);
    fclose(f);

    /* Build message to sign */
    uint64_t ts = (uint64_t)time(NULL);
    size_t ssid_len = strlen(ssid);
    size_t mac_len  = strlen(mac);

    size_t msg_len = ssid_len + mac_len + sizeof(ts);
    uint8_t *msg = malloc(msg_len);
    if (!msg) die("malloc");

    memcpy(msg, ssid, ssid_len);
    memcpy(msg + ssid_len, mac, mac_len);
    memcpy(msg + ssid_len + mac_len, &ts, sizeof(ts));

    /* Sign */
    uint8_t sig[crypto_sign_BYTES];
    unsigned long long siglen;

    if (crypto_sign_detached(sig, &siglen, msg, msg_len, priv) != 0) {
        fprintf(stderr, "sign failed\n");
        return 1;
    }

    free(msg);
    sodium_memzero(priv, sizeof(priv));

    /* Build VSIE */
    uint8_t vsie[VSIE_LEN];

    vsie[0] = 0x00;   /* OUI */
    vsie[1] = 0x11;
    vsie[2] = 0x22;
    vsie[3] = 0x01;   /* Type */

    memcpy(vsie + 4, pub, crypto_sign_PUBLICKEYBYTES);
    memcpy(vsie + 4 + crypto_sign_PUBLICKEYBYTES, &ts, sizeof(ts));
    memcpy(vsie + 4 + crypto_sign_PUBLICKEYBYTES + sizeof(ts),
           sig, crypto_sign_BYTES);

    /* Output hex */
    for (size_t i = 0; i < sizeof(vsie); i++)
        printf("%02x", vsie[i]);
    printf("\n");

    return 0;
}
