#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// Windows için socket kütüphaneleri
#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
    #define close(s) closesocket(s)
    #define sleep(x) Sleep(x * 1000)
#else
    #include <unistd.h>
    #include <sys/socket.h>
    #include <arpa/inet.h>
    #include <netinet/in.h>
    #include <errno.h>
#endif

// Modbus TCP protokol sabitleri
#define MODBUS_TCP_PORT 8888
#define MODBUS_MAX_READ_REGISTERS 125
#define MODBUS_HEADER_LENGTH 6
#define MODBUS_TCP_HEADER_LENGTH 7

// Drone tespit verisi yapısı
typedef struct {
    unsigned short drone_count;           // Register 0: Aktif drone sayısı
    unsigned short threat_level;          // Register 1: Tehlike seviyesi (0=YOK, 1=DÜŞÜK, 2=ORTA, 3=YÜKSEK)
    unsigned short fire_authorized;       // Register 2: Ateş izni (0=Hayır, 1=Evet)
    unsigned short detection_id;          // Register 3: Tespit ID
    unsigned short confidence;            // Register 4: Güven oranı (0-1000, %10 = 100)
    unsigned short position_x;            // Register 5: X koordinatı (-1000 ile +1000 arası, 0.001 hassasiyet)
    unsigned short position_y;            // Register 6: Y koordinatı (-1000 ile +1000 arası, 0.001 hassasiyet)
    unsigned short zone_code;             // Register 7: Bölge kodu (0=MERKEZ, 1=KUZEY, 2=GÜNEY, 3=DOĞU, 4=BATI, vb.)
    unsigned short timestamp_high;        // Register 8: Unix timestamp üst 16 bit
    unsigned short timestamp_low;         // Register 9: Unix timestamp alt 16 bit
} drone_data_t;

// Modbus TCP başlık yapısı
typedef struct {
    unsigned short transaction_id;
    unsigned short protocol_id;
    unsigned short length;
    unsigned char unit_id;
} modbus_tcp_header_t;

// Modbus fonksiyon kodları
#define MODBUS_FC_READ_HOLDING_REGISTERS 0x03
#define MODBUS_FC_WRITE_SINGLE_REGISTER 0x06

// Hata kodları
#define MODBUS_SUCCESS 0
#define MODBUS_ERROR_CONNECTION -1
#define MODBUS_ERROR_INVALID_RESPONSE -2
#define MODBUS_ERROR_TIMEOUT -3

// Global değişkenler
#ifdef _WIN32
    SOCKET sockfd = INVALID_SOCKET;
#else
    int sockfd = -1;
#endif
unsigned short transaction_id = 1;

// Fonksiyon prototipleri
int modbus_connect(const char* ip_address, int port);
void modbus_disconnect(void);
int modbus_read_holding_registers(unsigned short start_addr, unsigned short num_registers, unsigned short* data);
int modbus_write_single_register(unsigned short address, unsigned short value);
void parse_drone_data(unsigned short* registers, drone_data_t* drone_data);
void print_drone_data(const drone_data_t* data);
const char* get_threat_level_string(unsigned short level);
const char* get_zone_string(unsigned short zone);
void clear_screen(void);
int init_winsock(void);
void cleanup_winsock(void);

int main(int argc, char* argv[]) {
    const char* server_ip = "127.0.0.1";  // Varsayılan server IP
    int server_port = MODBUS_TCP_PORT;
    
    // Windows socket başlatma
    if (init_winsock() != 0) {
        printf("Winsock başlatma hatası!\n");
        return -1;
    }
    
    // Komut satırı argümanlarını kontrol et
    if (argc >= 2) {
        server_ip = argv[1];
    }
    if (argc >= 3) {
        server_port = atoi(argv[2]);
    }
    
    printf("=== DRONE DETECTION MODBUS TCP CLIENT ===\n");
    printf("Server: %s:%d\n", server_ip, server_port);
    printf("========================================\n\n");
    
    // Modbus server'a bağlan
    if (modbus_connect(server_ip, server_port) != MODBUS_SUCCESS) {
        printf("HATA: Modbus server'a baglanamadi!\n");
        cleanup_winsock();
        return -1;
    }
    
    printf("Modbus server'a basariyla baglandi.\n");
    printf("Drone tespit verileri okunuyor...\n\n");
    
    drone_data_t drone_data;
    unsigned short registers[10];  // 10 register okuyacağız
    
    // Ana döngü - sürekli veri oku
    while (1) {
        // Holding register'ları oku (adres 0'dan başlayarak 10 register)
        int result = modbus_read_holding_registers(0, 10, registers);
        
        if (result == MODBUS_SUCCESS) {
            // Okunan verileri drone data yapısına çevir
            parse_drone_data(registers, &drone_data);
            
            // Verileri ekrana yazdır
            clear_screen();
            printf("=== DRONE DETECTION DATA (REAL-TIME) ===\n");
            time_t now = time(NULL);
            printf("Son guncelleme: %s", ctime(&now));
            printf("=========================================\n\n");
            print_drone_data(&drone_data);
            
            // Ateş kontrolü
            if (drone_data.fire_authorized && drone_data.drone_count > 0) {
                printf("\n*** UYARI: ATES IZNI AKTIF! ***\n");
                printf("Hedef drone tespit edildi ve ates etmeye hazir.\n");
            }
            
        } else {
            printf("HATA: Modbus veri okuma hatasi (Kod: %d)\n", result);
            
            // Bağlantı kopmuşsa yeniden bağlan
            if (result == MODBUS_ERROR_CONNECTION) {
                printf("Baglanti koptu, yeniden baglaniliyor...\n");
                modbus_disconnect();
                sleep(2);
                if (modbus_connect(server_ip, server_port) != MODBUS_SUCCESS) {
                    printf("Yeniden baglanti basarisiz!\n");
                    break;
                }
            }
        }
        
        // 1 saniye bekle
        sleep(1);
    }
    
    modbus_disconnect();
    cleanup_winsock();
    printf("Program sonlandirildi.\n");
    return 0;
}

int init_winsock(void) {
#ifdef _WIN32
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        printf("WSAStartup hatasi: %d\n", result);
        return -1;
    }
#endif
    return 0;
}

void cleanup_winsock(void) {
#ifdef _WIN32
    WSACleanup();
#endif
}

void clear_screen(void) {
#ifdef _WIN32
    system("cls");
#else
    system("clear");
#endif
}

int modbus_connect(const char* ip_address, int port) {
    struct sockaddr_in server_addr;
    
    // Socket oluştur
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
#ifdef _WIN32
    if (sockfd == INVALID_SOCKET) {
        printf("Socket olusturma hatasi: %d\n", WSAGetLastError());
        return MODBUS_ERROR_CONNECTION;
    }
#else
    if (sockfd < 0) {
        printf("Socket olusturma hatasi\n");
        return MODBUS_ERROR_CONNECTION;
    }
#endif
    
    // Timeout ayarla
#ifdef _WIN32
    DWORD timeout = 5000;  // 5000 ms = 5 saniye
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));
#else
    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));
#endif
    
    // Server adresi ayarla
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons((unsigned short)port);
    server_addr.sin_addr.s_addr = inet_addr(ip_address);
    
    // Bağlantı kur
    if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
#ifdef _WIN32
        printf("Baglanti hatasi: %d\n", WSAGetLastError());
#else
        printf("Baglanti hatasi\n");
#endif
        close(sockfd);
#ifdef _WIN32
        sockfd = INVALID_SOCKET;
#else
        sockfd = -1;
#endif
        return MODBUS_ERROR_CONNECTION;
    }
    
    return MODBUS_SUCCESS;
}

void modbus_disconnect(void) {
#ifdef _WIN32
    if (sockfd != INVALID_SOCKET) {
        close(sockfd);
        sockfd = INVALID_SOCKET;
    }
#else
    if (sockfd >= 0) {
        close(sockfd);
        sockfd = -1;
    }
#endif
}

int modbus_read_holding_registers(unsigned short start_addr, unsigned short num_registers, unsigned short* data) {
#ifdef _WIN32
    if (sockfd == INVALID_SOCKET) {
        return MODBUS_ERROR_CONNECTION;
    }
#else
    if (sockfd < 0) {
        return MODBUS_ERROR_CONNECTION;
    }
#endif
    
    // Modbus TCP isteği oluştur
    unsigned char request[12];
    unsigned short current_transaction_id = transaction_id++;
    
    // TCP başlığı
    request[0] = (current_transaction_id >> 8) & 0xFF;  // Transaction ID high
    request[1] = current_transaction_id & 0xFF;         // Transaction ID low
    request[2] = 0x00;  // Protocol ID high (Modbus için 0)
    request[3] = 0x00;  // Protocol ID low
    request[4] = 0x00;  // Length high
    request[5] = 0x06;  // Length low (6 byte PDU)
    request[6] = 0xFF;  // Unit ID (255 = broadcast)
    
    // PDU (Protocol Data Unit)
    request[7] = MODBUS_FC_READ_HOLDING_REGISTERS;  // Function code
    request[8] = (start_addr >> 8) & 0xFF;          // Start address high
    request[9] = start_addr & 0xFF;                 // Start address low
    request[10] = (num_registers >> 8) & 0xFF;      // Number of registers high
    request[11] = num_registers & 0xFF;             // Number of registers low
    
    // İsteği gönder
    int sent = send(sockfd, (char*)request, 12, 0);
    if (sent != 12) {
#ifdef _WIN32
        printf("Veri gonderme hatasi: %d\n", WSAGetLastError());
#else
        printf("Veri gonderme hatasi\n");
#endif
        return MODBUS_ERROR_CONNECTION;
    }
    
    // Yanıtı al
    unsigned char response[256];
    int received = recv(sockfd, (char*)response, sizeof(response), 0);
    if (received < 0) {
#ifdef _WIN32
        printf("Veri alma hatasi: %d\n", WSAGetLastError());
#else
        printf("Veri alma hatasi\n");
#endif
        return MODBUS_ERROR_CONNECTION;
    }
    
    // Yanıtı kontrol et
    if (received < 9) {
        printf("Gecersiz yanit uzunlugu: %d\n", received);
        return MODBUS_ERROR_INVALID_RESPONSE;
    }
    
    // Transaction ID kontrolü
    unsigned short response_transaction_id = (response[0] << 8) | response[1];
    if (response_transaction_id != current_transaction_id) {
        printf("Transaction ID uyumsuzlugu\n");
        return MODBUS_ERROR_INVALID_RESPONSE;
    }
    
    // Function code kontrolü
    if (response[7] != MODBUS_FC_READ_HOLDING_REGISTERS) {
        if (response[7] & 0x80) {  // Hata yanıtı
            printf("Modbus hatasi: %02X\n", response[8]);
            return MODBUS_ERROR_INVALID_RESPONSE;
        }
    }
    
    // Veri byte sayısını al
    unsigned char byte_count = response[8];
    if (byte_count != num_registers * 2) {
        printf("Gecersiz byte sayisi: %d\n", byte_count);
        return MODBUS_ERROR_INVALID_RESPONSE;
    }
    
    // Register verilerini çıkar
    int i;
    for (i = 0; i < num_registers; i++) {
        data[i] = (response[9 + i * 2] << 8) | response[10 + i * 2];
    }
    
    return MODBUS_SUCCESS;
}

int modbus_write_single_register(unsigned short address, unsigned short value) {
#ifdef _WIN32
    if (sockfd == INVALID_SOCKET) {
        return MODBUS_ERROR_CONNECTION;
    }
#else
    if (sockfd < 0) {
        return MODBUS_ERROR_CONNECTION;
    }
#endif
    
    // Modbus TCP yazma isteği oluştur
    unsigned char request[12];
    unsigned short current_transaction_id = transaction_id++;
    
    // TCP başlığı
    request[0] = (current_transaction_id >> 8) & 0xFF;
    request[1] = current_transaction_id & 0xFF;
    request[2] = 0x00;  // Protocol ID high
    request[3] = 0x00;  // Protocol ID low
    request[4] = 0x00;  // Length high
    request[5] = 0x06;  // Length low
    request[6] = 0xFF;  // Unit ID
    
    // PDU
    request[7] = MODBUS_FC_WRITE_SINGLE_REGISTER;  // Function code
    request[8] = (address >> 8) & 0xFF;            // Register address high
    request[9] = address & 0xFF;                   // Register address low
    request[10] = (value >> 8) & 0xFF;             // Register value high
    request[11] = value & 0xFF;                    // Register value low
    
    // İsteği gönder
    int sent = send(sockfd, (char*)request, 12, 0);
    if (sent != 12) {
        return MODBUS_ERROR_CONNECTION;
    }
    
    // Yanıtı al ve kontrol et (basitleştirilmiş)
    unsigned char response[12];
    int received = recv(sockfd, (char*)response, sizeof(response), 0);
    if (received < 12) {
        return MODBUS_ERROR_INVALID_RESPONSE;
    }
    
    return MODBUS_SUCCESS;
}

void parse_drone_data(unsigned short* registers, drone_data_t* drone_data) {
    drone_data->drone_count = registers[0];
    drone_data->threat_level = registers[1];
    drone_data->fire_authorized = registers[2];
    drone_data->detection_id = registers[3];
    drone_data->confidence = registers[4];
    drone_data->position_x = registers[5];
    drone_data->position_y = registers[6];
    drone_data->zone_code = registers[7];
    drone_data->timestamp_high = registers[8];
    drone_data->timestamp_low = registers[9];
}

void print_drone_data(const drone_data_t* data) {
    printf("DRONE TESPIT SISTEMI\n");
    printf("========================\n");
    printf("Aktif Drone Sayisi    : %d\n", data->drone_count);
    printf("Tehlike Seviyesi      : %s (%d)\n", get_threat_level_string(data->threat_level), data->threat_level);
    printf("Ates Izni             : %s\n", data->fire_authorized ? "AKTIF" : "PASIF");
    printf("\n");
    
    if (data->drone_count > 0) {
        printf("DRONE DETAYLARI\n");
        printf("===================\n");
        printf("Tespit ID             : D%03d\n", data->detection_id);
        printf("Guven Orani           : %.1f%%\n", data->confidence / 10.0);
        printf("X Koordinati          : %.3f\n", (short)data->position_x / 1000.0);
        printf("Y Koordinati          : %.3f\n", (short)data->position_y / 1000.0);
        printf("Bolge                 : %s (%d)\n", get_zone_string(data->zone_code), data->zone_code);
        
        // Timestamp
        unsigned long timestamp = ((unsigned long)data->timestamp_high << 16) | data->timestamp_low;
        if (timestamp > 0) {
            time_t ts = (time_t)timestamp;
            printf("Tespit Zamani         : %s", ctime(&ts));
        }
    } else {
        printf("HIC DRONE TESPIT EDILMEDI\n");
    }
    
    printf("\n========================\n");
}

const char* get_threat_level_string(unsigned short level) {
    switch (level) {
        case 0: return "YOK";
        case 1: return "DUSUK";
        case 2: return "ORTA SEVIYE";
        case 3: return "YUKSEK TEHLIKE";
        default: return "BILINMEYEN";
    }
}

const char* get_zone_string(unsigned short zone) {
    switch (zone) {
        case 0: return "MERKEZ";
        case 1: return "KUZEY";
        case 2: return "GUNEY";
        case 3: return "DOGU";
        case 4: return "BATI";
        case 5: return "KUZEYDOGU";
        case 6: return "KUZEYBATI";
        case 7: return "GUNEYDOGU";
        case 8: return "GUNEYBATI";
        default: return "BILINMEYEN";
    }
}
