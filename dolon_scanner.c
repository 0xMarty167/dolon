/*

oooooooooo.             oooo                        
`888'   `Y8b            `888                        
 888      888  .ooooo.   888   .ooooo.  ooo. .oo.   
 888      888 d88' `88b  888  d88' `88b `888P"Y88b  
 888      888 888   888  888  888   888  888   888  
 888     d88' 888   888  888  888   888  888   888  
o888bood8P'   `Y8bod8P' o888o `Y8bod8P' o888o o888o 

Basic portscanner by (c) Marty167, 2023 MIT License

Dolon was my very first project in C, created during my early days of learning programming.
It's a simple yet functional port scanner, built with a beginner's curiosity and determination. 
While it's not perfect, it represents my first steps into understanding networking and multi-threading in C.

*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <semaphore.h>
#include <stdbool.h>

// Maximum number of concurrent threads
#define MAX_THREADS 50

// Structure to hold arguments for each thread
typedef struct {
    int port;                    // Port number to scan
    char *ip_address;            // Target IP address
    sem_t *thread_semaphore;     // Semaphore to control thread concurrency
    bool *open_ports;            // Array to keep track of open ports
} ThreadArgs;

// Function Prototypes
int set_socket_non_blocking(int sockfd);
int check_port_status(int sockfd, struct sockaddr_in target);
void *port_scan(void *arguments);
void scan_target(char target_ip[]);
int is_host_up(const char ip_address[]);
void guess_operating_system(bool open_ports[]);
const char* port_to_service(int port);

/**
 * @brief Entry point of the Dolon port scanner.
 * 
 * Displays a banner, prompts the user for options and target IP, and initiates scanning.
 */
int main() {
    // Display the banner
    printf("oooooooooo.             oooo                        \n");
    printf("`888'   `Y8b            `888                        \n");
    printf(" 888      888  .ooooo.   888   .ooooo.  ooo. .oo.   \n");
    printf(" 888      888 d88' `88b  888  d88' `88b `888P\"Y88b  \n");
    printf(" 888      888 888   888  888  888   888  888   888  \n");
    printf(" 888     d88' 888   888  888  888   888  888   888  \n");
    printf("o888bood8P'   `Y8bod8P' o888o `Y8bod8P' o888o o888o \n");
    
    char target_ip[16]; // Buffer to store the target IP address

    // Welcome message and option selection
    printf("\nWelcome to Dolon port scanner. \n");
    printf("What do you want to do?\n");
    printf("\t1) ping scan\n");
    printf("\t2) ports scan\n");

    int option;
    printf("Option number: ");
    scanf("%d", &option);

    // Validate user input for option
    while(option != 1 && option !=2){
        printf("Not a valid option, try again: ");
        scanf("%1d", &option);
    }

    // Prompt user for the target IP address
    printf("Enter target IP address: ");
    scanf("%15s", target_ip); // Read IP address from user with buffer limit

    // Initialize the report file
    FILE *report = fopen("scan.txt", "w");
    if (!report) {
        perror("Failed to open report file");
        exit(EXIT_FAILURE);
    }
    fprintf(report,"*Dolon scan*\n");
    fprintf(report,"Report for: %s \n-------------------\n", target_ip);
    fclose(report);

    // Perform a ping scan if option 1 is selected
    if(option == 1){
        if(is_host_up(target_ip)){
            printf("Host is up\n");
        }
        else { 
            printf("Host is down or not reachable\n");
        }
        return 0; // Exit after ping scan
    }

    // Proceed with port scanning if option 2 is selected
    if (is_host_up(target_ip)) {
        printf("Host is up. Starting port scan...\n");
        scan_target(target_ip);
    } else {
        printf("Host %s is down or not reachable.\n", target_ip);
    }

    return 0;
}

/**
 * @brief Scans the target IP for open ports using multithreading.
 * 
 * Iterates through a predefined list of ports, creating threads to scan each port while limiting concurrency.
 * 
 * @param target_ip The IP address of the target to scan.
 */
void scan_target(char target_ip[]) {
    bool open_ports[1025] = { false };
    // Predefined list of common ports to scan
    int ports [] = {1,3,4,6,7,9,13,17,19,20,21,22,23,24,25,26,30,32,33,37,42,43,49,53,70,79,80,81,82,83,84,85,88,89,90,99,100,106,109,110,111,113,119,125,135,139,143,144,146,161,163,179,199,211,212,222,254,255,256,259,264,280,301,306,311,340,366,389,406,407,416,417,425,427,443,444,445,458,464,465,481,497,500,512,513,514,515,524,541,543,544,545,548,554,555,563,587,593,616,617,625,631,636,646,648,666,667,668,683,687,691,700,705,711,714,720,722,726,749,765,777,783,787,800,801,808,843,873,880,888,898,900,901,902,903,911,912,981,987,990,992,993,995,999,1000,1001,1002,1007,1009,1010,1011,1021,1022,1023,1024,1025,1026,1027,1028,1029,1030,1031,1032,1033,1034,1035,1036,1037,1038,1039,1040,1041,1042,1043,1044,1045,1046,1047,1048,1049,1050,1051,1052,1053,1054,1055,1056,1057,1058,1059,1060,1061,1062,1063,1064,1065,1066,1067,1068,1069,1070,1071,1072,1073,1074,1075,1076,1077,1078,1079,1080,1081,1082,1083,1084,1085,1086,1087,1088,1089,1090,1091,1092,1093,1094,1095,1096,1097,1098,1099,1100,1102,1104,1105,1106,1107,1108,1110,1111,1112,1113,1114,1117,1119,1121,1122,1123,1124,1126,1130,1131,1132,1137,1138,1141,1145,1147,1148,1149,1151,1152,1154,1163,1164,1165,1166,1169,1174,1175,1183,1185,1186,1187,1192,1198,1199,1201,1213,1216,1217,1218,1233,1234,1236,1244,1247,1248,1259,1271,1272,1277,1287,1296,1300,1301,1309,1310,1311,1322,1328,1334,1352,1417,1433,1434,1443,1455,1461,1494,1500,1501,1503,1521,1524,1533,1556,1580,1583,1594,1600,1641,1658,1666,1687,1688,1700,1717,1718,1719,1720,1721,1723,1755,1761,1782,1783,1801,1805,1812,1839,1840,1862,1863,1864,1875,1900,1914,1935,1947,1971,1972,1974,1984,1998,1999,2000,2001,2002,2003,2004,2005,2006,2007,2008,2009,2010,2013,2020,2021,2022,2030,2033,2034,2035,2038,2040,2041,2042,2043,2045,2046,2047,2048,2049,2065,2068,2099,2100,2103,2105,2106,2107,2111,2119,2121,2126,2135,2144,2160,2161,2170,2179,2190,2191,2196,2200,2222,2251,2260,2288,2301,2323,2366,2381,2382,2383,2393,2394,2399,2401,2492,2500,2522,2525,2557,2601,2602,2604,2605,2607,2608,2638,2701,2702,2710,2717,2718,2725,2800,2809,2811,2869,2875,2909,2910,2920,2967,2968,2998,3000,3001,3003,3005,3006,3007,3011,3013,3017,3030,3031,3052,3071,3077,3128,3168,3211,3221,3260,3261,3268,3269,3283,3300,3301,3306,3322,3323,3324,3325,3333,3351,3367,3369,3370,3371,3372,3389,3390,3404,3476,3493,3517,3527,3546,3551,3580,3659,3689,3690,3703,3737,3766,3784,3800,3801,3809,3814,3826,3827,3828,3851,3869,3871,3878,3880,3889,3905,3914,3918,3920,3945,3971,3986,3995,3998,4000,4001,4002,4003,4004,4005,4006,4045,4111,4125,4126,4129,4224,4242,4279,4321,4343,4443,4444,4445,4446,4449,4550,4567,4662,4848,4899,4900,4998,5000,5001,5002,5003,5004,5009,5030,5033,5050,5051,5054,5060,5061,5080,5087,5100,5101,5102,5120,5190,5200,5214,5221,5222,5225,5226,5269,5280,5298,5357,5405,5414,5431,5432,5440,5500,5510,5544,5550,5555,5560,5566,5631,5633,5666,5678,5679,5718,5730,5800,5801,5802,5810,5811,5815,5822,5825,5850,5859,5862,5877,5900,5901,5902,5903,5904,5906,5907,5910,5911,5915,5922,5925,5950,5952,5959,5960,5961,5962,5963,5987,5988,5989,5998,5999,6000,6001,6002,6003,6004,6005,6006,6007,6009,6025,6059,6100,6101,6106,6112,6123,6129,6156,6346,6389,6502,6510,6543,6547,6565,6566,6567,6580,6646,6666,6667,6668,6669,6689,6692,6699,6779,6788,6789,6792,6839,6881,6901,6969,7000,7001,7002,7004,7007,7019,7025,7070,7100,7103,7106,7200,7201,7402,7435,7443,7496,7512,7625,7627,7676,7741,7777,7778,7800,7911,7920,7921,7937,7938,7999,8000,8001,8002,8007,8008,8009,8010,8011,8021,8022,8031,8042,8045,8080,8081,8082,8083,8084,8085,8086,8087,8088,8089,8090,8093,8099,8100,8180,8181,8192,8193,8194,8200,8222,8254,8290,8291,8292,8300,8333,8383,8400,8402,8443,8500,8600,8649,8651,8652,8654,8701,8800,8873,8888,8899,8994,9000,9001,9002,9003,9009,9010,9011,9040,9050,9071,9080,9081,9090,9091,9099,9100,9101,9102,9103,9110,9111,9200,9207,9220,9290,9415,9418,9485,9500,9502,9503,9535,9575,9593,9594,9595,9618,9666,9876,9877,9878,9898,9900,9917,9929,9943,9944,9968,9998,9999,10000,10001,10002,10003,10004,10009,10010,10012,10024,10025,10082,10180,10215,10243,10566,10616,10617,10621,10626,10628,10629,10778,11110,11111,11967,12000,12174,12265,12345,13456,13722,13782,13783,14000,14238,14441,14442,15000,15002,15003,15004,15660,15742,16000,16001,16012,16016,16018,16080,16113,16992,16993,17877,17988,18040,18101,18988,19101,19283,19315,19350,19780,19801,19842,20000,20005,20031,20221,20222,20828,21571,22939,23502,24444,24800,25734,25735,26214,27000,27352,27353,27355,27356,27715,28201,30000,30718,30951,31038,31337,32768,32769,32770,32771,32772,32773,32774,32775,32776,32777,32778,32779,32780,32781,32782,32783,32784,32785,33354,33899,34571,34572,34573,35500,38292,40193,40911,41511,42510,44176,44442,44443,44501,45100,48080,49152,49153,49154,49155,49156,49157,49158,49159,49160,49161,49163,49165,49167,49175,49176,49400,49999,50000,50001,50002,50003,50006,50300,50389,50500,50636,50800,51103,51493,52673,52822,52848,52869,54045,54328,55055,55056,55555,55600,56737,56738,57294,57797,58080,60020,60443,61532,61900,62078,63331,64623,64680,65000,65129,65389};
    
    pthread_t threads[MAX_THREADS];
    sem_t thread_semaphore;
    sem_init(&thread_semaphore, 0, MAX_THREADS);

    int thread_count = 0;

    // Iterate through each port and create a thread to scan it
    for (int i = 0; i <= ((sizeof(ports)/ sizeof(ports[0]))-1); i++) { 
        sem_wait(&thread_semaphore);

        ThreadArgs *args = malloc(sizeof(ThreadArgs));
        if (!args) {
            perror("Failed to allocate memory for thread arguments");
            exit(EXIT_FAILURE);
        }

        args->port = ports[i];
        args->ip_address = target_ip;
        args->thread_semaphore = &thread_semaphore;
        args->open_ports = open_ports; 

        if (pthread_create(&threads[thread_count % MAX_THREADS], NULL, port_scan, args)) {
            fprintf(stderr, "Error creating thread\n");
            free(args);
            sem_post(&thread_semaphore);
            continue;
        }

        thread_count++;

        // Join threads in batches to limit concurrency
        if (thread_count % MAX_THREADS == 0) {
            for (int j = 0; j < MAX_THREADS; j++) {
                pthread_join(threads[j], NULL);
            }
        }
    }

    // Join any remaining threads
    for (int j = 0; j < thread_count % MAX_THREADS; j++) {
        pthread_join(threads[j], NULL);
    }

    sem_destroy(&thread_semaphore);
    
    // Attempt to guess the operating system based on open ports
    guess_operating_system(open_ports);
}

/**
 * @brief Sets a socket to non-blocking mode.
 * 
 * @param sockfd The file descriptor of the socket.
 * @return int Returns 0 on success, -1 on failure.
 */
int set_socket_non_blocking(int sockfd) {
    int flags = fcntl(sockfd, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
}

/**
 * @brief Checks the status of a specific port on the target.
 * 
 * Attempts to connect to the target port and determines if it's open, filtered, or closed.
 * 
 * @param sockfd The socket file descriptor.
 * @param target The sockaddr_in structure containing target details.
 * @return int Returns 0 if open, -1 if closed, -2 if filtered, and -3 on error.
 */
int check_port_status(int sockfd, struct sockaddr_in target) {
    if (set_socket_non_blocking(sockfd) < 0) return -3;

    int result = connect(sockfd, (struct sockaddr *)&target, sizeof(target));
    if (result == -1 && errno != EINPROGRESS) return -3;

    if (result == 0) return 0;

    fd_set writefds;
    FD_ZERO(&writefds);
    FD_SET(sockfd, &writefds);

    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;

    result = select(sockfd + 1, NULL, &writefds, NULL, &tv);
    if (result == -1) {
        return -3;
    } else if (result == 0) {
        return -2;
    } else {
        if (FD_ISSET(sockfd, &writefds)) {
            int error;
            socklen_t len = sizeof(error);
            if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
                return -3;
            }
            return error == 0 ? 0 : -1;
        }
    }
    return -2;
}

/**
 * @brief Thread function to perform port scanning.
 * 
 * Each thread attempts to connect to a specific port and logs the result.
 * 
 * @param arguments Pointer to ThreadArgs structure containing scan parameters.
 * @return void* Returns NULL upon completion.
 */
void *port_scan(void *arguments) {
    ThreadArgs *args = (ThreadArgs *)arguments;
    int sockfd, status;
    struct sockaddr_in target;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Could not create socket");
        sem_post(args->thread_semaphore);
        free(arguments);
        return NULL;
    }

    memset(&target, 0, sizeof(target));
    target.sin_family = AF_INET;
    target.sin_addr.s_addr = inet_addr(args->ip_address);
    target.sin_port = htons(args->port);

    FILE *report = fopen("scan.txt", "a+");
    if (!report) {
        perror("Failed to open report file");
        close(sockfd);
        sem_post(args->thread_semaphore);
        free(arguments);
        return NULL;
    }

    status = check_port_status(sockfd, target);
    if (status == 0) {
        args->open_ports[args->port] = true;
        const char *service_name = port_to_service(args->port);
        printf("Port %d is open (Service: %s).\n", args->port, service_name ? service_name : "Unknown");
        fprintf(report, "Port %d is open (Service: %s).\n", args->port, service_name ? service_name : "Unknown");
    }  else if (status == -2) {
        printf("Port %d is filtered.\n", args->port);
        fprintf(report, "Port %d is filtered.\n", args->port);
    }
    fclose(report);
    sem_post(args->thread_semaphore);
    close(sockfd);
    free(arguments);
    return NULL;
}

/**
 * @brief Determines if the host is up by sending ping requests.
 * 
 * Sends multiple ping attempts and considers the host up if a minimum number succeed.
 * 
 * @param ip_address The IP address of the target host.
 * @return int Returns 1 if the host is up, 0 otherwise.
 */
int is_host_up(const char ip_address[]) {
    char command[64];
    int success_count = 0;
    int attempts = 4;
    int required_successes = 2;

    for (int i = 0; i < attempts; i++) {
        snprintf(command, sizeof(command), "ping -c 1 -W 2 %s > /dev/null 2>&1", ip_address);
        if (system(command) == 0) {
            success_count++;
        }
    }

    return success_count >= required_successes;
}

/**
 * @brief Guesses the operating system based on the open ports detected.
 * 
 * Uses common port indicators to make an educated guess about the target's OS.
 * 
 * @param open_ports Array indicating which ports are open.
 */
void guess_operating_system(bool open_ports[]) {
    FILE *report = fopen("scan.txt", "a+");
    if (!report) {
        perror("Failed to open report file");
        return;
    }
    
    // Example OS fingerprinting based on open ports
    if (open_ports[22] && open_ports[80]) {
        printf("Operating System might be Linux/Unix based\n");
        fprintf(report, "Operating System might be Linux/Unix based\n");
    } else if (open_ports[135] && open_ports[445]) {
        printf("Operating System might be Windows\n");
        fprintf(report, "Operating System might be Windows\n");
    } else if (open_ports[548] || open_ports[631]) {
        printf("Operating System might be macOS\n");
        fprintf(report, "Operating System might be macOS\n");
    } else {
        printf("Unable to determine the Operating System\n");
        fprintf(report, "Unable to determine the Operating System\n");
    }
    fclose(report);
}

/**
 * @brief Maps port numbers to their common service names.
 * 
 * Provides a human-readable service name for well-known ports.
 * 
 * @param port The port number to map.
 * @return const char* The name of the service, or NULL if unmapped.
 */
const char* port_to_service(int port) {
    switch (port) {
        case 20: return "FTP (Data Transfer)";
        case 21: return "FTP (Control)";
        case 22: return "SSH";
        case 23: return "Telnet";
        case 25: return "SMTP";
        case 53: return "DNS";
        case 67: return "DHCP (Server)";
        case 68: return "DHCP (Client)";
        case 69: return "TFTP";
        case 80: return "HTTP";
        case 110: return "POP3";
        case 119: return "NNTP";
        case 123: return "NTP";
        case 135: return "Microsoft RPC";
        case 137: return "NetBIOS Name Service";
        case 138: return "NetBIOS Datagram Service";
        case 139: return "NetBIOS Session Service";
        case 143: return "IMAP";
        case 161: return "SNMP";
        case 162: return "SNMP Trap";
        case 179: return "BGP";
        case 201: return "AppleTalk Routing Maintenance";
        case 389: return "LDAP";
        case 443: return "HTTPS";
        case 445: return "Microsoft SMB";
        case 465: return "SMTPS";
        case 514: return "Syslog";
        case 515: return "LPD";
        case 543: return "Kerberos";
        case 548: return "AFP (Apple Filing Protocol)";
        case 587: return "SMTP (Mail Submission)";
        case 993: return "IMAPS";
        case 995: return "POP3S";
        case 1025: return "Microsoft RPC";
        case 1723: return "PPTP";
        case 2049: return "NFS";
        case 3306: return "MySQL";
        case 3389: return "RDP";
        case 5060: return "SIP";
        case 5900: return "VNC";
        case 6000: return "X11";
        default: return NULL;
    }
}
