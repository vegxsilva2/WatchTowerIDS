#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <pcap.h>


//Callback function to proccess the captured packets
void packet_handler(unsigned char *user, const struct pcap_pkthdr *header, const unsigned char *packet){
    printf("Packet captures: Length: %d\n", header->len);

    // Llama al módulo de análisis de paquetes
    // Aquí puedes llamar a una función de otro módulo para analizar el paquete
    // Por ejemplo: analyze_packet(packet, header->len);

    // Para demostrar, solo imprimimos el tamaño del paquete
    // Reemplaza esto con una llamada a tu función de análisis de paquetes

}


int main(){
    
    //Initialize Winsock
    WSADATA wsaData;
    
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        printf("WSAStartup failed: %d\n", WSAGetLastError());
        return 1;
    }

    //Initialize Socket
    SOCKET rawSocket = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
    if (rawSocket == INVALID_SOCKET) {
        printf("Error al crear socket: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }

    //Configure the net interface for capture
    struct sockaddr_in sockAddr;
    sockAddr.sin_family = AF_INET;
    sockAddr.sin_port = htons(0); // Port 0, as we wont use an specific port
    sockAddr.sin_addr.s_addr = inet_addr("192.168.1.107"); // Replace with your local IP address

    if (bind(rawSocket, (struct sockaddr*)&sockAddr, sizeof(sockAddr)) == SOCKET_ERROR) {
        printf("Error al enlazar el socket: %d\n", WSAGetLastError());
        closesocket(rawSocket);
        WSACleanup();
        return 1;
    }

    //Configure the socket to capture all the incoming packets
    int opt = 1;
    if (setsockopt(rawSocket, IPPROTO_IP, IP_HDRINCL, (char *)&opt, sizeof(opt)) == SOCKET_ERROR) {
        printf("Error al configurar socket: %d\n", WSAGetLastError());
        closesocket(rawSocket);
        WSACleanup();
        return 1;
    }

    //Activates the promiscous mode (Capturing all the network's traffic, not only the traffic heading to host)
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Encuentra todos los dispositivos de red
    handle = pcap_open_live("\\Device\\NPF_{0BE90C74-D0BF-4CE8-9720-FE349676F4BC}", BUFSIZ, 1, 1000, errbuf); // First argument must be the name of your network adapter
    if (handle == NULL) {
        printf("No se pudo abrir el dispositivo para captura: %s\n", errbuf);
        return 1;
    }


   //Capture and analyse the traffic using pcap_next_ex() or pcap_loop()
    printf("Starting the packet capture...\n");
    pcap_loop(handle, 0, packet_handler, NULL); // 0 means capturing until the program is detained

   //Close the socket and clean up
    closesocket(rawSocket);
    WSACleanup();
    pcap_close(handle);
    
    return 0;
}