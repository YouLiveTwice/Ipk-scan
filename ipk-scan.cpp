#include <getopt.h>
#include <iostream>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <cstring>
#include <unistd.h>
#include <thread>
#include <queue>
#include <netdb.h>
#include <errno.h>
//#include <thread>


//https://www.tenouk.com/Module43a.html?fbclid=IwAR3UyMpoGN13tSrKl7R2Az5hg7smMgiHQpyj5GPkLRif0BHW20km3ifDdEk
struct IPHEADER {
	unsigned char			iph_ihl:5, iph_ver:4;
	unsigned char			iph_tos;
	unsigned short int 	iph_len;
	unsigned short int 	iph_ident;
	unsigned char			iph_flag;
	unsigned short int 	iph_offset;
	unsigned char			iph_ttl;
	unsigned char 			iph_protocol;
	unsigned short int 	iph_chksum;
	unsigned int 			iph_source;
	unsigned int 			iph_dest;
};

//https://www.tenouk.com/Module43a.html?fbclid=IwAR3UyMpoGN13tSrKl7R2Az5hg7smMgiHQpyj5GPkLRif0BHW20km3ifDdEk
struct UDPHEADER {
	unsigned short int 	udph_srcport;
	unsigned short int 	udph_destport;
	unsigned short int 	udph_len;
	unsigned short int 	udph_chksum;
};

//https://www.tenouk.com/Module43a.html?fbclid=IwAR3UyMpoGN13tSrKl7R2Az5hg7smMgiHQpyj5GPkLRif0BHW20km3ifDdEk
struct TCPHEADER {
	 unsigned short int tcph_srcport;
	 unsigned short int tcph_destport;
	 unsigned int       tcph_seqnum;
	 unsigned int       tcph_acknum;
	 unsigned char      tcph_reserved:4, tcph_offset:4;
	  unsigned int
	       tcp_res1:4,      
	       tcph_hlen:4,     
	       tcph_fin:1,     
	       tcph_syn:1,      
	       tcph_rst:1,     
	       tcph_psh:1,     
	       tcph_ack:1,      
	       tcph_urg:1,      
	       tcph_res2:2;
	 unsigned short int tcph_win;
	 unsigned short int tcph_chksum;
	 unsigned short int tcph_urgptr;
};

//https://www.tenouk.com/Module43a.html?fbclid=IwAR3UyMpoGN13tSrKl7R2Az5hg7smMgiHQpyj5GPkLRif0BHW20km3ifDdEk
#define LEN 8192 

std::queue<int> tflag;
std::queue<int> uflag;
std::string iflag = "";
std::string adress = "";
std::string adress_src = "";

void PrintHelp()
{
    std::cout <<
	"-t or --pt <port_min,port_max> <port1,port2>: 	skaned ports for udp\n"
	"-u or --pu <port_min,port_max> <port1,port2>: 	skaned ports for tcp\n"
	"-i <interface>:	internet interface when not enterd, Takes first interface(not lo)\n"
	"--help:	Show help\n";
	exit(1);
}
//https://gist.github.com/quietcricket/2521037?fbclid=IwAR0qv9CPWL_Zw575aweSQIqzwTTI5Dqz4oaAcygqKg2xB4oM44xvsxU5ptc
//vezme sfecifikovani interface z argumetu nebo pokud je praydrna tak defaultni interface a pokusi se ytjisti ipadresu
std::string getIPAddress(){
    std::string ipAddress="";
    struct ifaddrs *interfaces = NULL;
    struct ifaddrs *temp_addr = NULL;
    int success = 0;
    success = getifaddrs(&interfaces);
    if (success == 0) {
        temp_addr = interfaces;
        while(temp_addr != NULL) {
            if(temp_addr->ifa_addr->sa_family == AF_INET) {
                if(strcmp(temp_addr->ifa_name, iflag.c_str())==0){ //TODO string.c_str() taky tady musi byt ifalg
                    ipAddress = inet_ntoa(((struct sockaddr_in*)temp_addr->ifa_addr)->sin_addr);
                }
            }
            temp_addr = temp_addr->ifa_next;
        }
    }
    freeifaddrs(interfaces);
    if (ipAddress == "")
    {
    	perror("interface error");
    	PrintHelp();
    	exit(1);
    }
    return ipAddress;
}

//https://www.tenouk.com/Module43a.html?fbclid=IwAR3UyMpoGN13tSrKl7R2Az5hg7smMgiHQpyj5GPkLRif0BHW20km3ifDdEk
unsigned short csum(unsigned short *buf, int nwords)
{
    unsigned long sum;
    for(sum=0; nwords>0; nwords--){
		sum += *buf++;
    }
    sum = (sum >> 16) + (sum &0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

//prevztao s http://man7.org/linux/man-pages/man3/getifaddrs.3.html
//zjisti prvni nelopbacovi internetovi interface
std::string getInterface(){
	std::string interface = "";
	struct ifaddrs *ifaddr, *ifa;
	int family;

	if (getifaddrs(&ifaddr) == -1) {
		perror("getifaddrs"); 
		exit(1);
    }
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL)
 			continue;
 		family = ifa->ifa_addr->sa_family;
 		if (family == AF_INET){
 			interface = ifa->ifa_name;
 		} 
	}

	if (interface == "" or interface == "lo")
    {
    	PrintHelp();
    	exit(1);
    }
    else
		return interface;
}
//testovani na 4 tecki a rozsak mezi 0-255
bool ValidIpAdress(std::string adress){
	//test na pocet tecek
	int dot = 0;
	for(int i = 0; i < adress.length(); i++){
		if (adress[i] == '.'){
			dot += 1;
		}
	}
	if(dot != 3){
		return false;
	}
	//postupne roydelovani a testovani na spravne rozmezi
	for(int i = 0; i <= dot; i++){
		std::string delimiter = ".";
		std::string token = adress.substr(0, adress.find(delimiter));
		adress.erase(0, token.length() + 1);

		std::string::size_type sz;
		int intToken = std::stoi (token, &sz);
		if(intToken < 0 or intToken > 255){
			return false;
		}
	}
	return true;
}

//https://paulschreiber.com/blog/2005/10/28/simple-gethostbyname-example/
//pokuseit se dostat ip adresu s domeny
std::string getIpAdressFromName (std::string adress){
	struct hostent *stru_adress;
	if((stru_adress = gethostbyname(adress.c_str())) == NULL){
		perror("Bad domain name\n");
		PrintHelp();
		exit(1);
	}
	return inet_ntoa(*( struct in_addr*)(stru_adress->h_addr_list[0]));
}
//testovani na znkay adresi 
bool ValidDomain(std::string adress){
	std::string token = "www";
	if(adress.find(token) != -1 and adress.find('.') != -1){
		return true;
	}
	else{
		return false;
	}
}

//prevede dotayovane pory ktere jsou v string na int[]
std::queue<int> getPortArray(std::string port_string){
	std::queue<int> port_array;
	//pokdu je argumet zadan ve stilu port,port
	if(port_string.find(',') != -1) {
		int i = 0;
		while(port_string != ""){
			std::string port = port_string.substr(0, port_string.find(","));
			int *tmp;
			if(atoi(port.c_str()) > 0 and atoi(port.c_str()) <= 65535){
				port_array.push(atoi(port.c_str()));
				port_string.erase(0, port.length() + 1);
				//std::cout << port_array.back() << "\n";
			}
			else{
				PrintHelp();
				exit(1);
			}
			i++;
		}
	}

	//pokud je agrumet zadan ve stilu port-port
	else if(port_string.find('-') != -1){
		std::string port = port_string.substr(0, port_string.find("-"));
		port_string.erase(0, port.length() + 1);
		int beggining = atoi(port.c_str());
		int end = atoi(port_string.c_str());
		if (beggining  <  end and beggining > 0 and beggining < 65535 and end > 1 and end <= 65535){
			int i = 0;
			while(beggining <= end){
				port_array.push(beggining);
				//std::cout << port_array.back() << "\n";
				beggining++;
				i++;
			}
		}
		else{
			PrintHelp();
			exit(1);
		} 
	}

	//pokud argumet je jen ve tvaru port
	else{
		if(atoi(port_string.c_str()) > 0 and atoi(port_string.c_str()) <= 65535){
			port_array.push(atoi(port_string.c_str()));
		}
		else{
			PrintHelp();
			exit(1);
		}
	}
	return port_array;
}
//https://www.gnu.org/software/libc/manual/html_node/Getopt-Long-Option-Example.html
void ProcessArgs(int argc, char** argv)
{
	const char* const short_opts = "t:u:i:h";
	const option long_opts[] = {
            {"pt", required_argument, nullptr, 't'},
            {"pu", required_argument, nullptr, 'u'},
            {"i", no_argument, nullptr, 'i'},
            {"help", no_argument, nullptr, 'h'},
            {nullptr, no_argument, nullptr, 0}
    };

	while (true)
    {
		const int opt = getopt_long(argc, argv, short_opts, long_opts, nullptr);
		if (-1 == opt)
			break;
		switch (opt)
        {
			case 't':
				tflag = getPortArray(std::string(optarg)); 
			break;
			case 'u':
            	uflag = getPortArray(std::string(optarg));
			break;
			case 'i':
            	iflag = std::string(optarg);
			break;
			case 'h': // -h or --help
			case '?': // Unrecognized option
			default:
				PrintHelp();
			break;
        }
    }
    //jeden s tech poarametru musi bzt zadani
    if (tflag.empty() and uflag.empty()){
    	PrintHelp();
    	exit(1);
    }

    //pocatek vzpisu 
    for(int i = 1; i < argc ;i++){
    	std::string localhost = argv[i];
    	if(ValidIpAdress(argv[i])){
    		adress = argv[i];
    		printf("Interesting ports on %s:\n", adress.c_str());
    	}
    	else if(ValidDomain(argv[i])){
    		printf("Interesting ports on %s ", argv[i]);
    		adress = getIpAdressFromName(argv[i]);
    		printf("(%s):\n", adress.c_str());
    	}	
    	else if((localhost.compare("localhost")) == 0){	
    		adress = "127.0.0.1";
    		printf("Interesting ports on localhost (%s):\n", adress.c_str());
    	}
    }
    //kontaloa ifalgu pokud nei tak se vzbere prvni interfacea priradi se do iflagu
    if (iflag == ""){
    	iflag = getInterface();
    }
    adress_src = getIPAddress();
    //adresa pokud neni zadan tak se nevi kam posilat tedi exit
    if (adress == ""){
    	PrintHelp();
    	exit(1);
    }
    printf("PORT STATE\n");
}

//vzato s https://www.tenouk.com/Module43a.html?fbclid=IwAR3ZnVIcPHkbFBggRmGJS-3rC3oFxiu8iIa-p2EqxfEUHFQuPK82IUvZJCM
void udpscan (){
	char buff[LEN];
	//inicializce ip a udp headru
	struct IPHEADER *ipheader = (struct IPHEADER *) buff;
	struct UDPHEADER *udpheader = (struct UDPHEADER *) (buff + sizeof(struct IPHEADER));

	//https://www.tenouk.com/Module43a.html?fbclid=IwAR3ZnVIcPHkbFBggRmGJS-3rC3oFxiu8iIa-p2EqxfEUHFQuPK82IUvZJCM
	//inicialiyace structury pro ip adresy
	struct sockaddr_in sin;
	socklen_t sinSize = sizeof(sin);

	int one = 1;
	const int *val = &one;
	memset(buff, 0, LEN);

	//https://www.tenouk.com/Module43a.html?fbclid=IwAR3ZnVIcPHkbFBggRmGJS-3rC3oFxiu8iIa-p2EqxfEUHFQuPK82IUvZJCMl
	//inicialiyace socketu
	int sd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if(sd < 0)
	{
		perror("socket() error");
		exit(-1);
	}

	//https://www.tenouk.com/Module43a.html?fbclid=IwAR3ZnVIcPHkbFBggRmGJS-3rC3oFxiu8iIa-p2EqxfEUHFQuPK82IUvZJCM
	//rodina adres
	sin.sin_family = AF_INET;

	//https://www.tenouk.com/Module43a.html?fbclid=IwAR3ZnVIcPHkbFBggRmGJS-3rC3oFxiu8iIa-p2EqxfEUHFQuPK82IUvZJCM
	//ip adresi pro odesilatele a prijemce
	sin.sin_addr.s_addr = inet_addr(adress.c_str());

	//https://www.tenouk.com/Module43a.html?fbclid=IwAR3ZnVIcPHkbFBggRmGJS-3rC3oFxiu8iIa-p2EqxfEUHFQuPK82IUvZJCM
	//naplneni ip hedru
	ipheader->iph_ihl = 5;
	ipheader->iph_ver = 4;
	ipheader->iph_tos = 16; //krate zpozdeni
	ipheader->iph_protocol = 17; //udp
	ipheader->iph_ttl = 64; //skoky
	ipheader->iph_len = sizeof(IPHEADER) + sizeof(UDPHEADER);
	ipheader->iph_ident = htons(54321);
	//ip adresa rozhrani
	ipheader->iph_source = inet_addr(adress_src.c_str());
	//ip adresa prijemce
	ipheader->iph_dest = inet_addr(adress.c_str());
	//port prijemce

	udpheader->udph_len = htons(sizeof(struct UDPHEADER));
	ipheader->iph_chksum = csum((unsigned short *)buff, sizeof(struct IPHEADER) + sizeof(struct UDPHEADER));

	if(setsockopt(sd, IPPROTO_IP, IP_RECVERR, val, sizeof(one)) < 0)
	{
		perror("setsockopt() error");
		exit(-1);
	}

	while(!uflag.empty()){
		udpheader->udph_destport = htons(uflag.front());
		sin.sin_port = htons(uflag.front());
		if(sendto(sd, buff, ipheader->iph_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
		{
			perror("sendto() error");
			exit(-1);
		}

		else
		{ 
			//http://www.mathcs.emory.edu/~cheung/Courses/455/Syllabus/9-netw-prog/timeout.html
			fd_set select_fds;                
	      	struct timeval timeout;           
			FD_ZERO(&select_fds);             
	      	FD_SET(sd, &select_fds);           

	      	timeout.tv_sec = 5;        
	      	timeout.tv_usec = 0;
	      	if ( select(32, &select_fds, NULL, NULL, &timeout) == 0)
	      	{
	        	printf("%d/udp closed\n", uflag.front());
	      	}
	        else{
	        	if (recvfrom(sd, buff, ipheader->iph_len, 0, (struct sockaddr *)&sin, &sinSize) > 0){
					printf("%d/udp open\n", uflag.front());
				}
				else{
					printf("%d/udp closed\n", uflag.front());
				}
	        }
		}
		uflag.pop();
	}
	close(sd);
}
//https://www.tenouk.com/Module43a.html?fbclid=IwAR3ZnVIcPHkbFBggRmGJS-3rC3oFxiu8iIa-p2EqxfEUHFQuPK82IUvZJCM
void tcpscan (int port){
	char buff[LEN];
	struct IPHEADER *ipheader = (struct IPHEADER *) buff;
	struct TCPHEADER *tcpheader = (struct TCPHEADER *) (buff + sizeof(struct IPHEADER));
	//https://www.tenouk.com/Module43a.html?fbclid=IwAR3ZnVIcPHkbFBggRmGJS-3rC3oFxiu8iIa-p2EqxfEUHFQuPK82IUvZJCM
	struct sockaddr_in sin;
	socklen_t sinSize = sizeof(sin);
	int one = 1;
	const int *val = &one;
	memset(buff, 0, LEN);
	//https://www.tenouk.com/Module43a.html?fbclid=IwAR3ZnVIcPHkbFBggRmGJS-3rC3oFxiu8iIa-p2EqxfEUHFQuPK82IUvZJCM
	int sd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(sd < 0)
	{
		perror("socket() error");
   		exit(1);
	}
	//https://www.tenouk.com/Module43a.html?fbclid=IwAR3ZnVIcPHkbFBggRmGJS-3rC3oFxiu8iIa-p2EqxfEUHFQuPK82IUvZJCM
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = inet_addr(adress.c_str());
	ipheader->iph_ihl = 5;
	ipheader->iph_ver = 4;
	ipheader->iph_tos = 16;
	ipheader->iph_len = sizeof(struct IPHEADER) + sizeof(struct TCPHEADER);
	ipheader->iph_ident = htons(54321);
	ipheader->iph_offset = 0;
	ipheader->iph_ttl = 64;
	ipheader->iph_protocol = 6; //TCP protocol
	ipheader->iph_chksum = 0; 

	//adresa odesilatele
	ipheader->iph_source = inet_addr(adress_src.c_str());
	//adresa prijemce
	ipheader->iph_dest = inet_addr(adress.c_str());

	//https://www.tenouk.com/Module43a.html?fbclid=IwAR3ZnVIcPHkbFBggRmGJS-3rC3oFxiu8iIa-p2EqxfEUHFQuPK82IUvZJCM
	//Naplneni TCP Hedru
	tcpheader->tcph_seqnum = htonl(1);
	tcpheader->tcph_acknum = 0;
	tcpheader->tcph_offset = 5;
	tcpheader->tcph_syn = 1;
	tcpheader->tcph_ack = 0;
	tcpheader->tcph_win = htons(32767);
	tcpheader->tcph_chksum = 0; 
	tcpheader->tcph_urgptr = 0;

	//https://www.tenouk.com/Module43a.html?fbclid=IwAR3ZnVIcPHkbFBggRmGJS-3rC3oFxiu8iIa-p2EqxfEUHFQuPK82IUvZJCM
	ipheader->iph_chksum = csum((unsigned short *) buff, (sizeof(struct IPHEADER) + sizeof(struct TCPHEADER)));

	//nastaveni socketu
	if(setsockopt(sd, IPPROTO_IP, IP_RECVERR, val, sizeof(one)) < 0)
	{
	    perror("setsockopt() error");
	    exit(1);
	}
	//projit vsechni porty ktere jsou ulozeni v tflag

	sin.sin_port = htons(port);
	tcpheader->tcph_destport = htons(port);
	//https://stackoverflow.com/questions/4181784/how-to-set-socket-timeout-in-c-when-making-multiple-connections?fbclid=IwAR1dEY1MVG6YBAo-HYEP8bjOUHku45YN5IioVsWBgcZMhkEm3bxQPy7do1s
	struct timeval t;      
 	t.tv_sec = 3;
   	t.tv_usec = 0;
    if (setsockopt (sd, SOL_SOCKET, SO_SNDTIMEO, (char *)&t, sizeof(t)) < 0){
    	printf("setsockopt failed\n");
    	exit(1);
    }

	if(connect(sd, (struct sockaddr *)&sin, sinSize) != 0){
			//https://docs.python.org/2/library/errno.html
			//fitrovani pokud nedostanem odpoved a skonci timer
			if(errno == 115){
				printf("%d/tcp filtered\n", port);
			}
			//pokud dostaneme odpoved
			else if(errno == 111){
				printf("%d/tcp closed\n", port);
			}
		}
	//pokud prijde odpoved ze je port otevreni 
	else{
		printf("%d/tcp open\n",port);
	}
	close(sd);
}

int main(int argc, char **argv)
{
	ProcessArgs(argc, argv);
	if(!uflag.empty()){
		udpscan();
	}
	if(!tflag.empty()){
		while(!tflag.empty()){
			int port = tflag.front();
			tflag.pop();
			tcpscan(port);
		}
	}
	return 0;
}