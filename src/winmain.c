/* WinMain entry point for Windows GUI subsystem.
   Delegates to main() so peddlecheap.exe can be built as a console app
   even when MinGW defaults to WinMain. */
#ifdef _WIN32
#include <windows.h>
int main(int argc, char **argv);
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine, int nCmdShow)
{
    return main(__argc, __argv);
}
#endif