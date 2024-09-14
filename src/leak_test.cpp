#include <unistd.h>

char* New(int i)
{
    return new char[i];
}

int main()
{
    for (int i = 0; i < 10; i++)
    {
        New(i);
        sleep(1);
    }
    return 0;
}