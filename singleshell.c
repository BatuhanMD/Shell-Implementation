/*
21120205317 (Batuhan) - memshr,logout,xterm,shellog
22120205073 (Beytullah) -main deki while döngüsü ve parent-child management
21120205705 (Kaan) - Sonu "_addr" ile biten fonksiyonlar,kontrol işlemleri
Dipnot= Geri kalan işlevler beraberce düşünülüp yazılmıştır.
Programda fonksiyonların ismi ve anlaşılmayacak durumlar yanlarında özetlenmiştir.
Chatgpt'den yardım alınan yerler= init_screen(),
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <signal.h>

#define INBUF_SIZE 256
#define OUTBUF_SIZE 1024

#define MY_FILE_SIZE 1024
const char *name = "log.txt";
char *addr = NULL;
int fd = -1;
char inp_buffer[INBUF_SIZE];
ssize_t errnos = 0;

void my_prompt();
int initmem();
void init_screen();
char *return_current_date_str();
void log_stdout_addr(const char *parameter);
void log_stderr_addr(const char *parameter);
void program_end_addr();
void program_start_addr();
void log_output();
void memshr(const char *x);
void program_end();
void write_addr_to_filelog1(); /*test function.*/
int write_err(ssize_t size);   /*size_t ile ssize_t nin farkı https://jameshfisher.com/2017/02/22/ssize_t*/

int write_err(ssize_t size) /*write için errer durumu kontrol*/
{
    if (size == -1)
    {
        perror("write:");
         log_stderr_addr(" write error:\n");
        return 1;
    }

    return 0;
}

void write_addr_to_filelog1()
{
    int log_fd = open("log1.txt", O_RDWR | O_APPEND | O_CREAT, 0666);
    if (log_fd == -1)
    {
        perror("log_fd -> Dosya acma hatasi!:");
         log_stderr_addr("File open error:\n");
    }

    int i = 0;
    int mem_len = strlen(addr);
    for (i = 0; i < mem_len; i++)
    {
        errnos = write(log_fd, &addr[i], 1);
        if (write_err(errnos))
        {
            exit(1);
        }
    }

    close(log_fd);
}

void signal_callback_handler(int signum)
{
    printf("Caught signal %d\n", signum);
    /* ctrl+c sinyali alındığında "exit" mesajını log dosyasına yazdır*/
    if (signum == SIGINT)
    {
        memshr("exit");
        program_end_addr();
    }

    exit(signum);
}
void log_output() /*çıktıların yazılması*/
{

    fd = open(name, O_RDWR | O_APPEND | O_CREAT, 0666);
    char *date_str = return_current_date_str();

    char output[1024];
    snprintf(output, sizeof(output), "Komut: %s | Parent id: %d | Child id: %d | Time: %s\n", addr, getppid(), getpid(), date_str);

    errnos = write(fd, output, strlen(output));
    if (write_err(errnos))
    {
        exit(1);
    }

    close(fd);
    free(date_str);
}
void program_end() /* program sonlandiginda cagrilacak fonksiyon*/
{
    log_output();
}
void memshr(const char *x) /*addr'e yazdirma*/
{
    strncpy(inp_buffer, x, INBUF_SIZE - 1);
    inp_buffer[INBUF_SIZE - 1] = '\0';
    memcpy(addr, inp_buffer, INBUF_SIZE);
    log_output();
}

char *return_current_date_str() /*return time to str*/
{
    time_t now = time(NULL);
    struct tm *mytime = localtime(&now);
    char *date = malloc(sizeof(char) * 36);
    snprintf(date, 36, "%02d/%02d/%4d, %d:%d:%d\n", mytime->tm_mday, mytime->tm_mon + 1, mytime->tm_year + 1900, mytime->tm_hour, mytime->tm_min, mytime->tm_sec); // date formatında yazma
    return date;
}

void log_stdout_addr(const char *parameter) /*stdout'u  yazdırma*/
{
    char output[OUTBUF_SIZE];
    snprintf(output, OUTBUF_SIZE, "parent process id:[%d]child process id:[%d] %s\n", getppid(), getpid(), parameter);
    strncat(&addr[strlen(addr)], output, OUTBUF_SIZE - strlen(addr) - 1);
    printf("%s", parameter);
}

void log_stderr_addr(const char *parameter) // stderr'leri yazdırma
{
    char output[OUTBUF_SIZE];
    snprintf(output, OUTBUF_SIZE, "process id :[%d], %.64s", getpid(), parameter);
    memshr(output);
}
void program_end_addr() /*program end durumunu addr'e yazdirma*/
{
    char output[OUTBUF_SIZE];
    snprintf(output, OUTBUF_SIZE, "program exited at %s", return_current_date_str());
    strncat(&addr[strlen(addr)], output, OUTBUF_SIZE - strlen(addr) - 1);
    printf("%s\n", output);
    memshr(output); // test
}
void program_start_addr() /* program start durumunu addr'e yazdirma*/
{
    char output[OUTBUF_SIZE];
    time_t current_time = time(NULL);
    snprintf(output, OUTBUF_SIZE, "parent id :[%d] Shell started at %s", getppid(), ctime(&current_time));
    strncpy(addr, output, OUTBUF_SIZE - 1);
    printf("%s", output);
    memshr(output);
}

void my_prompt() /*Logname ile prompt olusturma*/
{
    char *logname = getenv("LOGNAME");
    if (logname == NULL)
    {
        perror("logname:");
         log_stderr_addr(" LOGNAME error\n");
        exit(1);
    }
    char prompt[256];
    snprintf(prompt, sizeof(prompt), "%.32s$", logname);
    errno = write(1, prompt, strlen(prompt));
    if (write_err(errnos))
    {
        exit(1);
    }
}

int initmem()
{

    fd = shm_open(name, O_RDWR | O_CREAT, 0666); /* O_CREAT 'ı ben ekledim "kaan"*/
    if (fd == -1)
    {
        printf("fd'nin degeri =%d\n", fd);
        perror("singleshell.c: fd < 0");
        log_stderr_addr("shmopen error:\n");
        exit(1);
    }
    if (ftruncate(fd, 1024) == -1) /*eklenmediği durumda hata alınıyordu.*/
    {
        perror("ftruncate");
        log_stderr_addr("ftruncate error:\n");
        exit(1);
    }

    addr = mmap(NULL, MY_FILE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    printf("control: addr is shared with log.txt addr in initmem is ={%.32s}\n", addr);
    if (addr == MAP_FAILED)
    {

        perror("singleshell.c:mmap:");
         log_stderr_addr("singleshell.c mmap error:\n");
        close(fd);
        exit(1);
    }
    addr[sizeof(addr)] = '\0';
    return 0;
}

void init_screen()
{
    fflush(stdout);
    printf("\033[2J");
    printf("\033[1;1H");
    printf("\033[38;2;255;0;0m");
    printf("      _   _      _ _       \n");
    printf("     | | | | ___| | | ___  \n");
    printf("     | |_| |/ _ \\ | |/ _ \\\n");
    printf("     |  _  |  __/ | | (_) |\n");
    printf("     |_| |_|\\___|_|_|\\___/\n");
    sleep(2);
    printf("\033[0m");
    printf("\033[38;2;255;165;0m");
    printf(" ____ ____ ____ ____ ____ ____ ____\n");
    printf("||M |||Y |||S |||H |||E |||L |||L ||\n");
    printf("||__|||__|||__|||__|||__|||__|||__||\n");
    printf("|/__\\|/__\\|/__\\|/__\\|/__\\|/__\\/__\\||\n\n");
    printf("\033[0m");
}

int main()
{

    init_screen();
    initmem();
    signal(SIGINT, signal_callback_handler);
    char giris[INBUF_SIZE] = "\0";
    int oku_boy;
    char *argmnlar[20];
    char *program = NULL;
    char *token = NULL;
    int i = 0;
    argmnlar[i] = NULL;

    char child_msg[MY_FILE_SIZE] = "\0";
    char parent_message[256] = "\0";

    /*strncpy(&addr[3],"cat",OUTBUF_SIZE);*/
    char *parent_time = return_current_date_str(); /*parent time*/
    printf("parent process id :%d,%s\n", getppid(), parent_time);
    // screen ui
    printf("\033[0m");

    program_start_addr();

    while (1)
    {
        fflush(stdin);
        my_prompt();

        oku_boy = read(0, giris, 255);
        if (oku_boy <= 0)
        {
            perror("boy(giris)<=0 -> Bos komut!:");
             log_stderr_addr("boy(giris)<=0 -> Bos komut! error:\n");
        }

        else
        {
            giris[oku_boy - 1] = '\0';
            memshr(giris);
        }

        if (strncmp(giris, "exit", 4) == 0)
        {

            program_end_addr(); /*end infos*/

            exit(0);
        }

        token = strtok(giris, " \t");
        program = token;

        i = 0;
        while (token != NULL)
        {
            argmnlar[i] = token;
            token = strtok(NULL, " \t");
            i++;
        }
        argmnlar[i] = NULL;

        if (strncmp(program, "cd", 2) == 0) /*chdir durumu*/
        {
            int islem_sonuc = chdir(argmnlar[1]);
            if (islem_sonuc == -1)
            {

                printf("%.64s chdir error ! |", giris); // test
                log_stderr_addr("chdir error:\n");
            }
        }
        else
        {

            pid_t child_pr = fork();

            if (child_pr == -1)
            {
                perror("fork error:");
                 log_stderr_addr("fork error:\n");
                continue;
            }

            if (child_pr == 0)
            {
                char *child_time = return_current_date_str(); /* get time from child process*/

                int islem_sonuc = execvp(program, argmnlar);
                printf("islem_sonuc :%d", islem_sonuc);
                sprintf(child_msg, "Child process %d reading from shared memory: %s\n", getpid(), program);
                if (islem_sonuc < 0)
                {
                    snprintf(giris,INBUF_SIZE," [%.64s] process is not valid! error:\n", giris);
                    log_stderr_addr(giris);
                }
            }

            if (child_pr > 0)
            {

                waitpid(child_pr, NULL, 0);
            }
            else // silinecek ???
            {

                wait(0);
            }

            char *parent_time = return_current_date_str();

            sprintf(parent_message, "Parent process %d writing to log file, at: %s\n", getpid(), parent_time);

            free(parent_time);
            // write(fd, log_msg, strlen(log_msg));
        }
        giris[0] = '\0'; /*reset values*/
        argmnlar[i] = NULL;
        token = NULL;
        program = NULL;
    }

    if (munmap(addr, MY_FILE_SIZE) == -1)
    {
        perror("munmap:");
         log_stderr_addr(" munmap error:\n");
        exit(1);
    }
    unlink(addr);

    write(fd, addr, strlen(addr));
    if (write_err(errnos))
    {
        exit(1);
    }

    return 0;
}
