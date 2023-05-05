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

#define MY_SHARED_FILE_NAME "/sharedlogfile"
const char *name = "log.txt";

#define MAX_SHELL 10
#define OUTBUF_SIZE 1024
#define INBUF_SIZE 256
#define MAX_PATH_LEN 2048
#define MY_FILE_SIZE 1024

ssize_t errnos = 0;
char inp_buffer[INBUF_SIZE];
char *addr = NULL;
int fd = -1;
const char program_name[] = "singleshell"; 
char path[MAX_PATH_LEN];

void log_stderr_addr(const char *parameter);
void memshr(const char *x);
void log_output();
int write_err(ssize_t size);
char *return_current_date_str();


char *return_current_date_str() /*return time to str*/
{
    time_t now = time(NULL);
    struct tm *mytime = localtime(&now);
    char *date = malloc(sizeof(char) * 36);
    snprintf(date, 36, "%02d/%02d/%4d, %d:%d:%d\n", mytime->tm_mday, mytime->tm_mon + 1, mytime->tm_year + 1900, mytime->tm_hour, mytime->tm_min, mytime->tm_sec); // date formatında yazma
    return date;
}


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

void log_stderr_addr(const char *parameter) // eklenecek
{
    char output[OUTBUF_SIZE];
    snprintf(output, OUTBUF_SIZE, "process id :[%d], %.64s", getpid(), parameter);
    memshr(output);
}
void memshr(const char *x) /*addr'e yazdirma*/
{
    strncpy(inp_buffer, x, INBUF_SIZE - 1);
    inp_buffer[INBUF_SIZE - 1] = '\0';
    memcpy(addr, inp_buffer, INBUF_SIZE);
    log_output();
}



int initmem()
{
    fd = shm_open(name,
                  O_CREAT | O_RDWR | O_TRUNC, 0666);
    if (fd < 0)
    {
        perror("multishell.c: shm_open file:");
        log_stderr_addr("multishell.c: shm_open file error:\n");
        exit(1);
    }
    if (ftruncate(fd, 1024) == -1)
    {
        perror("ftruncate:");
        exit(1);
    }

    addr = mmap(NULL, MY_FILE_SIZE,
                PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (addr == NULL)
    {
        perror("mmap:");
        log_stderr_addr("mmap error:\n");
        exit(1);
    }
    return 0;
}

int main(int argc, char **argv)
{
    printf("Usage: ./multishell 4\n");
    char *current_path = getenv("PWD"); /* programın path'ini al(farklı durumlarda farklı path dönebileceği için path'ini emin olarak olmaya çalıştım*/ 
    if (current_path == NULL)
    {
        perror("Failed to get current working directory:");
        log_stderr_addr("pwd error:\n");
        exit(-1);
    }
    if (snprintf(path, MAX_PATH_LEN, "%s/%s", current_path, program_name) >= MAX_PATH_LEN)
    { /*şuanki konum ve programın ismini birleştir.*/ 
        perror("path' is too long:");
        log_stderr_addr("path size error:\n");
        exit(-1);
    }
    char *abs_path = realpath(path, NULL); /* absolute  path'i al (realpath pathi'i almak için kolay bir yöntem stdlib.h'da var gozukmeyebilir*/ 
    
    if (abs_path == NULL)
    {
        perror("failed get abs_path:");
        log_stderr_addr("abs path error:\n");
        exit(-1);
    }

    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s <number of single shell instances>\n", argv[0]);
        exit(1);
    }

    int nshell = atoi(argv[1]); /*casting işlemi*/ 
    if (nshell > MAX_SHELL)
    {
        fprintf(stderr, "Maximum number of single shell instances is %d\n", MAX_SHELL); 
        exit(1);
    }

    initmem();

    pid_t pid;
    char arg2[32];

    for (int i = 0; i < nshell; i++)
    { /*xtermdeki sayı kadar pencere*/ 
        pid = fork();

        if (pid < 0)
        {
            perror("fork:");
            log_stderr_addr("fork error:\n");
            exit(1);
        }
        else if (pid == 0)
        {
            sprintf(arg2, "./singleshell %d", i + 1);
            execlp("xterm", "xterm", "-e", abs_path, arg2, NULL); /*xterm execution*/ 
            perror("execlp:");
            log_stderr_addr("execl error\n");
            exit(1);
        }
    }

    /* childi bekle*/
    for (int i = 0; i < nshell; i++)
    {
        wait(NULL);
    }
    time_t t = time(NULL);
    struct tm *tm = localtime(&t);
    char datetime[32];
    strftime(datetime, sizeof(datetime), "%Y%m%d_%H%M%S", tm);
    char log_file_name[64];
    snprintf(log_file_name, sizeof(log_file_name), "Shellog-%s.txt", datetime); /*shellog dosyasi olusturma*/

    int log_fd = open("log.txt", O_RDONLY|O_CREAT,0666);  
    if (log_fd < 0) {
    perror("multishell.c:open log file log_fd:");
    log_stderr_addr("multishell.c:open log file error:\n");
    exit(1);
    }
    size_t output_size = lseek(log_fd, 0, SEEK_END); /* dosyanın boyutunu al*/
    lseek(log_fd, 0, SEEK_SET); /*dosyanın başına geri dön*/ 

    char* output_buffer = (char*)malloc(output_size); /*Okunan verileri tutmak için bellek ayirildi*/ 
    if (output_buffer == NULL) {
    perror("multishell.c:allocate memory:");
    log_stderr_addr("multishell allocate mem error:\n");
    exit(1);
    }

    if (read(log_fd, output_buffer, output_size) != output_size) { /*log.txt dosyasından verileri okumak icin*/ 
    perror("multishell.c:read log file:");
    log_stderr_addr("multishell read log error:\n");
    exit(1);
    }

    close(log_fd); 

    int shellog_fd = open(log_file_name, O_CREAT | O_WRONLY , 0666);

    if (shellog_fd < 0) {
    perror("multishell.c:open Shellog file shellog_fd:");
    log_stderr_addr("multishell.c:open Shellog file error:\n");
    exit(1);
    }

    if (write(shellog_fd, output_buffer, output_size) != output_size) { /*okunan verileri shellog[time]a yazar*/ 
    perror("multishell.c:write Shellog file:\n");
    exit(1);
    }

    

    
    
    if (munmap(addr, 1024) != 1)
    {
        perror("munmap");
        log_stderr_addr("munmap error:\n");
        exit(0);
    }
    close(shellog_fd); 
    close(fd);
    free(abs_path);
    free(current_path);
    free(output_buffer);
    return 0;
}
