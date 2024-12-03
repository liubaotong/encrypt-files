#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#ifdef _WIN32
#include <windows.h>
#endif

#define BUFFER_SIZE 4096
#define KEY 0xAB  // 简单的加密密钥
#define PROGRESS_BAR_WIDTH 50
#define MEGABYTE (1024 * 1024)
#define SHA256_STRING_LENGTH (EVP_MAX_MD_SIZE * 2 + 1)
#define HASH_HEADER_MAGIC "ENCRYPTED_FILE_"  // 14 bytes
#define HASH_FOOTER_MAGIC "_END_OF_HASH"     // 11 bytes

// 函数声明
void processFile(const char* path, int encrypt);
void processDirectory(const char* path, int encrypt);
void encryptDecryptBuffer(unsigned char* buffer, size_t size);
void displayProgress(const char* filename, size_t current, size_t total);
void clearLine(void);
void calculateFileHash(const char* path, char* hash_str);
void bytesToHexString(const unsigned char* bytes, char* hex_str, int len);
int writeHashToFile(const char* path, const char* hash);
int readHashFromFile(const char* path, char* hash);
int isFileEncrypted(const char* path);

// 禁用输出缓冲
void disableBuffering() {
#ifdef _WIN32
    // Windows平台下设置控制台模式
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode;
    GetConsoleMode(hOut, &mode);
    SetConsoleMode(hOut, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
#endif
    setvbuf(stdout, NULL, _IONBF, 0);
}

int main(int argc, char* argv[]) {
    // 初始化输出设置
    disableBuffering();

    if (argc != 3) {
        printf("使用方法:\n");
        printf("加密: %s -e <文件或目录路径>\n", argv[0]);
        printf("解密: %s -d <文件或目录路径>\n", argv[0]);
        return 1;
    }

    int encrypt = strcmp(argv[1], "-e") == 0;
    if (!encrypt && strcmp(argv[1], "-d") != 0) {
        printf("错误: 无效的操作参数\n");
        return 1;
    }

    struct stat path_stat;
    if (stat(argv[2], &path_stat) != 0) {
        printf("错误: 无法访问指定的文件或目录\n");
        return 1;
    }

    if (S_ISREG(path_stat.st_mode)) {
        // 处理单个文件
        processFile(argv[2], encrypt);
    } else if (S_ISDIR(path_stat.st_mode)) {
        // 处理目录
        processDirectory(argv[2], encrypt);
    } else {
        printf("错误: 不支持的文件类型\n");
        return 1;
    }

    return 0;
}

void processFile(const char* path, int encrypt) {
    char original_hash[SHA256_STRING_LENGTH] = {0};
    char stored_hash[SHA256_STRING_LENGTH] = {0};
    int is_encrypted = isFileEncrypted(path);

    // 如果是解密操作，先读取存储的原始哈希值
    if (!encrypt) {
        if (!is_encrypted) {
            printf("错误: 文件未被加密或格式不正确\n");
            return;
        }
        if (!readHashFromFile(path, stored_hash)) {
            printf("错误: 无法读取原始哈希值，文件可能已损坏\n");
            return;
        }
    } else {
        if (is_encrypted) {
            printf("错误: 文件已经被加密\n");
            return;
        }
        // 计算原始文件的哈希值
        calculateFileHash(path, original_hash);
    }

    FILE* file = fopen(path, "rb");
    if (!file) {
        printf("错误: 无法打开文件 %s\n", path);
        return;
    }

    // 获取原始文件大小
    fseek(file, 0, SEEK_END);
    size_t file_size = ftell(file);
    if (!encrypt) {
        // 解密时，需要减去哈希头尾的大小
        file_size -= (strlen(HASH_HEADER_MAGIC) + SHA256_STRING_LENGTH - 1 + strlen(HASH_FOOTER_MAGIC));
    }
    fseek(file, 0, SEEK_SET);

    // 创建临时文件
    char temp_path[1024];
    snprintf(temp_path, sizeof(temp_path), "%s.tmp", path);
    FILE* temp_file = fopen(temp_path, "wb");
    if (!temp_file) {
        printf("错误: 无法创建临时文件\n");
        fclose(file);
        return;
    }

    // 如果是加密操作，先写入哈希值
    if (encrypt) {
        size_t written = 0;
        written += fprintf(temp_file, "%s", HASH_HEADER_MAGIC);
        written += fwrite(original_hash, 1, SHA256_STRING_LENGTH - 1, temp_file);
        written += fprintf(temp_file, "%s", HASH_FOOTER_MAGIC);

        if (written != strlen(HASH_HEADER_MAGIC) + SHA256_STRING_LENGTH - 1 + strlen(HASH_FOOTER_MAGIC)) {
            printf("错误: 写入哈希值失败\n");
            fclose(file);
            fclose(temp_file);
            remove(temp_path);
            return;
        }
    }

    unsigned char buffer[BUFFER_SIZE];
    size_t bytes_read;
    size_t total_bytes_processed = 0;

    if (!encrypt) {
        // 解密时跳过哈希头
        size_t header_offset = strlen(HASH_HEADER_MAGIC) + SHA256_STRING_LENGTH - 1 + strlen(HASH_FOOTER_MAGIC);
        if (fseek(file, header_offset, SEEK_SET) != 0) {
            printf("错误: 无法跳过文件头部\n");
            fclose(file);
            fclose(temp_file);
            remove(temp_path);
            return;
        }
    }

    // 显示初始进度
    displayProgress(path, 0, file_size);

    while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, file)) > 0) {
        encryptDecryptBuffer(buffer, bytes_read);
        if (fwrite(buffer, 1, bytes_read, temp_file) != bytes_read) {
            clearLine();  // 清除进度条
            printf("错误: 写入文件失败\n");
            fclose(file);
            fclose(temp_file);
            remove(temp_path);
            return;
        }
        total_bytes_processed += bytes_read;
        displayProgress(path, total_bytes_processed, file_size);
    }

    // 确保最终进度为100%
    displayProgress(path, file_size, file_size);

    fclose(file);
    fclose(temp_file);

    // 替换原文件
    if (remove(path) != 0) {
        clearLine();
        printf("错误: 无法删除原文件\n");
        remove(temp_path);
        return;
    }
    if (rename(temp_path, path) != 0) {
        clearLine();
        printf("错误: 无法重命名临时文件\n");
        return;
    }

    clearLine();  // 清除进度条

    // 如果是解密操作，验证文件完整性
    if (!encrypt) {
        char final_hash[SHA256_STRING_LENGTH];
        calculateFileHash(path, final_hash);
        printf("成功读取原始文件哈希值: %s\n", stored_hash);
        printf("解密后文件哈希值: %s\n", final_hash);
        
        if (strcmp(stored_hash, final_hash) == 0) {
            printf("文件完整性验证: 成功 ✓\n");
        } else {
            printf("文件完整性验证: 失败 ✗\n");
            printf("警告: 解密后的文件与原始文件不匹配！\n");
        }
    } else {
        printf("原始文件哈希值: %s\n", original_hash);
    }

    printf("%s 文件%s成功 (总大小: %.2f MB)\n", 
           path, 
           encrypt ? "加密" : "解密", 
           (double)file_size / MEGABYTE);
}

void processDirectory(const char* path, int encrypt) {
    DIR* dir = opendir(path);
    if (!dir) {
        printf("错误: 无法打开目录 %s\n", path);
        return;
    }

    struct dirent* entry;
    char full_path[1024];

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        snprintf(full_path, sizeof(full_path), "%s/%s", path, entry->d_name);

        struct stat path_stat;
        if (stat(full_path, &path_stat) == 0) {
            if (S_ISREG(path_stat.st_mode)) {
                processFile(full_path, encrypt);
            } else if (S_ISDIR(path_stat.st_mode)) {
                processDirectory(full_path, encrypt);
            }
        }
    }

    closedir(dir);
    printf("目录 %s 处理完成\n", path);
}

void encryptDecryptBuffer(unsigned char* buffer, size_t size) {
    for (size_t i = 0; i < size; i++) {
        buffer[i] ^= KEY;  // 使用异或运算进行简单的加密/解密
    }
}

// 清除当前行
void clearLine(void) {
    // 使用ANSI转义序列清除当前行
    printf("\033[2K\r");
    fflush(stdout);
}

// 显示进度条
void displayProgress(const char* filename, size_t current, size_t total) {
    static size_t last_percent = 0;
    float progress = (float)current / total;
    size_t current_percent = (size_t)(progress * 100);

    // 每1%更新一次显示
    if (current_percent == last_percent && current != total) {
        return;
    }
    last_percent = current_percent;

    const int bar_width = PROGRESS_BAR_WIDTH;
    int pos = bar_width * progress;

    // 使用字符串缓冲区构建输出
    char progress_bar[256] = {0};
    char bar_content[PROGRESS_BAR_WIDTH + 1] = {0};
    
    // 构建进度条内容
    for (int i = 0; i < bar_width; i++) {
        bar_content[i] = (i < pos) ? '=' : (i == pos ? '>' : ' ');
    }
    bar_content[bar_width] = '\0';

    // 格式化完整的进度信息
    snprintf(progress_bar, sizeof(progress_bar), 
             "%s: [%s] %3.1f%% (%5.2f/%5.2f MB)",
             filename,
             bar_content,
             progress * 100.0,
             (double)current / MEGABYTE,
             (double)total / MEGABYTE);

    // 清除当前行并显示进度
    clearLine();
    printf("%s", progress_bar);
    fflush(stdout);
}

// 计算文件的SHA-256哈希值
void calculateFileHash(const char* path, char* hash_str) {
    FILE* file = fopen(path, "rb");
    if (!file) {
        strcpy(hash_str, "无法计算哈希值");
        return;
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        strcpy(hash_str, "无法初始化哈希上下文");
        fclose(file);
        return;
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        strcpy(hash_str, "无法初始化SHA-256");
        EVP_MD_CTX_free(ctx);
        fclose(file);
        return;
    }

    unsigned char buffer[BUFFER_SIZE];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, file)) > 0) {
        if (EVP_DigestUpdate(ctx, buffer, bytes_read) != 1) {
            strcpy(hash_str, "计算哈希值时出错");
            EVP_MD_CTX_free(ctx);
            fclose(file);
            return;
        }
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    if (EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1) {
        strcpy(hash_str, "完成哈希计算时出错");
        EVP_MD_CTX_free(ctx);
        fclose(file);
        return;
    }

    EVP_MD_CTX_free(ctx);
    fclose(file);
    
    bytesToHexString(hash, hash_str, hash_len);
}

// 将字节数组转换为十六进制字符串
void bytesToHexString(const unsigned char* bytes, char* hex_str, int len) {
    for (int i = 0; i < len; i++) {
        sprintf(hex_str + (i * 2), "%02x", bytes[i]);
    }
    hex_str[len * 2] = '\0';
}

// 检查文件是否已经被加密
int isFileEncrypted(const char* path) {
    FILE* file = fopen(path, "rb");
    if (!file) {
        printf("错误: 无法打开文件检查加密状态\n");
        return 0;
    }

    char header[32] = {0};
    size_t header_size = strlen(HASH_HEADER_MAGIC);
    size_t read_size = fread(header, 1, header_size, file);
    fclose(file);

    if (read_size != header_size) {
        printf("错误: 文件太小或读取失败\n");
        return 0;
    }

    return strncmp(header, HASH_HEADER_MAGIC, header_size) == 0;
}

// 从加密文件中读取原始哈希值
int readHashFromFile(const char* path, char* hash) {
    FILE* file = fopen(path, "rb");
    if (!file) {
        printf("错误: 无法打开文件进行哈希值读取\n");
        return 0;
    }

    // 读取并验证头部魔数
    char header[32] = {0};
    size_t header_size = strlen(HASH_HEADER_MAGIC);
    if (fread(header, 1, header_size, file) != header_size) {
        printf("错误: 无法读取文件头部\n");
        fclose(file);
        return 0;
    }

    if (strncmp(header, HASH_HEADER_MAGIC, header_size) != 0) {
        printf("错误: 文件头部格式不正确 (预期: %s, 实际: %.*s)\n", 
               HASH_HEADER_MAGIC, (int)header_size, header);
        fclose(file);
        return 0;
    }

    // 读取哈希值
    memset(hash, 0, SHA256_STRING_LENGTH);
    char hash_buffer[SHA256_STRING_LENGTH] = {0};
    if (fread(hash_buffer, 1, SHA256_STRING_LENGTH - 1, file) != SHA256_STRING_LENGTH - 1) {
        printf("错误: 无法读取完整的哈希值\n");
        fclose(file);
        return 0;
    }
    strncpy(hash, hash_buffer, SHA256_STRING_LENGTH - 1);
    hash[SHA256_STRING_LENGTH - 1] = '\0';

    // 读取并验证尾部魔数
    char footer[32] = {0};
    size_t footer_size = strlen(HASH_FOOTER_MAGIC);
    if (fread(footer, 1, footer_size, file) != footer_size) {
        printf("错误: 无法读取文件尾部\n");
        fclose(file);
        return 0;
    }

    if (strncmp(footer, HASH_FOOTER_MAGIC, footer_size) != 0) {
        printf("错误: 文件尾部格式不正确 (预期: %s, 实际: %.*s)\n", 
               HASH_FOOTER_MAGIC, (int)footer_size, footer);
        fclose(file);
        return 0;
    }

    fclose(file);
    return 1;
}
