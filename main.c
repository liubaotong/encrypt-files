#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/evp.h>

#ifdef _WIN32
#include <windows.h>
#define S_ISREG(m) (((m) & S_IFMT) == S_IFREG)
#define S_ISDIR(m) (((m) & S_IFMT) == S_IFDIR)
#else
#include <dirent.h>
#endif

#define BUFFER_SIZE 4096
#define KEY 0xAB  // Simple encryption key
#define MEGABYTE (1024.0 * 1024.0)
#define PROGRESS_BAR_WIDTH 20
#define SHA256_STRING_LENGTH 65  // 64 chars plus null terminator
#define HASH_HEADER_MAGIC "ENCRYPTED_FILE_"
#define HASH_FOOTER_MAGIC "_END_OF_HASH"

// Function declarations
void processFile(const char* path, int encrypt);
void processDirectory(const char* path, int encrypt);
void encryptDecryptBuffer(unsigned char* buffer, size_t size);
void displayProgress(const char* filename, size_t current, size_t total);
void clearLine(void);
void calculateFileHash(const char* path, char* hash_str);
int readHashFromFile(const char* path, char* hash);
int isFileEncrypted(const char* path);
void bytesToHexString(const unsigned char* bytes, int len, char* hex_str);

// Disable output buffering
void disableBuffering() {
#ifdef _WIN32
    // Set console mode for Windows
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode;
    GetConsoleMode(hOut, &mode);
    SetConsoleMode(hOut, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
#endif
    setvbuf(stdout, NULL, _IONBF, 0);
}

int main(int argc, char* argv[]) {
    // Initialize output settings
    disableBuffering();

    if (argc != 3) {
        printf("Usage:\n");
        printf("Encrypt: %s -e <file or directory path>\n", argv[0]);
        printf("Decrypt: %s -d <file or directory path>\n", argv[0]);
        return 1;
    }

    int encrypt = strcmp(argv[1], "-e") == 0;
    if (!encrypt && strcmp(argv[1], "-d") != 0) {
        printf("Error: Invalid operation parameter\n");
        return 1;
    }

    struct stat path_stat;
    if (stat(argv[2], &path_stat) != 0) {
        printf("Error: Cannot access specified file or directory\n");
        return 1;
    }

    if (S_ISREG(path_stat.st_mode)) {
        // Process single file
        processFile(argv[2], encrypt);
    } else if (S_ISDIR(path_stat.st_mode)) {
        // Process directory
        processDirectory(argv[2], encrypt);
    } else {
        printf("Error: Unsupported file type\n");
        return 1;
    }

    return 0;
}

void processFile(const char* path, int encrypt) {
    char original_hash[SHA256_STRING_LENGTH] = {0};
    char stored_hash[SHA256_STRING_LENGTH] = {0};
    int is_encrypted = isFileEncrypted(path);

    // For decryption, read the stored original hash first
    if (!encrypt) {
        if (!is_encrypted) {
            printf("Error: File is not encrypted or format is incorrect\n");
            return;
        }
        if (!readHashFromFile(path, stored_hash)) {
            printf("Error: Cannot read original hash, file may be corrupted\n");
            return;
        }
    } else {
        if (is_encrypted) {
            printf("Error: File is already encrypted\n");
            return;
        }
        // Calculate hash of original file
        calculateFileHash(path, original_hash);
    }

    FILE* file = fopen(path, "rb");
    if (!file) {
        printf("Error: Cannot open file %s\n", path);
        return;
    }

    // Get original file size
    fseek(file, 0, SEEK_END);
    size_t file_size = (size_t)ftell(file);
    if (!encrypt) {
        // For decryption, subtract hash header and footer size
        file_size -= (strlen(HASH_HEADER_MAGIC) + SHA256_STRING_LENGTH - 1 + strlen(HASH_FOOTER_MAGIC));
    }
    fseek(file, 0, SEEK_SET);

    // Create temporary file
    char temp_path[1024];
    snprintf(temp_path, sizeof(temp_path), "%s.tmp", path);
    FILE* temp_file = fopen(temp_path, "wb");
    if (!temp_file) {
        printf("Error: Cannot create temporary file\n");
        fclose(file);
        return;
    }

    // For encryption, write hash first
    if (encrypt) {
        size_t written = 0;
        written += fprintf(temp_file, "%s", HASH_HEADER_MAGIC);
        written += fwrite(original_hash, 1, SHA256_STRING_LENGTH - 1, temp_file);
        written += fprintf(temp_file, "%s", HASH_FOOTER_MAGIC);

        if (written != strlen(HASH_HEADER_MAGIC) + SHA256_STRING_LENGTH - 1 + strlen(HASH_FOOTER_MAGIC)) {
            printf("Error: Failed to write hash\n");
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
        // Skip hash header for decryption
        size_t header_offset = strlen(HASH_HEADER_MAGIC) + SHA256_STRING_LENGTH - 1 + strlen(HASH_FOOTER_MAGIC);
        if (fseek(file, (long)header_offset, SEEK_SET) != 0) {
            printf("Error: Cannot skip file header\n");
            fclose(file);
            fclose(temp_file);
            remove(temp_path);
            return;
        }
    }

    // Show initial progress
    displayProgress(path, 0, file_size);

    while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, file)) > 0) {
        encryptDecryptBuffer(buffer, bytes_read);
        if (fwrite(buffer, 1, bytes_read, temp_file) != bytes_read) {
            clearLine();
            printf("Error: Failed to write file\n");
            fclose(file);
            fclose(temp_file);
            remove(temp_path);
            return;
        }
        total_bytes_processed += bytes_read;
        displayProgress(path, total_bytes_processed, file_size);
    }

    // Ensure final progress is 100%
    displayProgress(path, file_size, file_size);

    fclose(file);
    fclose(temp_file);

    // Replace original file
    if (remove(path) != 0) {
        clearLine();
        printf("Error: Cannot delete original file\n");
        remove(temp_path);
        return;
    }
    if (rename(temp_path, path) != 0) {
        clearLine();
        printf("Error: Cannot rename temporary file\n");
        return;
    }

    clearLine();

    // For decryption, verify file integrity
    if (!encrypt) {
        char final_hash[SHA256_STRING_LENGTH];
        calculateFileHash(path, final_hash);
        printf("Successfully read original file hash: %s\n", stored_hash);
        printf("Decrypted file hash: %s\n", final_hash);
        
        if (strcmp(stored_hash, final_hash) == 0) {
            printf("File integrity verification: Success\n");
        } else {
            printf("File integrity verification: Failed\n");
            printf("Warning: Decrypted file does not match original!\n");
        }
    } else {
        printf("Original file hash: %s\n", original_hash);
    }

    printf("%s file %s successfully (Total size: %.2f MB)\n", 
           path, 
           encrypt ? "encrypted" : "decrypted", 
           (double)file_size / MEGABYTE);
}

void processDirectory(const char* path, int encrypt) {
#ifdef _WIN32
    WIN32_FIND_DATAA findData;
    char searchPath[MAX_PATH];
    char filePath[MAX_PATH];
    HANDLE hFind;

    // Construct search path
    snprintf(searchPath, sizeof(searchPath), "%s\\*", path);
    
    hFind = FindFirstFileA(searchPath, &findData);
    if (hFind == INVALID_HANDLE_VALUE) {
        printf("Error: Cannot open directory %s\n", path);
        return;
    }

    do {
        // Skip . and ..
        if (strcmp(findData.cFileName, ".") == 0 || strcmp(findData.cFileName, "..") == 0)
            continue;

        // Construct full file path
        snprintf(filePath, sizeof(filePath), "%s\\%s", path, findData.cFileName);

        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            // Recursively process subdirectories
            processDirectory(filePath, encrypt);
        } else {
            // Process file
            processFile(filePath, encrypt);
        }
    } while (FindNextFileA(hFind, &findData));

    FindClose(hFind);
#else
    DIR* dir = opendir(path);
    if (!dir) {
        printf("Error: Cannot open directory %s\n", path);
        return;
    }

    struct dirent* entry;
    char filePath[1024];
    struct stat statbuf;

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        snprintf(filePath, sizeof(filePath), "%s/%s", path, entry->d_name);
        
        if (stat(filePath, &statbuf) == 0) {
            if (S_ISDIR(statbuf.st_mode)) {
                processDirectory(filePath, encrypt);
            } else {
                processFile(filePath, encrypt);
            }
        }
    }

    closedir(dir);
#endif
    printf("Directory %s processed\n", path);
}

void encryptDecryptBuffer(unsigned char* buffer, size_t size) {
    for (size_t i = 0; i < size; i++) {
        buffer[i] ^= KEY;  // Simple encryption/decryption using XOR
    }
}

// Clear current line
void clearLine(void) {
    // Use ANSI escape sequence to clear current line
    printf("\033[2K\r");
    fflush(stdout);
}

// Display progress bar
void displayProgress(const char* filename, size_t current, size_t total) {
    static size_t last_percent = 0;
    float progress = (float)current / total;
    size_t current_percent = (size_t)(progress * 100);

    // Update display every 1%
    if (current_percent == last_percent && current != total) {
        return;
    }
    last_percent = current_percent;

    const int bar_width = PROGRESS_BAR_WIDTH;
    int pos = (int)(bar_width * progress);

    // Construct output string
    char progress_bar[256] = {0};
    char bar_content[PROGRESS_BAR_WIDTH + 1] = {0};
    
    // Construct progress bar content
    for (int i = 0; i < bar_width; i++) {
        bar_content[i] = (i < pos) ? '=' : (i == pos ? '>' : ' ');
    }
    bar_content[bar_width] = '\0';

    // Format complete progress information
    snprintf(progress_bar, sizeof(progress_bar), 
             "%s: [%s] %3.1f%% (%5.2f/%5.2f MB)",
             filename,
             bar_content,
             progress * 100.0,
             (double)current / MEGABYTE,
             (double)total / MEGABYTE);

    // Clear current line and display progress
    clearLine();
    printf("%s", progress_bar);
    fflush(stdout);
}

// Calculate SHA-256 hash of file
void calculateFileHash(const char* path, char* hash_str) {
    FILE* file = fopen(path, "rb");
    if (!file) {
        strncpy(hash_str, "Cannot calculate hash", SHA256_STRING_LENGTH - 1);
        hash_str[SHA256_STRING_LENGTH - 1] = '\0';
        return;
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        strncpy(hash_str, "Cannot initialize hash context", SHA256_STRING_LENGTH - 1);
        hash_str[SHA256_STRING_LENGTH - 1] = '\0';
        fclose(file);
        return;
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        strncpy(hash_str, "Cannot initialize SHA-256", SHA256_STRING_LENGTH - 1);
        hash_str[SHA256_STRING_LENGTH - 1] = '\0';
        EVP_MD_CTX_free(ctx);
        fclose(file);
        return;
    }

    unsigned char buffer[BUFFER_SIZE];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, file)) > 0) {
        if (EVP_DigestUpdate(ctx, buffer, bytes_read) != 1) {
            strncpy(hash_str, "Error calculating hash", SHA256_STRING_LENGTH - 1);
            hash_str[SHA256_STRING_LENGTH - 1] = '\0';
            EVP_MD_CTX_free(ctx);
            fclose(file);
            return;
        }
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    if (EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1) {
        strncpy(hash_str, "Error finalizing hash", SHA256_STRING_LENGTH - 1);
        hash_str[SHA256_STRING_LENGTH - 1] = '\0';
        EVP_MD_CTX_free(ctx);
        fclose(file);
        return;
    }

    EVP_MD_CTX_free(ctx);
    fclose(file);
    
    bytesToHexString(hash, hash_len, hash_str);
}

// Convert byte array to hexadecimal string
void bytesToHexString(const unsigned char* bytes, int len, char* hex_str) {
    for (int i = 0; i < len; i++) {
        snprintf(hex_str + (i * 2), 3, "%02x", bytes[i]);
    }
    hex_str[len * 2] = '\0';
}

// Check if file is already encrypted
int isFileEncrypted(const char* path) {
    FILE* file = fopen(path, "rb");
    if (!file) {
        printf("Error: Cannot open file to check encryption status\n");
        return 0;
    }

    char header[32] = {0};
    size_t header_size = strlen(HASH_HEADER_MAGIC);
    size_t read_size = fread(header, 1, header_size, file);
    fclose(file);

    if (read_size != header_size) {
        printf("Error: File is too small or read failed\n");
        return 0;
    }

    return strncmp(header, HASH_HEADER_MAGIC, header_size) == 0;
}

// Read original hash from encrypted file
int readHashFromFile(const char* path, char* hash) {
    FILE* file = fopen(path, "rb");
    if (!file) {
        printf("Error: Cannot open file to read hash\n");
        return 0;
    }

    // Read and verify header magic
    char header[32] = {0};
    size_t header_size = strlen(HASH_HEADER_MAGIC);
    if (fread(header, 1, header_size, file) != header_size) {
        printf("Error: Cannot read file header\n");
        fclose(file);
        return 0;
    }

    if (strncmp(header, HASH_HEADER_MAGIC, header_size) != 0) {
        printf("Error: File header format is incorrect (expected: %s, actual: %.*s)\n", 
               HASH_HEADER_MAGIC, (int)header_size, header);
        fclose(file);
        return 0;
    }

    // Read hash
    memset(hash, 0, SHA256_STRING_LENGTH);
    char hash_buffer[SHA256_STRING_LENGTH] = {0};
    if (fread(hash_buffer, 1, SHA256_STRING_LENGTH - 1, file) != SHA256_STRING_LENGTH - 1) {
        printf("Error: Cannot read complete hash\n");
        fclose(file);
        return 0;
    }
    strncpy(hash, hash_buffer, SHA256_STRING_LENGTH - 1);
    hash[SHA256_STRING_LENGTH - 1] = '\0';

    // Read and verify footer magic
    char footer[32] = {0};
    size_t footer_size = strlen(HASH_FOOTER_MAGIC);
    if (fread(footer, 1, footer_size, file) != footer_size) {
        printf("Error: Cannot read file footer\n");
        fclose(file);
        return 0;
    }

    if (strncmp(footer, HASH_FOOTER_MAGIC, footer_size) != 0) {
        printf("Error: File footer format is incorrect (expected: %s, actual: %.*s)\n", 
               HASH_FOOTER_MAGIC, (int)footer_size, footer);
        fclose(file);
        return 0;
    }

    fclose(file);
    return 1;
}
