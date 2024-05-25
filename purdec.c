#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <gcrypt.h>
#include <sys/stat.h>
#include <sys/socket.h> // For socket-related functions
#include <netinet/in.h> // For internet address structures
#include <arpa/inet.h>  // For manipulating IP addresses
#include <asm-generic/socket.h>
#include <ctype.h>

#define MAX_BUFFER_SIZE 1024
#define HMAC_SIZE 16

void print_hex_ln(const char *message, unsigned char *data, int length) {
    int i;
    printf("%s", message);
    for(i=0; i<length; i++) {
        if(i%16 == 0) {
        printf("\n");
        }
        printf("%02x ", data[i]);
    }
    printf("\n");
}

void compute_hmac(const char *data, size_t data_len, unsigned char *key, char *hmac) {
    gcry_md_hd_t handle;
    gcry_md_open(&handle, GCRY_MD_SHA256, GCRY_MD_FLAG_HMAC);

    gcry_md_setkey(handle, key, HMAC_SIZE);
    gcry_md_write(handle, data, data_len);
    memcpy(hmac, gcry_md_read(handle, 0), HMAC_SIZE);
    
    gcry_md_close(handle);
}

char *decrypt_filel(char *input_file, int *filesize) {


    FILE *input = fopen(input_file, "rb");
    if (!input) {
        perror("Failed to open input file");
        exit(EXIT_FAILURE);
    }
    struct stat st;
    stat(input_file, &st);
    *filesize = st.st_size - HMAC_SIZE; // Exclude HMAC size from file size

    // Prompt user for password
    char password[20];
    printf("Enter password: ");
    scanf("%s", password);

    char *salt = "professor-daveti";

    // Compute key from password using PBKDF2
    char *key_buffer = (char *)malloc(32);
    gcry_kdf_derive(password, strlen(password), GCRY_KDF_PBKDF2, GCRY_MD_SHA512,
                   salt, strlen(salt), 4096, 32, key_buffer);
    
    unsigned char iv[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

    
    // Initialize libgcrypt
    if (!gcry_check_version(GCRYPT_VERSION)) {
        fprintf(stderr, "libgcrypt version mismatch\n");
        exit(EXIT_FAILURE);
    }
    gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN);
    gcry_control(GCRYCTL_INIT_SECMEM, 16384, 0);
    gcry_control(GCRYCTL_RESUME_SECMEM_WARN);
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);

    // Set up decryption context
    gcry_cipher_hd_t handle;
    gcry_cipher_open(&handle, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, GCRY_CIPHER_CBC_CTS);
    gcry_cipher_setkey(handle, key_buffer, 32);
    gcry_cipher_setiv(handle, iv, sizeof(iv));

    // Read input file, including HMAC
    char *cipher_text_with_hmac;
    cipher_text_with_hmac = (char *) malloc((*filesize + HMAC_SIZE) * sizeof(char));
    fread(cipher_text_with_hmac, sizeof(char), *filesize + HMAC_SIZE, input);
    fclose(input);

    // Extract HMAC from the end of the file
    char *hmac_received = cipher_text_with_hmac + *filesize;
    
    // Calculate HMAC of the encrypted data
    char hmac_input[*filesize + sizeof(iv)];
    memcpy(hmac_input, iv, sizeof(iv));
    memcpy(hmac_input + sizeof(iv), cipher_text_with_hmac, *filesize);
    
    char hmac_calculated[HMAC_SIZE];
    compute_hmac(hmac_input, *filesize + sizeof(iv), key_buffer, hmac_calculated);

    // Verify HMAC
    if (memcmp(hmac_received, hmac_calculated, HMAC_SIZE) != 0) {
        fprintf(stderr, "Error: HMAC verification failed. File may have been tampered with.\n");
        exit(EXIT_FAILURE);
    }

    // Decrypt data
    gcry_cipher_decrypt(handle, cipher_text_with_hmac, *filesize, NULL, 0);

    // Finalize libgcrypt
    gcry_cipher_final(handle);
    gcry_cipher_close(handle);

    printf("Decryption completed successfully\n");

    // Return decrypted data without HMAC
    return cipher_text_with_hmac;
}

char *decrypt_file(unsigned char *file_buf, size_t filesize, unsigned char *hmac) {

    printf("In decrypt: ");

    // Prompt user for password
    char password[20];
    printf("Enter password: ");
    scanf("%20s", password);

    char *salt = "professor-daveti";

    // Compute key from password using PBKDF2
    char *key_buffer = (char *)malloc(32);
    gcry_kdf_derive(password, strlen(password), GCRY_KDF_PBKDF2, GCRY_MD_SHA512,
                   salt, strlen(salt), 4096, 32, key_buffer);
    print_hex_ln("Key: ", key_buffer, 32);
    
    unsigned char iv[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

    
    // Initialize libgcrypt
    if (!gcry_check_version(GCRYPT_VERSION)) {
        fprintf(stderr, "libgcrypt version mismatch\n");
        exit(EXIT_FAILURE);
    }
    gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN);
    gcry_control(GCRYCTL_INIT_SECMEM, 16384, 0);
    gcry_control(GCRYCTL_RESUME_SECMEM_WARN);
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);

    // Set up decryption context
    gcry_cipher_hd_t handle;
    gcry_cipher_open(&handle, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, GCRY_CIPHER_CBC_CTS);
    gcry_cipher_setkey(handle, key_buffer, 32);
    gcry_cipher_setiv(handle, iv, sizeof(iv));
    
    char hmac_calculated[HMAC_SIZE];
    compute_hmac(file_buf, filesize + sizeof(iv), key_buffer, hmac_calculated);
    print_hex_ln("Computed HMAC: ", hmac_calculated, HMAC_SIZE);

    // // Verify HMAC
    // if (memcmp(hmac, hmac_calculated, HMAC_SIZE) != 0) {
    //     fprintf(stderr, "Error: HMAC verification failed. File may have been tampered with.\n");
    //     exit(EXIT_FAILURE);
    // }

    // Decrypt data
    gcry_cipher_decrypt(handle, file_buf, filesize, NULL, 0);

    // Finalize libgcrypt
    gcry_cipher_final(handle);
    gcry_cipher_close(handle);

    printf("Decryption completed successfully\n");

    // Return decrypted data without HMAC
    return file_buf;
}

void write_to_file(char *file, unsigned char *data, unsigned char *data2, size_t total_bytes_read) {
    printf("to File.");
    FILE *fp = fopen(file, "wb");
    if (!fp) {
        printf("Failed writing to file.\n");
    }
    if (fwrite(data, 1, total_bytes_read, fp) != total_bytes_read) {
        fclose(fp);
        printf("Failed writing to file.\n");
    }
    if (fwrite(data2, 1, HMAC_SIZE, fp) != HMAC_SIZE) {
        fclose(fp);
        printf("Failed writing to file.\n");
    }
    printf("Wrote to File.");
    fclose(fp);
}


int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s [-l <input file>] [<port>]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    char *input_file = NULL;
    char *output_file = NULL;
    char *password = NULL;
    int local_mode = 0;
    int network_mode = 0; // Default to network mode
    char *remote_address = NULL;
    int port = -1;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-l") == 0) {
            local_mode = 1;
            if (argc > i + 1) {
                input_file = argv[i + 1];
                i++;
            } else {
                fprintf(stderr, "Error: Missing argument for -l option\n");
                exit(EXIT_FAILURE);
            }
        } else {
            // Argument is assumed to be port number
            network_mode = 1;
            port = atoi(argv[i]);
        }
    }

    if (local_mode && port != -1) {
        fprintf(stderr, "Error: Port number is not required in local mode\n");
        exit(EXIT_FAILURE);
    }

    if (local_mode && network_mode) {
        fprintf(stderr, "Error: Cannot specify both -l and network mode\n");
        exit(EXIT_FAILURE);
    }

    if (!local_mode && !network_mode) {
        fprintf(stderr, "Error: You must specify either -l or network mode\n");
        exit(EXIT_FAILURE);
    }

    if (network_mode) {
        // Handle network mode
        // Implement receiving encrypted file from remote daemon
        // Create socket

        int server_fd, new_socket, valread;
        struct sockaddr_in address;
        int opt = 1, n;
        int addrlen = sizeof(address);


        // Creating socket file descriptor
        if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
            perror("socket failed");
            exit(EXIT_FAILURE);
        }

        printf("Socket creation successful\n");
        // Forcefully attaching socket to the port 8080
        if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
            perror("setsockopt");
            exit(EXIT_FAILURE);
        }
        printf("a\n");
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = INADDR_ANY;
        address.sin_port = htons(port);

        // Forcefully attaching socket to the port 8080
        if (bind(server_fd, (struct sockaddr*)&address,sizeof(address))< 0) {
            perror("bind failed");
            exit(EXIT_FAILURE);
        }
        printf("b\n");
        if (listen(server_fd, 3) < 0) {
            exit(EXIT_FAILURE);
        }
        printf("c\n");
        printf("Waiting for connections.\n");
        if ((new_socket = accept(server_fd, (struct sockaddr*)&address, (socklen_t*)&addrlen)) < 0) {
            perror("accept");
            exit(EXIT_FAILURE);
        }
        printf("Connected from %s\n", inet_ntoa(address.sin_addr));
  
        int ch=0,curSize=2,padLen=0,contentLen=0;

        // read(new_socket,&ch,1);
        uint32_t temp_file_nam_len;
        read(new_socket, &temp_file_nam_len, sizeof(uint32_t));
        size_t file_nam_len = (size_t)ntohl(temp_file_nam_len);
        printf("File name length: %ld\n", file_nam_len);

        unsigned char *file_name = malloc(file_nam_len);

        // Read the file name.
        read(new_socket, file_name, file_nam_len);
        printf("Received filename: %s\n", file_name);
        
        // Read file length.
        uint32_t temp_file_len;
        ssize_t bytes_read = read(new_socket, &temp_file_len, sizeof(uint32_t));
        size_t file_len = (size_t)ntohl(temp_file_len);
        printf("File length: %ld\n", file_len);

        unsigned char *file_buffer = malloc(file_len);

        size_t total_bytes_read = 0;
        while (total_bytes_read < file_len) {
            // Calculate remaining bytes to read
            size_t remaining_bytes = file_len - total_bytes_read;
            // Determine the chunk size to read
            size_t chunk_size = remaining_bytes > MAX_BUFFER_SIZE ? MAX_BUFFER_SIZE : remaining_bytes;
            
            // Read a chunk of data
            bytes_read = read(new_socket, file_buffer + total_bytes_read, chunk_size);
            if (bytes_read <= 0) {
                perror("Error reading file data");
                exit(EXIT_FAILURE);
            }
            
            // Update the total bytes read
            total_bytes_read += bytes_read;
        }
        printf("Bytes read: %d", total_bytes_read);
        // print_hex_ln("File Buffer: ", file_buffer, total_bytes_read);

        unsigned char hmac[HMAC_SIZE]; // Define HMAC key
        // Read HMAC.
        read(new_socket, &hmac, HMAC_SIZE);
        print_hex_ln("HMAC: ", hmac, HMAC_SIZE);

        close(new_socket);
	    shutdown(server_fd, SHUT_RDWR);
        
        char *plain_text = decrypt_file(file_buffer, total_bytes_read, hmac);

        char *output_file = strdup(file_name);
        FILE *output = fopen(output_file, "wb");
        if (!output) {
            perror("Failed to open output file");
            exit(EXIT_FAILURE);
        }
        fwrite(plain_text, 1, total_bytes_read, output);
        fclose(output);
        free(plain_text);
	}

    if (local_mode) {  
        
        // Remove ".pur" extension from input file name
        char *output_file = strdup(input_file);
        char *dot = strrchr(output_file, '.');
        if (dot && strcmp(dot, ".pur") == 0) {
            *dot = '\0';
        } else {
        fprintf(stderr, "Error: Input file does not have '.pur' extension\n");
        exit(EXIT_FAILURE);
        }


        // Handle local mode
        // Decrypt file and write to local disk
        int filesize;
        char *plain_text = decrypt_filel(input_file, &filesize);

        // Write decrypted data to output file
        output_file = strdup(input_file);
        dot = strrchr(output_file, '.');
        if (dot && strcmp(dot, ".pur") == 0) {
            *dot = '\0';
        }
        FILE *output = fopen(output_file, "wb");
        if (!output) {
            perror("Failed to open output file");
            exit(EXIT_FAILURE);
        }
        fwrite(plain_text, 1, filesize, output);
        fclose(output);
        free(plain_text);
    }

    return 0;
}
