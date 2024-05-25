#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <gcrypt.h>
#include <sys/stat.h>
#include <sys/socket.h> // For socket-related functions
#include <netinet/in.h> // For internet address structures
#include <arpa/inet.h>  // For manipulating IP addresses

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
    print_hex_ln("HMAC: ", hmac, HMAC_SIZE);

    gcry_md_close(handle);
}


unsigned char *encrypt_file_network_mode(char *input_file, int *filesize, unsigned char *hmac_key, uint64_t *ctxtlen) {
    FILE *input = fopen(input_file, "rb");
    if (!input) {
        perror("Failed to open input file");
        exit(EXIT_FAILURE);
    }
    struct stat st2;
    stat(input_file, &st2);
    *filesize = st2.st_size;

    // Prompt user for password
    char password[20];
    printf("Enter password: ");
    scanf("%20s", password);

    char *salt = "professor-daveti";

    // Compute key from password using PBKDF2
    unsigned char *key_buffer = (unsigned char *)malloc(32);
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

    // Set up encryption context
    gcry_cipher_hd_t handle;
    gcry_cipher_open(&handle, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, GCRY_CIPHER_CBC_CTS);
    gcry_cipher_setkey(handle, key_buffer, 32);
    gcry_cipher_setiv(handle, iv, sizeof(iv));

    // Read input file, encrypt data
    unsigned char *cipher_text;
    cipher_text = (unsigned char *) malloc(*filesize * sizeof(unsigned char));
    fread(cipher_text, sizeof(unsigned char), *filesize, input);
    
    gcry_cipher_encrypt(handle, cipher_text, *filesize, NULL, 0);
    *ctxtlen = *filesize;

    // Calculate HMAC of the encrypted data
    char hmac_input[sizeof(iv) + *filesize];
    memcpy(hmac_input, iv, sizeof(iv));
    memcpy(hmac_input + sizeof(iv), cipher_text, *filesize);
    compute_hmac(hmac_input, sizeof(iv) + *filesize, key_buffer, (char *)hmac_key);

    // Finalize libgcrypt and close files
    gcry_cipher_final(handle);
    gcry_cipher_close(handle);
    fclose(input);

    printf("Encryption completed successfully\n");
    

    return cipher_text;
    
}
unsigned char *encrypt_file(char *input_file, int *filesize, unsigned char *hmac_key) {
    FILE *input = fopen(input_file, "rb");
    if (!input) {
        perror("Failed to open input file");
        exit(EXIT_FAILURE);
    }
    struct stat st2;
    stat(input_file, &st2);
    *filesize = st2.st_size;

    // Prompt user for password
    char password[20];
    printf("Enter password: ");
    scanf("%s", password);

    char *salt = "professor-daveti";

    // Compute key from password using PBKDF2
    unsigned char *key_buffer = (unsigned char *)malloc(32);
    gcry_kdf_derive(password, strlen(password), GCRY_KDF_PBKDF2, GCRY_MD_SHA512,
                   salt, strlen(salt), 4096, 32, key_buffer);
    
    printf("Key : ");
    int i;
	for (i = 0; i < 32; i++) {
		printf("%02X ", key_buffer[i]);
	}
	printf("\n");

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

    // Set up encryption context
    gcry_cipher_hd_t handle;
    gcry_cipher_open(&handle, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, GCRY_CIPHER_CBC_CTS);
    gcry_cipher_setkey(handle, key_buffer, 32);
    gcry_cipher_setiv(handle, iv, sizeof(iv));

    // Read input file, encrypt data
    unsigned char *cipher_text;
    cipher_text = (unsigned char *) malloc(*filesize * sizeof(unsigned char));
    fread(cipher_text, sizeof(unsigned char), *filesize, input);
    
    gcry_cipher_encrypt(handle, cipher_text, *filesize, NULL, 0);
    

    // Calculate HMAC of the encrypted data
    char hmac_input[sizeof(iv) + *filesize];
    memcpy(hmac_input, iv, sizeof(iv));
    memcpy(hmac_input + sizeof(iv), cipher_text, *filesize);
    compute_hmac(hmac_input, sizeof(iv) + *filesize, key_buffer, (char *)hmac_key);

    // Finalize libgcrypt and close files
    gcry_cipher_final(handle);
    gcry_cipher_close(handle);
    fclose(input);

    printf("Encryption completed successfully\n");
    

    return cipher_text;
    
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input file> [-d <output IP-addr:port>] [-l]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    char *input_file = argv[1];
    char *output_file = NULL;
    char *password = NULL;
    int local_mode = 0;
    int network_mode = 0;
    char *remote_address = NULL;
    int port = -1;
    char *plain_text_file_name = argv[1];
    //printf("remoteddres is : %s", argv[3]);

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-d") == 0) {
            network_mode = 1;
            if (argc > i + 1) {
                remote_address = strtok(argv[i + 1], ":"); // Extract IP address
                printf("remoteddres is : %s", remote_address);
                char *port_str = strtok(NULL, ":"); // Extract port number
                
                if (port_str) {
                    port = atoi(port_str);
                } else {
                    fprintf(stderr, "Error: Invalid port number\n");
                    exit(EXIT_FAILURE);
                }
                i++;
                
            } else {
                fprintf(stderr, "Error: Missing argument for -d option\n");
                exit(EXIT_FAILURE);
            }
        } else if (strcmp(argv[i], "-l") == 0) {
            local_mode = 1;
        } else {
            fprintf(stderr, "Error: Invalid option %s\n", argv[i]);
            exit(EXIT_FAILURE);
        }
    }

    if (network_mode && local_mode) {
        fprintf(stderr, "Error: Cannot specify both -d and -l options\n");
        exit(EXIT_FAILURE);
    }

    // network_mode = 0;
    // local_mode = 1;
    if (network_mode) 
    {    
        // Handle network mode
        // Implement sending encrypted file to remote daemon
        
        int enc_text_size;
        //int* enc_with_hmsize;
        uint64_t ctxtlen;
        unsigned char hmac[HMAC_SIZE]; // Define HMAC key
        unsigned char *cipher_text = encrypt_file_network_mode(plain_text_file_name, &enc_text_size, hmac, &ctxtlen);
        print_hex_ln("HMAC returned from encrypt function: ", hmac, HMAC_SIZE);


        uint32_t file_nam_len = strlen(plain_text_file_name);

        // Connect to remote host
        int sock, client_fd;
        struct sockaddr_in servaddr;
        struct sockaddr_in dest_addr;

        if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
            printf("\n Socket creation error \n");
            exit(1);
        }

        servaddr.sin_family = AF_INET;
        servaddr.sin_port = htons(port);
        printf("port is: \n %d", port);
        
        if (inet_pton(AF_INET, remote_address, &servaddr.sin_addr)< 0) {
            printf("\nInvalid address or Address not supported \n:%s", remote_address);
            exit(1);
        }

        if ((client_fd = connect(sock, (struct sockaddr*)&servaddr,sizeof(servaddr)))< 0) { 
            printf("\nConnection Failed \n");
            exit(1);
        }

        printf("File length: %d", ctxtlen);

        uint32_t file_nam_len_htonl = htonl(file_nam_len);
        uint32_t ctxtlen_htonl = htonl(ctxtlen);
        // Send filename, encrypted data, and HMAC over the network
        write(sock, &file_nam_len_htonl, sizeof(uint32_t)); //send file name's length
        write(sock, plain_text_file_name, strlen(plain_text_file_name));//send file name
        write(sock, &ctxtlen_htonl, sizeof(uint32_t)); //send file-contents length
        write(sock, cipher_text, ctxtlen); //send ciphertext
        // print_hex_ln("Cipher text: ", cipher_text, ctxtlen);
        printf("Cipher text length: %d\n", ctxtlen);
        write(sock, hmac, HMAC_SIZE); //send hmac
        print_hex_ln("Sent HMAC: ", hmac, HMAC_SIZE);
        //printf("sent size of %d:", );
        printf("Written ciphertext succesfully:");

        // Close the socket
        close(client_fd);
    }

    if (local_mode) {
        // Handle local mode
        // Encrypt file and write to local disk
        int filesize;
        unsigned char hmac_key[HMAC_SIZE]; // Define HMAC key
        unsigned char *cipher_text = encrypt_file(input_file, &filesize, hmac_key);

        // Write encrypted data and HMAC to output file
        output_file = strcat(input_file, ".pur");
        FILE *output = fopen(output_file, "wb");
        if (!output) {
            perror("Failed to open output file");
            exit(EXIT_FAILURE);
        }
        fwrite(cipher_text, 1, filesize, output);
        fwrite(hmac_key, 1, HMAC_SIZE, output); // Write HMAC to file
        fclose(output);
        free(cipher_text);
    }

    return 0;
}
