#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

void print_hex_dump(const char *label, const unsigned char *data, size_t len) {
    printf("%s (%zu bytes):\n", label, len);
    for (size_t i = 0; i < len; i++) {
        printf("%02x ", data[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n\n");
}

void analyze_certificate_message(const unsigned char *data, size_t len) {
    printf("=== Certificate Message Analysis ===\n");
    print_hex_dump("Raw Certificate Message", data, len);
    
    if (len < 7) {
        printf("Message too short\n");
        return;
    }
    
    // Parse TLS 1.3 Certificate message structure
    unsigned char msg_type = data[0];
    unsigned int total_len = (data[1] << 16) | (data[2] << 8) | data[3];
    unsigned char context = data[4];
    unsigned int cert_list_len = (data[5] << 16) | (data[6] << 8) | data[7];
    
    printf("Message Type: 0x%02x (Certificate = 11)\n", msg_type);
    printf("Total Length: %u bytes\n", total_len);
    printf("Context: %u\n", context);
    printf("Certificate List Length: %u bytes\n", cert_list_len);
    
    if (len < 8 + cert_list_len) {
        printf("Message truncated\n");
        return;
    }
    
    const unsigned char *cert_list = data + 8;
    size_t offset = 0;
    int cert_count = 0;
    
    while (offset < cert_list_len && cert_count < 10) {
        if (offset + 3 > cert_list_len) {
            printf("Certificate list truncated\n");
            break;
        }
        
        unsigned int cert_len = (cert_list[offset] << 16) | (cert_list[offset + 1] << 8) | cert_list[offset + 2];
        printf("\nCertificate %d:\n", cert_count);
        printf("  Length: %u bytes\n", cert_len);
        printf("  Offset: %zu\n", offset);
        
        if (offset + 3 + cert_len > cert_list_len) {
            printf("  Certificate data truncated\n");
            break;
        }
        
        print_hex_dump("  Certificate Data", cert_list + offset + 3, cert_len);
        
        offset += 3 + cert_len;
        
        // Check for TLS 1.3 extensions
        if (offset + 2 <= cert_list_len) {
            unsigned int ext_len = (cert_list[offset] << 8) | cert_list[offset + 1];
            printf("  Extensions Length: %u bytes\n", ext_len);
            
            if (offset + 2 + ext_len <= cert_list_len) {
                print_hex_dump("  Extensions", cert_list + offset + 2, ext_len);
                offset += 2 + ext_len;
            } else {
                printf("  Extensions truncated\n");
                break;
            }
        }
        
        cert_count++;
        
        // Check for dual certificate delimiter
        if (offset + 3 <= cert_list_len) {
            if (cert_list[offset] == 0x00 && cert_list[offset + 1] == 0x00 && cert_list[offset + 2] == 0x00) {
                printf("  *** DUAL CERTIFICATE DELIMITER DETECTED ***\n");
                offset += 3;
            }
        }
    }
    
    printf("\n=== End Analysis ===\n");
}

int main() {
    // This is a placeholder for the actual certificate message data
    // In a real implementation, you would capture this from the TLS handshake
    
    printf("Dual Certificate Message Analysis Tool\n");
    printf("=====================================\n\n");
    
    // Example of how to use the analysis function
    // unsigned char cert_msg[] = { /* captured certificate message */ };
    // analyze_certificate_message(cert_msg, sizeof(cert_msg));
    
    printf("To use this tool:\n");
    printf("1. Capture the Certificate message from a TLS handshake\n");
    printf("2. Pass the raw bytes to analyze_certificate_message()\n");
    printf("3. The tool will parse and display the structure\n");
    
    return 0;
} 