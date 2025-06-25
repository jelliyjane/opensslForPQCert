#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void print_hex_dump(const char *label, const unsigned char *data, size_t len) {
    printf("%s (%zu bytes):\n", label, len);
    for (size_t i = 0; i < len; i++) {
        printf("%02x ", data[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n\n");
}

int main() {
    // Certificate message from the test
    unsigned char cert_msg[] = {
        0x0b, 0x00, 0x07, 0x9b, 0x00, 0x00, 0x07, 0x97, 0x00, 0x03, 0x85, 0x00, 0x03, 0x80, 0x30, 0x82,
        0x03, 0x7c, 0x30, 0x82, 0x02, 0x64, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x2d, 0x50, 0x11,
        // ... (first certificate data)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x09, 0x00, 0x04, 0x04, 0x30, 0x82, 0x04, 0x00, 0x30,
        0x82, 0x02, 0xe8, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x67, 0x07, 0xfa, 0x95, 0xe6, 0x93,
        // ... (second certificate data)
        0x00, 0x00
    };
    
    size_t msg_len = sizeof(cert_msg);
    
    printf("=== Certificate Message Structure Analysis ===\n\n");
    
    // Parse TLS 1.3 Certificate message
    if (msg_len < 7) {
        printf("Message too short\n");
        return 1;
    }
    
    unsigned char msg_type = cert_msg[0];
    unsigned int total_len = (cert_msg[1] << 16) | (cert_msg[2] << 8) | cert_msg[3];
    unsigned char context = cert_msg[4];
    unsigned int cert_list_len = (cert_msg[5] << 16) | (cert_msg[6] << 8) | cert_msg[7];
    
    printf("Message type: 0x%02x (Certificate)\n", msg_type);
    printf("Total length: %u bytes\n", total_len);
    printf("Context: 0x%02x\n", context);
    printf("Certificate list length: %u bytes\n", cert_list_len);
    
    // Parse certificate list
    size_t offset = 8;
    size_t cert_idx = 0;
    
    while (offset < msg_len - 3) {
        if (offset + 3 > msg_len) break;
        
        unsigned int cert_len = (cert_msg[offset] << 16) | (cert_msg[offset + 1] << 8) | cert_msg[offset + 2];
        printf("\nCertificate %zu:\n", cert_idx);
        printf("  Length: %u bytes\n", cert_len);
        printf("  Offset: %zu\n", offset);
        
        if (offset + 3 + cert_len > msg_len) {
            printf("  ERROR: Certificate extends beyond message\n");
            break;
        }
        
        // Check for delimiter after this certificate
        size_t after_cert = offset + 3 + cert_len;
        if (after_cert + 3 <= msg_len) {
            printf("  After certificate bytes: %02x %02x %02x %02x %02x %02x\n",
                   cert_msg[after_cert], cert_msg[after_cert + 1], cert_msg[after_cert + 2],
                   cert_msg[after_cert + 3], cert_msg[after_cert + 4], cert_msg[after_cert + 5]);
            
            if (cert_msg[after_cert] == 0x00 && cert_msg[after_cert + 1] == 0x00 && cert_msg[after_cert + 2] == 0x00) {
                printf("  *** DUAL CERTIFICATE DELIMITER FOUND! ***\n");
                
                // Check what comes after the delimiter
                size_t after_delimiter = after_cert + 3;
                if (after_delimiter + 2 <= msg_len) {
                    unsigned int next_len = (cert_msg[after_delimiter] << 8) | cert_msg[after_delimiter + 1];
                    printf("  After delimiter: length field = %u bytes\n", next_len);
                }
            }
        }
        
        offset = after_cert;
        cert_idx++;
        
        // For TLS 1.3, check for extensions
        if (cert_idx == 1 && offset + 2 <= msg_len) {
            unsigned int extensions_len = (cert_msg[offset] << 8) | cert_msg[offset + 1];
            printf("  TLS 1.3 Extensions length: %u bytes\n", extensions_len);
            offset += 2 + extensions_len;
        }
    }
    
    return 0;
} 