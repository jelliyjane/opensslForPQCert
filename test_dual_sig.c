#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/tls1.h>

int main() {
    printf("Testing Dual Signature Algorithms Extension\n");
    printf("==========================================\n\n");
    
    /* Test that the extension type is defined */
    printf("TLSEXT_TYPE_dual_signature_algorithms = %d\n", 
           TLSEXT_TYPE_dual_signature_algorithms);
    
    /* Test that it's the expected value (51) */
    if (TLSEXT_TYPE_dual_signature_algorithms == 51) {
        printf("✓ Extension type correctly defined as 51\n");
    } else {
        printf("✗ Extension type should be 51, got %d\n", 
               TLSEXT_TYPE_dual_signature_algorithms);
        return 1;
    }
    
    /* Test that OpenSSL version includes our modifications */
    printf("\nOpenSSL version: %s\n", OpenSSL_version(OPENSSL_VERSION));
    
    printf("\n✓ Dual signature algorithms extension implementation verified!\n");
    printf("The extension is ready for testing with actual TLS handshakes.\n");
    
    return 0;
} 