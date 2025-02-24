# Slack Cookie Decryption Script  

## **Description**  
This script extracts and decrypts stored session authentication cookies from the Slack desktop application on Windows. 

## **How It Works**  
- It retrieves the **secret encryption key** from Slack's Local State file. The script decodes and decrypts it using Windows DPAPI.
- Retrieves encrypted session cookies from Slack's application cookie database.
- Decrypts the cookies using the extracted encryption key with AES-GCM decryption. 
- The decrypted cookies are then saved in a CSV file (`decrypted_cookies.csv`).  
