# OWASP Juice Shop
OWASP Juice Shop is insecure web application, It can be used in security trainings, awareness demos, CTFs and as a guinea pig for security tools! 
## The purpose of Test
The purpose of this test is to identify vulnerabilities within the OWASP Juice Shop,The test aims to enhance understanding of common web security issues and develop effective remediation strategies
## Key Findings
Critical Vulnerabilities Identified:
Enumeration of hidden paths, including the admin login page.
Lack of rate-limiting and account lockouts, allowing brute force attacks on admin credentials.
Unsanitized input in the product search functionality, leading to Cross-Site Scripting (XSS) attacks.
High-Level Impact:
Full admin access obtained through brute force attacks.
Execution of malicious scripts via XSS, potentially compromising user sessions and data.
## Scope and Methodology
###  Scope : Docker.io -  bkimminich/juice-shop
###  Approach : Black-box
###  Tools : Burp Suite
# Find Admin Email
The website supports reviewing juice products and displays the email address of the person conducting the review.

![1](https://github.com/user-attachments/assets/02e31a84-7bd5-469b-9a3e-fb2dfe6321db)
# SQL-Injection in Authentication as Admin
To access the admin account in the absence of a password, we use this command, which manipulates the internal components of the database code.
`admin@juice-sh.op ' OR 1=1 --`
### to avoid this attack We should Use Regular expressions in input fields

![4](https://github.com/user-attachments/assets/b8114625-efaf-4aa4-a6d7-67b32044088c)
# Get Admin Path
We can easily obtain the admin path by searching through the website's code files for the routes, and we will find it.

![2](https://github.com/user-attachments/assets/387e7b35-9b7b-4db3-ab8a-e1b1c676bc22)

![3](https://github.com/user-attachments/assets/410d8c9f-1c92-4743-9603-d552c2722d2b)
# Brute Force Attack
In this attack, I will use the Burp Suite tool to brute force the admin's password by attempting all the passwords contained in the wordlist , The tool sends requests to the site with different passwords until a request is accepted. 
### to avoid this attack We should make strong complicated passwords and block te ip which try to access many times

![Screenshot 2024-12-27 161428](https://github.com/user-attachments/assets/e2a9ef38-fb81-47df-953a-ce36709d9f22)

![Screenshot 2024-12-27 161608](https://github.com/user-attachments/assets/7d61f0f9-6b86-4b21-9e21-4441666ce366)
#  XSS Attack
In the beginning, we will set up a server to store the stolen cookies.

`nano capture_server.py`


`import socket
def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', 12345)) 
    server.listen(5)
    print("Server started on 0.0.0.0:12345")
    while True:
        client, address = server.accept()
        print(f"Connection from {address} has been established.")
        client.sendall(b"Hello, you are connected to the server!\n")
        client.close()
if __name__ == "__main__":
    start_server()`

  ![Screenshot 2024-12-27 194119](https://github.com/user-attachments/assets/d57099f7-e09c-4b66-b1c8-092f48041930)
  
Embedding the script into the search engine to steal cookies.

![Screenshot 2024-12-27 194543](https://github.com/user-attachments/assets/fccff3cf-462b-4217-83ea-a1c9e6a8679e)

![image](https://github.com/user-attachments/assets/b42db7a4-78ad-4133-b1eb-5d89be1f064d)

to avoid this Attack : Check user inputs, make outputs safe, and block bad scripts with CSP.
# Additional Vulnerabilities 
## Vulnerability: wired crypto
Juice Shop has a cryptographic flaw where weak encryption or poor key management exposes sensitive data.  
## Prevention:
Use strong encryption (e.g., AES-256) and secure key storage.  
## Precaution: 
Regularly audit and update cryptographic libraries, avoiding custom implementations.

![+1](https://github.com/user-attachments/assets/0fec56c4-468c-4da9-8fcd-b633a7357691)
## Vulnerability: 
Björn's Favorite Pet challenge in Juice Shop exploits predictable answers in security questions.  
## Prevention: 
Avoid using easily guessable security questions and implement multi-factor authentication.  
## Precaution: 
Regularly review and strengthen account recovery mechanisms.

![+2](https://github.com/user-attachments/assets/5999f059-525d-4b6e-94f6-8ae513d86053)
## Vulnerability: 
The "Viewing Other's Baskets" issue in Juice Shop allows unauthorized access to other users' shopping baskets via insecure API endpoints.  
## Prevention: 
Implement proper access control checks and validate user permissions on every request.  
## Precaution: 
Regularly test APIs for broken access control vulnerabilities and enforce strict authorization rules.

![+3](https://github.com/user-attachments/assets/32e1a44f-352d-4918-8f89-ea17bfcb2652)

![+4](https://github.com/user-attachments/assets/25c45752-9723-4885-aba4-d965c3d6213c)












