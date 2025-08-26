# python-scanning-tool

# Python Scanning Tool

A basic Python script developed to practice **network scanning and enumeration**.  
The script demonstrates how to discover open ports and services.

## Features
- Scans target host for open ports
- Identifies running services
- Simple CLI usage

## Tools & Technologies
- Python 3
- socket / nmap libraries



## Disclaimer

⚠️ This tool is for **educational and research purposes only**.  
Use it only on systems you own or have explicit permission to test.  
The author is **not responsible** for any misuse.


the first page :
<img width="1717" height="591" alt="image" src="https://github.com/user-attachments/assets/145c5561-b4ca-435b-aba1-c51803000c15" />

Here, the user who is not registered on the site can upload any Word file and convert it to PDF, but there is a loophole in this page, which is that the attacker can exploit the ID to change it and see the file of another user who is not authorized to see it:
<img width="1657" height="638" alt="image" src="https://github.com/user-attachments/assets/381fc3f1-3f9a-41d5-a41f-b9392e09d1d4" />

## Insecure Version (IDOR Vulnerability)

- When a user uploads a `.docx` file, it is converted to PDF and saved with a sequential numeric ID (e.g., `12`).
- The download link is generated as:


- **Problem:** There is no access control check.  
Any user can change the `id` parameter and download other users’ files.

### Example
1. User uploads file → gets link `/pdf?id=12`
2. Attacker tries `/pdf?id=11` → successfully downloads another user’s PDF.
3. This is a classic **Insecure Direct Object Reference (IDOR)** issue.


can change the ID to 9 and show file to aother user not supposed to be seen :

<img width="454" height="118" alt="image" src="https://github.com/user-attachments/assets/7d235dda-c425-4ab2-942f-c87a89b6f303" />






## Secure Version (Fixed Implementation)

- Access to `/convert_fix` requires login.
- Files are stored using **UUIDs** (Universally Unique Identifiers) instead of sequential IDs.
- Each file is **bound to the owner** in a secure map (`.owners.json`).
- When a user requests a file via `/pdf_fix?id=<uuid>`:
  - The system checks if the file exists.
  - Verifies that the current session `user_id` matches the owner.
  - Otherwise returns **403 Forbidden**.

### Security Benefits
- Prevents attackers from guessing file IDs.
- Ensures only the rightful owner can access the uploaded file.
- Mitigates **IDOR (Insecure Direct Object Reference)** vulnerability.


Login page for registered user:

<img width="1028" height="471" alt="image" src="https://github.com/user-attachments/assets/7bbe3489-173c-434c-902e-7f092252a0ca" />

The user logs in securely, uploads the file he wants, and it is converted securely without changing our ID value:
<img width="889" height="502" alt="image" src="https://github.com/user-attachments/assets/db3d0829-e90c-48d2-aeb4-5830b7704895" />








Admin login page:
<img width="902" height="421" alt="image" src="https://github.com/user-attachments/assets/968b1d5c-25bf-4983-8577-bac5c26e8616" />

## Admin Dashboard (Scan Feature)

- **Run Scan (INSECURE):**
  - The system enumerates sequential IDs (1, 2, 3, ...).
  - Result shows multiple files accessible → demonstrates **IDOR vulnerability**.
  - Example: `IDOR FOUND for IDs: 1, 2, 3, ...`.

- **Run Scan (SECURE):**
  - The system checks UUID-based files.
  - Each file is bound to its owner and requires authentication.
  - If an attacker tries to access it without permission, the server responds with **403 Forbidden**.
  - This confirms the **secure fix prevents IDOR**.

the result of scan the INSECURE page :

<img width="1454" height="856" alt="image" src="https://github.com/user-attachments/assets/220e24c2-bbfd-417a-b733-fbf6d09e6f3c" />


the result of scan the SECURE page :
🔒 Even if an **admin** account tries to access files that do not belong to them,  
the system enforces strict ownership checks and returns **403 Forbidden**.  
This ensures full protection of user data and prevents unauthorized access.



<img width="1194" height="412" alt="image" src="https://github.com/user-attachments/assets/cd6b01a3-fb96-403c-b456-35bd602eca05" />














## How to Run
```bash
python scanner.py <target-ip>
---

## Example Output
[*] Scanning target: 127.0.0.1
[+] Port 22 is OPEN (SSH)
[+] Port 80 is OPEN (HTTP)
[-] Port 443 is CLOSED


---

## Code Snippet

```python
import socket

def scan_port(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    try:
        s.connect((host, port))
        print(f"[+] Port {port} is OPEN")
    except:
        pass
    s.close()
---

