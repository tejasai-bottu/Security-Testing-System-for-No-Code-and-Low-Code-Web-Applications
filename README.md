# Security-Testing-System-for-No-Code-and-Low-Code-Web-Applications
Developed an automated system that scans no-code/low-code web apps for security vulnerabilities using tools like OWASP ZAP, Nikto, and SQLmap. It uses a local AI model (Gemma3) to analyze results and generate user-friendly HTML reports. The system improves security awareness and reduces manual effort, making it ideal for non-technical users.



## How to install dependencies
Use `pip install -r requirements.txt` to install dependencies.

# Automated Vulnerability Assessment Framework

## 🔑 Key Features

- **Automated Vulnerability Scanning**
- **AI-Powered Report Generation using Gemma3**
- **Easy-to-Understand HTML Reports**
- **Parallel Execution of Security Tools**
- **Local Processing for Privacy**

---

## 🛠️ Tools & Technologies Used

| Tool               | Purpose                     | Download Link                                                                 |
|--------------------|-----------------------------|--------------------------------------------------------------------------------|
| Python             | Automation scripting         | [Download](https://www.python.org/downloads/)                                  |
| OWASP ZAP          | Web application scanner      | [Download](https://www.zaproxy.org/download/)                                  |
| Nikto              | Web server scanner           | [GitHub](https://github.com/sullo/nikto)                                       |
| SQLmap             | SQL Injection tester         | [Website](https://sqlmap.org/)                                                 |
| Metasploit         | Exploit framework            | [Docs](https://docs.metasploit.com/docs/using-metasploit/getting-started.html) |
| Nmap               | Network scanner              | [Download](https://nmap.org/download.html)                                     |
| Lynis              | System auditing              | [Website](https://cisofy.com/lynis/)                                           |
| OpenVAS            | Vulnerability scanning       | [Website](https://www.greenbone.net/en/testnow/)                               |
| Ollama + Gemma3    | AI model for analysis        | [Ollama](https://ollama.com/) → `ollama pull gemma3-chat`                      |
| Jinja2 (Python)    | HTML report generation       | Install via `pip install Jinja2`                                               |

---

## 🔄 Workflow

1. **Input**: User provides a web app URL  
2. **Scanning**: Tools like **ZAP**, **Nikto**, and **SQLmap** scan the app in parallel  
3. **AI Analysis**: Results are analyzed by the **Gemma3** model for clarity  
4. **Reporting**: A structured **HTML report** is generated  

---

## 📤 Output

- A **professional, human-readable HTML report**
- Summarizes vulnerabilities by **severity**
- Includes **suggestions for fixing issues**
