### Content

- [REST](#rest)
	- [Identifying REST Endpoints](#identifying-rest-endpoints)
	- [Endpoints Structure and Parameters Types](#endpoints-structure-and-parameters-types)
	- [Discovering REST Endpoints and Parameters](#discovering-rest-endpoints-and-parameters)
- [SOAP](#soap)
	- [Identifying SOAP Endpoints](#identifying-soap-endpoints)
	- [Endpoints Structure and Parameters](#endpoints-structure-and-parameters)
	- [Discovering REST Endpoints and Parameters](#discovering-rest-endpoints-and-parameters)
- [GraphQL](#graphql)
	- [Endpoints Structure and Parameters](#endpoints-structure-and-parameters)
	- [GraphQL Queries](#graphql-queries)
	- [GraphQL Mutations](#graphql-mutations)
	- [Discovering Queries and Mutations](#discovering-queries-and-mutations)

> An application programming interface (API) is a set of rules that enables data transmission between different software. The technical specification of each API dictates the data exchange.

---
### REST

Representational State Transfer Application Programming Interfaces (REST APIs ) are:

- Stateless
- Client-server communication model.
- utilize standard `HTTP methods` (`GET`, `POST`, `PUT`, `DELETE`) to perform `CRUD` (Create, Read, Update, Delete) operations on resources identified by unique URLs.
- Exchange data in formats like `JSON` or `XML`.

ex:

```HTTP
GET /users/123
```

#### Identifying REST Endpoints

- REST APIs are built around the concept of resources identified by (unique URLs) = (endpoints).
- The endpoints are targeted by client requests, often with parameters.

#### Endpoints Structure and Parameters Types

- Endpoints structured as URLs representing the resources to access or manipulate, ex:
	- `/users` - Represents a collection of user resources.
	- `/users/123` - Represents a specific user with the ID 123.
- There are several types of parameters, ex:
	- Query Parameters: `/users?limit=10&sort=name`
	- Path Parameters: `/products/{id}pen_spark`
	- Request Body Parameters: `{ "name": "New Product", "price": 99.99 }`
	  Sent in the body of POST, PUT, or PATCH requests. Used to create or update resources.

#### Discovering REST Endpoints and Parameters

1. `API Documentation`: The most reliable way to understand an API is to refer to its official documentation.
2. `Network Traffic Analysis`: If documentation is not available or incomplete, you can analyze network traffic to observe how the API is used.
3. `Parameter Name Fuzzing`: Similar to fuzzing for directories and files, you can use the same tools and techniques to fuzz for parameter names within API requests.

---
### SOAP

SOAP (Simple Object Access Protocol) APIs rely on XML-based messages.

- All messages are written in XML and wrapped inside a SOAP Envelope.
- Can run over multiple network protocols ex: `HTTP` or `SMTP`.
- Supports built-in security, reliability, and transaction management features, suitable for strict data integrity and error handling.
- WSDL (Web Services Description Language), An optional but common companion file that describes what operations a SOAP service exposes and how to call them. Think of it as the API's "manual."

Anatomy of a SOAP Message:

```XML
<soap:Envelope>          ← REQUIRED: Wrapper that marks this as SOAP (not plain XML)
  <soap:Header>          ← OPTIONAL: Instructions for SOAP nodes (routing, auth, etc.)
  </soap:Header>
  <soap:Body>            ← REQUIRED: The actual request/response data + parameters
    <soap:Fault>         ← OPTIONAL (inside Body): Error details if the call failed
    </soap:Fault>
  </soap:Body>
</soap:Envelope>
```

Request example:

```HTTP
POST /userService HTTP/1.1
Host: api.example.com
Content-Type: text/xml; charset=utf-8
Content-Length: 320
SOAPAction: "http://example.com/GetUserDetails"

<?xml version="1.0" encoding="utf-8"?>
	<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"xmlns:usr="http://example.com/userservice">

	  <soap:Header>
	    <usr:AuthToken>eyJhbGciOiJIUzI1NiJ9.abc123</usr:AuthToken>
	  </soap:Header>

	  <soap:Body>
	    <usr:GetUserDetails>
	      <usr:UserID>1337</usr:UserID>
	    </usr:GetUserDetails>
	  </soap:Body>

	</soap:Envelope>
```

Response example:

```HTTP
HTTP/1.1 200 OK
Content-Type: text/xml; charset=utf-8
Content-Length: 420

<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:usr="http://example.com/userservice">

  <soap:Header>
    <usr:ResponseTimestamp>2026-05-24T20:14:00Z</usr:ResponseTimestamp>
  </soap:Header>

  <soap:Body>
    <usr:GetUserDetailsResponse>
      <usr:UserID>1337</usr:UserID>
      <usr:Username>reactor_engineer</usr:Username>
      <usr:Email>engineer@reactor.htb</usr:Email>
      <usr:Role>admin</usr:Role>
    </usr:GetUserDetailsResponse>
  </soap:Body>

</soap:Envelope>
```

#### Identifying SOAP Endpoints

- SOAP APIs typically expose a single endpoint.
- This endpoint is a URL where the SOAP server listens for incoming requests.
- The content of the SOAP message itself determines the specific operation you want to perform.

#### Endpoints Structure and Parameters

The parameters are defined in the `Web Services Description Language` (`WSDL`) file, an `XML-based document` that describes the web service's interface, operations, and message formats.

- SOAP parameters are defined within the body of the SOAP message, an XML document.
- These parameters are organized into elements and attributes, forming a hierarchical structure.
- The specific structure of the parameters depends on the operation being invoked.

A SOAP API for a library that offers a book search service. The WSDL file might define an operation called `SearchBooks` with the following input parameters:

- `keywords` (string): The search terms to use.
- `author` (string): The name of the author (optional).
- `genre` (string): The genre of the book (optional).

A sample SOAP request to this API might look like this:

```XML
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:lib="http://example.com/library">
   <soapenv:Header/>
   <soapenv:Body>
      <lib:SearchBooks>
         <lib:keywords>cybersecurity</lib:keywords>
         <lib:author>Dan Kaminsky</lib:author>
      </lib:SearchBooks>
   </soapenv:Body>
</soapenv:Envelope>
```

#### Discovering REST Endpoints and Parameters

1. `WSDL Analysis`: The WSDL file is the most valuable resource for understanding a SOAP API.
2. `Network Traffic Analysis`
3. `Fuzzing for Parameter Names and Values`: By sending malformed or unexpected values within SOAP requests and see how the server responds.

---
### GraphQL

Graph Query Language (`GraphQL`) :

- provides a single endpoint where clients can request the data they need using a flexible query language.

ex:

```graphql
query {
  user(id: 123) {
    name
    email
  }
}
```

#### Endpoints Structure and Parameters

-  GraphQL APIs are designed to be more flexible and efficient by allowing clients to request precisely the data they need in a single request.
-  Typically have a single endpoint. This endpoint is usually a URL like `/graphql` and serves as the entry point for all queries and mutations sent to the API.
-  GraphQL uses a unique query language to specify the data requirements.

#### GraphQL Queries

| Component     | Description                                                                               | Example                 |
| ------------- | ----------------------------------------------------------------------------------------- | ----------------------- |
| Field         | Represents a specific piece of data you want to retrieve (e.g., name, email).             | `name`, `email`         |
| Relationship  | Indicates a connection between different types of data (e.g., a user's posts).            | `posts`                 |
| Nested Object | A field that returns another object, allowing you to traverse deeper into the data graph. | `posts { title, body }` |
| Argument      | Modifies the behavior of a query or field (e.g., filtering, sorting, pagination).         | `posts(limit: 5)`       |

```graphql
query {
  user(id: 123) {
    name
    email
    posts(limit: 5) {
      title
      body
    }
  }
}
```

Query for information about a `user` with the ID 123, requesting his `name` and `email`, Also fetch his first 5 `posts`, including the `title` and `body` of each post.

#### GraphQL Mutations

Mutations are the counterparts to queries designed to modify data on the server.

|Component|Description|Example|
|---|---|---|
|Operation|The action to perform (e.g., createPost, updateUser, deleteComment).|`createPost`|
|Argument|Input data required for the operation (e.g., title and body for a new post).|`title: "New Post", body: "This is the content of the new post"`|
|Selection|Fields you want to retrieve in the response after the mutation completes (e.g., id, title of new post).|`id`, `title`|

```graphql
mutation {
  createPost(title: "New Post", body: "This is the content of the new post") {
    id
    title
  }
}
```

A mutation creates a new post with title and body, returning the `id` and `title` of the created post in the response.

#### Discovering Queries and Mutations

1. `Introspection`: GraphQL's introspection system is a powerful tool for discovery. By sending an introspection query to the GraphQL endpoint, you can retrieve a complete schema describing the API's capabilities.
2. `API Documentation`
3. `Network Traffic Analysis`

> Focus on understanding the underlying schema and how clients can construct valid requests to retrieve or modify data.