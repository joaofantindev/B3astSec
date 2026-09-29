#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
B3AST API v3.0 — Swagger/OpenAPI + GraphQL Discovery
Descobre e analisa APIs REST (Swagger/OpenAPI) e GraphQL endpoints.
Uso: python3 b3ast_api.py http://alvo.com
"""
import sys, re, json
from urllib.parse import urljoin, urlparse
from b3ast_core import C, banner, log_ok, log_vuln, log_fail, log_warn, log_info, log_dim, \
    titulo_fase, safe_exec, salvar_relatorio, menu_niveis, http_request, fingerprint_tecnologia

try:
    from bs4 import BeautifulSoup
except ImportError:
    sys.exit("[!] pip3 install beautifulsoup4")

# Endpoints Swagger/OpenAPI comuns
SWAGGER_PATHS = [
    "swagger", "swagger/", "swagger/ui", "swagger/ui/", "swagger/index.html",
    "swagger/v1/swagger.json", "swagger/v2/swagger.json", "swagger.json",
    "swagger.yaml", "swagger.yml", "api/swagger", "api/swagger/",
    "api/swagger/ui", "api/swagger/index.html", "api/swagger/v1/swagger.json",
    "api-docs", "api-docs/", "api/docs", "api/docs/", "apidocs", "apidocs/",
    "openapi.json", "openapi.yaml", "openapi.yml", "api/openapi.json",
    "api/openapi.yaml", "api/openapi.yml", "v1/openapi.json", "v2/openapi.json",
    "v3/openapi.json", "api/v1/openapi.json", "api/v2/openapi.json",
    "api/v3/openapi.json", "docs", "docs/", "documentation", "documentation/",
    "api/docs", "api/docs/", "api/documentation", "api/documentation/",
    "redoc", "redoc/", "api/redoc", "api/redoc/", "rapidoc", "rapidoc/",
    "scalar", "scalar/", "api/scalar", "api/scalar/",
]

# Endpoints GraphQL comuns
GRAPHQL_PATHS = [
    "graphql", "graphql/", "graphql/v1", "graphql/v2", "api/graphql",
    "api/graphql/", "api/v1/graphql", "api/v2/graphql", "graphql/api",
    "graphiql", "graphiql/", "playground", "playground/", "api/playground",
    "altair", "altair/", "api/altair", "api/altair/", "graphql/console",
    "graphql/console/", "api/graphql/console", "api/graphql/console/",
    "subscriptions", "subscriptions/", "api/subscriptions", "api/subscriptions/",
    "graphql/subscriptions", "graphql/subscriptions/",
]

# Payloads GraphQL introspection
GRAPHQL_INTROSPECTION = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
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
  type { ...TypeRef }
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
"""

def descobrir_swagger(base):
    """Descobre endpoints Swagger/OpenAPI."""
    encontrados = []
    for path in SWAGGER_PATHS:
        url = urljoin(base + "/", path)
        r = http_request(url, timeout=10)
        if r and r.status_code == 200:
            content_type = r.headers.get("Content-Type", "")
            if "json" in content_type or "yaml" in content_type or "text/html" in content_type:
                # Verifica se é realmente um spec OpenAPI/Swagger
                try:
                    if "json" in content_type:
                        data = r.json()
                        if "swagger" in data or "openapi" in data:
                            encontrados.append((url, "OpenAPI/Swagger", r.status_code, len(r.content)))
                            log_vuln(f"OpenAPI/Swagger: {url} ({len(r.content)} bytes)")
                    elif "text/html" in content_type:
                        soup = BeautifulSoup(r.text, "html.parser")
                        title = soup.find("title")
                        if title and ("swagger" in title.text.lower() or "openapi" in title.text.lower()):
                            encontrados.append((url, "Swagger UI", r.status_code, len(r.content)))
                            log_vuln(f"Swagger UI: {url}")
                except Exception:
                    pass
    return encontrados

def analisar_openapi(url, content):
    """Analisa spec OpenAPI e extrai informações."""
    info = []
    try:
        if isinstance(content, str):
            data = json.loads(content)
        else:
            data = content
        
        # Informações gerais
        if "info" in data:
            info.append(f"Título: {data['info'].get('title', 'N/A')}")
            info.append(f"Versão: {data['info'].get('version', 'N/A')}")
            if "description" in data["info"]:
                info.append(f"Descrição: {data['info']['description'][:200]}")
        
        # Servidores
        if "servers" in data:
            for server in data["servers"]:
                info.append(f"Servidor: {server.get('url', 'N/A')}")
        
        # Paths/Endpoints
        if "paths" in data:
            paths = list(data["paths"].keys())
            info.append(f"Endpoints: {len(paths)}")
            for path in paths[:20]:
                methods = list(data["paths"][path].keys())
                info.append(f"  {path}: {', '.join(methods)}")
            if len(paths) > 20:
                info.append(f"  ... e mais {len(paths) - 20} endpoints")
        
        # Schemas/Models
        if "components" in data and "schemas" in data["components"]:
            schemas = list(data["components"]["schemas"].keys())
            info.append(f"Schemas: {len(schemas)}")
            for schema in schemas[:10]:
                info.append(f"  - {schema}")
        
        # Segurança
        if "security" in data:
            info.append(f"Segurança: {data['security']}")
        if "components" in data and "securitySchemes" in data["components"]:
            schemes = list(data["components"]["securitySchemes"].keys())
            info.append(f"Security Schemes: {', '.join(schemes)}")
    
    except Exception as e:
        info.append(f"Erro ao analisar: {e}")
    
    return info

def descobrir_graphql(base):
    """Descobre endpoints GraphQL."""
    encontrados = []
    for path in GRAPHQL_PATHS:
        url = urljoin(base + "/", path)
        # Testa com introspection query
        r = http_request(url, method="POST", json={
            "query": GRAPHQL_INTROSPECTION
        }, timeout=15)
        if r and r.status_code == 200:
            try:
                data = r.json()
                if "data" in data and "__schema" in data["data"]:
                    encontrados.append((url, "GraphQL (introspection)", r.status_code, len(r.content)))
                    log_vuln(f"GraphQL: {url} (introspection habilitado!)")
                elif "errors" in data:
                    # Mesmo com erro, pode ser GraphQL
                    error_msg = str(data["errors"])
                    if "introspection" in error_msg.lower():
                        encontrados.append((url, "GraphQL (introspection desabilitado)", r.status_code, len(r.content)))
                        log_ok(f"GraphQL: {url} (introspection desabilitado)")
            except Exception:
                pass
        
        # Testa GET (GraphiQL/Playground)
        r2 = http_request(url, method="GET", timeout=10)
        if r2 and r2.status_code == 200:
            content_type = r2.headers.get("Content-Type", "")
            if "text/html" in content_type:
                soup = BeautifulSoup(r2.text, "html.parser")
                title = soup.find("title")
                if title and any(x in title.text.lower() for x in ["graphiql", "playground", "graphql", "altair"]):
                    encontrados.append((url, f"GraphQL IDE: {title.text}", r2.status_code, len(r2.content)))
                    log_vuln(f"GraphQL IDE: {url} ({title.text})")
    
    return encontrados

def analisar_graphql_schema(url):
    """Obtém schema GraphQL completo via introspection."""
    r = http_request(url, method="POST", json={
        "query": GRAPHQL_INTROSPECTION
    }, timeout=30)
    
    if not r or r.status_code != 200:
        return None
    
    try:
        data = r.json()
        if "data" in data and "__schema" in data["data"]:
            return data["data"]["__schema"]
    except Exception:
        pass
    return None

def extrair_tipos_graphql(schema):
    """Extrai tipos, queries, mutations e subscriptions do schema."""
    info = []
    if not schema:
        return info
    
    # Query Type
    if "queryType" in schema and schema["queryType"]:
        info.append(f"Query Type: {schema['queryType'].get('name', 'N/A')}")
    
    # Mutation Type
    if "mutationType" in schema and schema["mutationType"]:
        info.append(f"Mutation Type: {schema['mutationType'].get('name', 'N/A')}")
    
    # Subscription Type
    if "subscriptionType" in schema and schema["subscriptionType"]:
        info.append(f"Subscription Type: {schema['subscriptionType'].get('name', 'N/A')}")
    
    # Types
    if "types" in schema:
        types = schema["types"]
        queries = []
        mutations = []
        subscriptions = []
        objects = []
        enums = []
        inputs = []
        
        for t in types:
            name = t.get("name", "")
            kind = t.get("kind", "")
            
            # Pula tipos internos
            if name.startswith("__"):
                continue
            
            if kind == "OBJECT":
                objects.append(name)
                if name == schema.get("queryType", {}).get("name"):
                    queries.append(name)
                elif name == schema.get("mutationType", {}).get("name"):
                    mutations.append(name)
                elif name == schema.get("subscriptionType", {}).get("name"):
                    subscriptions.append(name)
            elif kind == "ENUM":
                enums.append(name)
            elif kind == "INPUT_OBJECT":
                inputs.append(name)
        
        info.append(f"Types: {len(objects)} objects, {len(enums)} enums, {len(inputs)} inputs")
        
        # Fields de cada tipo
        for t in types:
            name = t.get("name", "")
            if name.startswith("__"):
                continue
            if "fields" in t and t["fields"]:
                field_names = [f.get("name", "") for f in t["fields"]]
                info.append(f"  {name}: {', '.join(field_names[:10])}")
                if len(field_names) > 10:
                    info.append(f"    ... e mais {len(field_names) - 10} fields")
    
    return info

def testar_graphql_mutations(url):
    """Testa mutações GraphQL comuns."""
    mutacoes_comuns = [
        {"query": 'mutation { deleteUser(id: "1") { id } }'},
        {"query": 'mutation { createUser(input: {name: "test"}) { id } }'},
        {"query": 'mutation { updateUser(id: "1", input: {name: "test"}) { id } }'},
        {"query": 'mutation { login(username: "admin", password: "admin") { token } }'},
        {"query": 'mutation { resetPassword(email: "admin@test.com") { success } }'},
        {"query": 'mutation { uploadFile(file: "test") { url } }'},
        {"query": 'mutation { sendEmail(to: "test@test.com", subject: "test") { id } }'},
        {"query": 'mutation { createPost(input: {title: "test", content: "test"}) { id } }'},
    ]
    
    resultados = []
    for mut in mutacoes_comuns:
        r = http_request(url, method="POST", json=mut, timeout=10)
        if r and r.status_code == 200:
            try:
                data = r.json()
                if "data" in data and data["data"]:
                    resultados.append((mut["query"][:50], "Sucesso"))
                    log_vuln(f"Mutação GraphQL: {mut['query'][:50]}")
                elif "errors" in data:
                    error_msg = str(data["errors"])
                    if "Cannot query field" not in error_msg and "Cannot mutate field" not in error_msg:
                        resultados.append((mut["query"][:50], f"Erro: {error_msg[:100]}"))
            except Exception:
                pass
    
    return resultados

def main():
    if len(sys.argv) < 2:
        log_fail(f'Uso: python3 {sys.argv[0]} http://alvo.com')
        sys.exit(1)
    base = sys.argv[1]

    banner()
    nivel = menu_niveis()

    # Fingerprint inicial
    titulo_fase("FINGERPRINT INICIAL")
    r = safe_exec(http_request, base, default=None, contexto="fingerprint")
    techs = []
    if r:
        techs = fingerprint_tecnologia(r.text, r.headers)
        for t in techs:
            log_ok(f"Detectado: {C.BOLD}{t}{C.END}")

    relatorio = []

    # ── Fase 1: Swagger/OpenAPI Discovery ──
    titulo_fase("SWAGGER/OPENAPI DISCOVERY")
    swagger_encontrados = safe_exec(descobrir_swagger, base, default=[], contexto="swagger")
    
    swagger_info = []
    for url, tipo, status, size in swagger_encontrados:
        swagger_info.append(f"{tipo}: {url} [{status}] ({size} bytes)")
        
        # Analisa spec se for JSON
        if "OpenAPI" in tipo or "Swagger" in tipo:
            r = http_request(url, timeout=15)
            if r:
                info = safe_exec(analisar_openapi, url, r.text, default=[], contexto="openapi")
                swagger_info.extend(info)
    
    if swagger_info:
        relatorio.append(("Swagger/OpenAPI", "\n".join(swagger_info)))
    else:
        relatorio.append(("Swagger/OpenAPI", "Nenhum endpoint Swagger/OpenAPI encontrado"))

    # ── Fase 2: GraphQL Discovery ──
    titulo_fase("GRAPHQL DISCOVERY")
    graphql_encontrados = safe_exec(descobrir_graphql, base, default=[], contexto="graphql")
    
    graphql_info = []
    for url, tipo, status, size in graphql_encontrados:
        graphql_info.append(f"{tipo}: {url} [{status}] ({size} bytes)")
        
        # Se introspection habilitado, obtém schema
        if "introspection" in tipo.lower() and "desabilitado" not in tipo.lower():
            schema = safe_exec(analisar_graphql_schema, url, default=None, contexto="schema")
            if schema:
                tipos_info = safe_exec(extrair_tipos_graphql, schema, default=[], contexto="tipos")
                graphql_info.extend(tipos_info)
                
                # Testa mutações (níveis avançados)
                if nivel in ("3", "4"):
                    mutacoes = safe_exec(testar_graphql_mutations, url, default=[], contexto="mutacoes")
                    if mutacoes:
                        graphql_info.append("\nMutations testadas:")
                        for mut, resultado in mutacoes:
                            graphql_info.append(f"  {mut}: {resultado}")
    
    if graphql_info:
        relatorio.append(("GraphQL", "\n".join(graphql_info)))
    else:
        relatorio.append(("GraphQL", "Nenhum endpoint GraphQL encontrado"))

    # ── Sumário ──
    print(f"\n{C.RED2}{C.BOLD}{'━'*64}")
    total = len(swagger_encontrados) + len(graphql_encontrados)
    print(f"  ☠ {total} APIS DESCOBERTAS")
    print(f"{'━'*64}{C.END}")
    
    if swagger_encontrados:
        print(f"  {C.GREEN}Swagger/OpenAPI:{C.END}")
        for url, tipo, status, size in swagger_encontrados:
            print(f"    → {url} [{status}]")
    
    if graphql_encontrados:
        print(f"  {C.GREEN}GraphQL:{C.END}")
        for url, tipo, status, size in graphql_encontrados:
            print(f"    → {url} [{status}]")

    salvar_relatorio("b3ast_api", urlparse(base).netloc, relatorio)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log_warn("Interrompido."); sys.exit(130)
