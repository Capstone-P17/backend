from __future__ import annotations

"""Rule catalog for Java static analysis sources, sinks, and sanitizers."""


HTTP_REQUEST_SOURCE_METHODS = (
    "getParameter",
    "getParameterValues",
    "getHeader",
    "getHeaders",
    "getCookies",
    "getQueryString",
    "getRequestURI",
    "getRequestURL",
    "getPathInfo",
)

SPRING_MVC_SOURCE_ANNOTATIONS = (
    "RequestParam",
    "PathVariable",
    "RequestHeader",
    "CookieValue",
    "RequestBody",
    "ModelAttribute",
)

SQL_EXEC_METHODS = ("executeQuery", "executeUpdate", "execute", "executeLargeUpdate", "executeBatch")
SQL_PREPARE_METHODS = ("prepareStatement",)
SQL_ORM_QUERY_METHODS = (
    "createQuery",
    "createNativeQuery",
    "createSQLQuery",
    "createMutationQuery",
    "newQuery",
)
SQL_TEMPLATE_METHODS = (
    "query",
    "queryForObject",
    "queryForList",
    "queryForMap",
    "queryForRowSet",
    "update",
    "batchUpdate",
)
SQL_SINK_METHODS = SQL_EXEC_METHODS + SQL_PREPARE_METHODS + SQL_ORM_QUERY_METHODS + SQL_TEMPLATE_METHODS
SQL_KEYWORDS = ("SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "CREATE", "MERGE", "ALTER", "TRUNCATE", "FROM", "WHERE")
SQL_BUILDER_METHODS = ("format", "formatted", "concat")
MYBATIS_ANNOTATION_SINKS = ("Select", "Insert", "Update", "Delete", "SelectProvider", "InsertProvider", "UpdateProvider", "DeleteProvider")

XSS_OUTPUT_METHODS = ("println", "print", "write", "append", "format")
XSS_HTML_FRAGMENTS = ("<", ">", "</", "/>", "<h1", "<div", "<span", "<p", "<script", "<img", "<a ")
XSS_SANITIZER_METHODS = (
    "escapeHtml",
    "escapeHtml4",
    "escapeHtml3",
    "htmlEscape",
    "htmlEscapeDecimal",
    "htmlEscapeHex",
    "encodeForHTML",
    "encodeForHtml",
    "encodeForHTMLAttribute",
    "encodeForHtmlAttribute",
    "forHtml",
    "forHtmlContent",
    "forHtmlAttribute",
    "clean",
    "sanitize",
)

PATH_FILE_TYPES = (
    "File",
    "FileInputStream",
    "FileOutputStream",
    "FileReader",
    "FileWriter",
    "RandomAccessFile",
)
PATH_FACTORY_METHODS = ("Paths.get", "Path.of")

COMMAND_EXEC_METHODS = ("Runtime.exec", "ProcessBuilder.command", "new ProcessBuilder")

UPLOAD_TYPES = ("MultipartFile", "Part", "FileItem")
UPLOAD_FILENAME_METHODS = ("getOriginalFilename", "getSubmittedFileName")
UPLOAD_STORAGE_SINKS = ("transferTo", "Files.copy", "write")
UPLOAD_WEB_ROOT_TOKENS = (
    "src/main/resources/static",
    "resources/static",
    "webapp",
    "public",
    "wwwroot",
    "htdocs",
)

WEAK_HASH_ALGORITHMS = ("MD5", "MD4", "MD2", "SHA-1", "SHA1")
PASSWORD_CONTEXT_TERMS = (
    "password",
    "passwd",
    "pwd",
    "credential",
    "credentials",
    "secret",
    "token",
    "auth",
)
NON_PASSWORD_CONTEXT_TERMS = ("checksum", "etag", "fingerprint", "file", "bytes", "integrity")
KDF_OR_PASSWORD_HASH_TERMS = ("PBKDF2", "SecretKeyFactory", "PBEKeySpec", "BCrypt", "SCrypt", "Argon2")
SALT_TERMS = ("salt", "gensalt")

SECURITY_RANDOM_CONTEXT_KEYWORDS = (
    "token",
    "session",
    "key",
    "nonce",
    "salt",
    "password",
    "passwd",
    "secret",
    "auth",
    "otp",
    "pin",
    "csrf",
)
NON_SECURITY_RANDOM_CONTEXT_KEYWORDS = ("dice", "roll", "page", "game", "shuffle", "simulation", "sample", "pager")
