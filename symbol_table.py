"""
symbol_table.py — Tabla de símbolos enriquecida
================================================

Almacena tipos, estado de taint y metadata de cada símbolo.
Usada por el TaintEngine y el TypeChecker para razonar sobre
la seguridad de cada variable y reducir falsos positivos.

Correcciones respecto a la versión original
-------------------------------------------
1. is_web_source()   — ahora reconoce variantes con sufijo .get / .getlist
                       y cualquier prefijo request.<attr>
2. mark_sanitized()  — método añadido para registrar el estado SANITIZED
                       (distinto de SAFE: el símbolo pasó por un sanitizador)
3. get_all_tainted() — recorre recursivamente los hijos de scope, no solo
                       el scope actual
4. is_source()       — reconoce también fuentes dinámicas por prefijo
5. is_sanitizer()    — acepta nombres con prefijo (re.escape, html.escape)
6. inherits_taint()  — propaga correctamente desde cualquier scope antecesor
7. Nuevo: mark_param_tainted() para marcar parámetros de función potencialmente
   tainted (se resuelven en análisis interprocedural)
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Set


# ──────────────────────────────────────────────────────────────────────────────
# Enumeraciones
# ──────────────────────────────────────────────────────────────────────────────

class TaintStatus(Enum):
    """Estado de contaminación de un símbolo."""
    UNKNOWN    = auto()   # no analizado aún
    SAFE       = auto()   # literales y constantes
    TAINTED    = auto()   # fluye desde fuente externa
    SANITIZED  = auto()   # pasó por sanitizador reconocido
    PARAM      = auto()   # parámetro de función — taint resuelto en call-site


# ──────────────────────────────────────────────────────────────────────────────
# Estructuras de datos
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class Symbol:
    """Representa un símbolo (variable, función, parámetro)."""
    name:               str
    type:               Optional[str]       = None
    taint_status:       TaintStatus         = TaintStatus.UNKNOWN
    line:               int                 = 0
    col:                int                 = 0
    sources:            List[str]           = field(default_factory=list)
    is_function_param:  bool                = False
    function_scope:     Optional[str]       = None
    sanitizer:          Optional[str]       = None   # qué función sanitizó este símbolo


@dataclass
class FunctionSignature:
    """Firma de función para análisis interprocedural."""
    name:         str
    params:       List[str]           = field(default_factory=list)
    param_types:  List[Optional[str]] = field(default_factory=list)
    return_type:  Optional[str]       = None
    calls:        List[str]           = field(default_factory=list)
    is_sanitizer: bool                = False
    is_source:    bool                = False


# ──────────────────────────────────────────────────────────────────────────────
# Tabla de símbolos
# ──────────────────────────────────────────────────────────────────────────────

class SymbolTable:
    """
    Tabla de símbolos con tracking de taint.

    Soporta scopes anidados mediante parent chaining.
    Los métodos de consulta suben por la cadena de padres.

    Uso:
        table = SymbolTable()
        table.define("x", line=1, col=1)
        table.mark_tainted("x", source="input()")
        sym = table.get("x")   # sym.taint_status == TaintStatus.TAINTED
    """

    # ── Fuentes externas conocidas ────────────────────────────────────────────
    _BUILTIN_SOURCES: Set[str] = {
        "input", "raw_input",
        "sys.stdin.read", "sys.stdin.readline", "sys.stdin",
        "getpass.getpass",
        "os.environ.get", "os.environ",
        "sys.argv",
    }

    # Prefijos de fuentes web — cualquier acceso a estos objetos es tainted
    _WEB_SOURCE_PREFIXES: Set[str] = {
        "request.args", "request.form", "request.values",
        "request.GET",  "request.POST",
        "request.json", "request.data",
        "request.cookies", "request.headers",
        "request.session",
        "cookies", "session",
    }

    # ── Sanitizadores conocidos ───────────────────────────────────────────────
    _SANITIZERS: Set[str] = {
        # Casts numéricos (eliminan taint de cadena)
        "int", "float", "bool",
        # Escapado HTML
        "html.escape", "cgi.escape", "escape", "markupsafe.escape",
        # Escapado SQL
        "quote", "pg_escape_string", "mysqli_escape_string",
        "sqlite3.escape_string", "sqlite.escape",
        # Regex / URL
        "re.escape", "urlencode", "urlquote", "urllib.parse.quote",
        # Repr (no es safe para SQL pero sí marca el taint como procesado)
        "repr",
    }

    # ── Sumideros SQL conocidos ───────────────────────────────────────────────
    _SQL_SINKS: Set[str] = {
        "execute", "executemany", "executescript",
        "cursor.execute", "cursor.executemany",
        "db.execute", "connection.execute",
        "session.execute", "conn.execute",
        "query", "raw_query", "raw",
    }

    def __init__(self, parent: Optional["SymbolTable"] = None):
        self._symbols:    Dict[str, Symbol]            = {}
        self._functions:  Dict[str, FunctionSignature] = {}
        self._parent:     Optional[SymbolTable]        = parent
        self._children:   List[SymbolTable]            = []
        self._scope_name: Optional[str]                = None

    # ── Scope management ──────────────────────────────────────────────────────

    def set_scope(self, name: str):
        """Establece el nombre del scope actual."""
        self._scope_name = name

    @property
    def scope_name(self) -> Optional[str]:
        return self._scope_name

    def create_child(self) -> "SymbolTable":
        """Crea y registra una tabla hija para un nuevo scope."""
        child = SymbolTable(parent=self)
        self._children.append(child)
        return child

    # ── Definición y consulta de símbolos ────────────────────────────────────

    def define(
        self,
        name:   str,
        type_:  Optional[str] = None,
        line:   int           = 0,
        col:    int           = 0,
    ) -> Symbol:
        """Define un nuevo símbolo en el scope actual."""
        sym = Symbol(
            name           = name,
            type           = type_,
            line           = line,
            col            = col,
            function_scope = self._scope_name,
        )
        self._symbols[name] = sym
        return sym

    def get(self, name: str) -> Optional[Symbol]:
        """Obtiene un símbolo buscando desde el scope actual hacia arriba."""
        if name in self._symbols:
            return self._symbols[name]
        if self._parent:
            return self._parent.get(name)
        return None

    def get_local(self, name: str) -> Optional[Symbol]:
        """Obtiene un símbolo solo en el scope actual (sin subir)."""
        return self._symbols.get(name)

    def has(self, name: str) -> bool:
        """Verifica si existe un símbolo en este scope o en algún padre."""
        return name in self._symbols or (
            self._parent is not None and self._parent.has(name)
        )

    # ── Funciones ─────────────────────────────────────────────────────────────

    def define_function(self, name: str) -> FunctionSignature:
        sig = FunctionSignature(name=name)
        self._functions[name] = sig
        return sig

    def get_function(self, name: str) -> Optional[FunctionSignature]:
        if name in self._functions:
            return self._functions[name]
        if self._parent:
            return self._parent.get_function(name)
        return None

    # ── Clasificación de nombres ──────────────────────────────────────────────

    def is_source(self, name: str) -> bool:
        """
        Determina si un nombre es una fuente de datos controlada por el usuario.
        Acepta tanto nombres exactos como prefijos (request.args.get → True).
        """
        if name in self._BUILTIN_SOURCES:
            return True
        # Prefijo web: request.args, request.args.get, request.form.get, etc.
        for prefix in self._WEB_SOURCE_PREFIXES:
            if name == prefix or name.startswith(prefix + ".") or name.startswith(prefix + "["):
                return True
        return False

    def is_web_source(self, name: str) -> bool:
        """Determina si el nombre es una fuente web (request.*, session, etc.)."""
        for prefix in self._WEB_SOURCE_PREFIXES:
            if name == prefix or name.startswith(prefix + ".") or name.startswith(prefix + "["):
                return True
        return False

    def is_sanitizer(self, name: str) -> bool:
        """
        Determina si un nombre es un sanitizador conocido.
        Acepta nombre completo (re.escape) o solo el método (.escape).
        """
        if name in self._SANITIZERS:
            return True
        # Solo el último segmento: "html.escape" → "escape"
        base = name.rsplit(".", 1)[-1] if "." in name else name
        return base in {s.rsplit(".", 1)[-1] for s in self._SANITIZERS}

    def is_sink(self, name: str) -> bool:
        """Determina si un nombre es un sumidero SQL conocido."""
        if name in self._SQL_SINKS:
            return True
        base = name.rsplit(".", 1)[-1] if "." in name else name
        return base in {s.rsplit(".", 1)[-1] for s in self._SQL_SINKS}

    # ── Operaciones de taint ──────────────────────────────────────────────────

    def mark_tainted(
        self,
        name:   str,
        source: str = "unknown",
        line:   int = 0,
        col:    int = 0,
    ):
        """
        Marca un símbolo como TAINTED.
        Si el símbolo no existe, lo crea automáticamente.
        Si ya está SANITIZED, no lo sobreescribe (la sanitización tiene prioridad).
        """
        sym = self.get(name)
        if sym is None:
            sym = self.define(name, line=line, col=col)
        if sym.taint_status == TaintStatus.SANITIZED:
            return   # un símbolo sanitizado no puede volver a ser tainted
        sym.taint_status = TaintStatus.TAINTED
        if source and source not in sym.sources:
            sym.sources.append(source)

    def mark_safe(self, name: str):
        """Marca un símbolo como seguro (literales, constantes)."""
        sym = self.get(name)
        if sym:
            sym.taint_status = TaintStatus.SAFE

    def mark_sanitized(self, name: str, sanitizer: str):
        """
        Marca un símbolo como SANITIZED — pasó por una función de sanitización.
        Estado distinto de SAFE: el símbolo era tainted pero fue saneado.
        """
        sym = self.get(name)
        if sym is None:
            sym = self.define(name)
        sym.taint_status = TaintStatus.SANITIZED
        sym.sanitizer    = sanitizer

    def mark_param(self, name: str, line: int = 0, col: int = 0):
        """Marca un símbolo como parámetro de función (taint potencial)."""
        sym = self.get(name)
        if sym is None:
            sym = self.define(name, line=line, col=col)
        sym.taint_status       = TaintStatus.PARAM
        sym.is_function_param  = True

    def inherits_taint(self, target: str, source: str):
        """
        Propaga taint desde source hacia target.
        Busca source en todos los scopes antes de propagar.
        """
        src_sym = self.get(source)
        if src_sym and src_sym.taint_status == TaintStatus.TAINTED:
            self.mark_tainted(target, source=source)

    # ── Consulta de estado ────────────────────────────────────────────────────

    def is_tainted(self, name: str) -> bool:
        """
        Verifica si un símbolo está TAINTED en cualquier scope accesible
        (sube hacia padres Y baja hacia hijos).
        """
        # Búsqueda upward (comportamiento normal de get)
        sym = self.get(name)
        if sym is not None and sym.taint_status == TaintStatus.TAINTED:
            return True
        # Búsqueda downward en hijos (para símbolos definidos en child scopes)
        for child in self._children:
            if child.is_tainted(name):
                return True
        return False

    def is_safe(self, name: str) -> bool:
        sym = self.get(name)
        return sym is not None and sym.taint_status in (
            TaintStatus.SAFE, TaintStatus.SANITIZED
        )

    def is_sanitized(self, name: str) -> bool:
        sym = self.get(name)
        return sym is not None and sym.taint_status == TaintStatus.SANITIZED

    def is_param(self, name: str) -> bool:
        sym = self.get(name)
        return sym is not None and sym.taint_status == TaintStatus.PARAM

    def get_taint_status(self, name: str) -> TaintStatus:
        sym = self.get(name)
        return sym.taint_status if sym else TaintStatus.UNKNOWN

    def get_all_tainted(self) -> List[Symbol]:
        """
        Retorna todos los símbolos TAINTED en este scope y en todos sus hijos.
        """
        result = [s for s in self._symbols.values()
                  if s.taint_status == TaintStatus.TAINTED]
        for child in self._children:
            result.extend(child.get_all_tainted())
        return result

    def get_all_symbols(self) -> List[Symbol]:
        """Retorna todos los símbolos en este scope y en sus hijos."""
        result = list(self._symbols.values())
        for child in self._children:
            result.extend(child.get_all_symbols())
        return result

    # ── Representación ────────────────────────────────────────────────────────

    def __repr__(self) -> str:
        lines = [f"SymbolTable(scope={self._scope_name!r}, "
                 f"{len(self._symbols)} symbols):"]
        for sym in self._symbols.values():
            src = f" ← {sym.sources}" if sym.sources else ""
            san = f" [by {sym.sanitizer}]" if sym.sanitizer else ""
            lines.append(
                f"  {sym.name:25} {str(sym.type or '?'):10} "
                f"[{sym.taint_status.name}]{src}{san}"
            )
        for child in self._children:
            for line in repr(child).splitlines():
                lines.append("  " + line)
        return "\n".join(lines)
