import ast

from .models import AttackNode, AttackPath, CodeLocation


DANGEROUS_CALLS = {
    "eval": ("CODE_EXECUTION", "CRITICAL"),
    "exec": ("CODE_EXECUTION", "CRITICAL"),
    "os.system": ("COMMAND_INJECTION", "CRITICAL"),
    "subprocess.run": ("COMMAND_INJECTION", "HIGH"),
    "subprocess.call": ("COMMAND_INJECTION", "HIGH"),
    "subprocess.Popen": ("COMMAND_INJECTION", "HIGH"),
}

SQL_SINKS = {
    "execute",
    "executemany",
    "executescript",
}

FILE_SINKS = {
    "open": "PATH_TRAVERSAL",
    "os.remove": "PATH_TRAVERSAL",
    "os.rename": "PATH_TRAVERSAL",
    "os.unlink": "PATH_TRAVERSAL",
    "shutil.copy": "PATH_TRAVERSAL",
    "shutil.move": "PATH_TRAVERSAL",
}

# Trick #1: re.match(pattern, variable) / re.fullmatch(pattern, variable)
# called like: if not re.match(pattern, variable): return/raise
WHITELIST_CHECK_FUNCTIONS = {
    "re.match",
    "re.fullmatch",
}

# Trick #2: variable.isalnum() / .isdigit() / .isalpha() called like:
# if not variable.isalnum(): return/raise
# All three check the variable itself the same way, so they share
# one set and one piece of matching logic.
WHITELIST_METHOD_CHECKS = {
    "isalnum",
    "isdigit",
    "isalpha",
}


def get_call_name(node):
    if isinstance(node, ast.Name):
        return node.id

    if isinstance(node, ast.Attribute):
        parent = get_call_name(node.value)

        if parent:
            return f"{parent}.{node.attr}"

        return node.attr

    return ""


def get_sink_kind(name):
    if name in DANGEROUS_CALLS:
        return name

    if name in SQL_SINKS or name in FILE_SINKS:
        return name

    if "." in name:
        final_part = name.rsplit(".", 1)[-1]

        if final_part in SQL_SINKS or final_part in FILE_SINKS:
            return final_part

    return name


class PythonSecurityAnalyzer(ast.NodeVisitor):

    def __init__(self, filepath, source):

        self.filepath = filepath
        self.source = source
        self.lines = source.splitlines()

        self.sources = []
        self.sinks = []
        self.paths = []
        self.suspicious = []

        self.tainted = {}
        self.taint_sources = {}

        # Variable names with "hands were washed" checks found
        # anywhere in this file. Filled in by analyze() before
        # visiting anything, so it's known ahead of time rather
        # than guessed as we go.
        self.sanitized = set()

    def analyze(self, tree):
        """
        Entry point: find "hands were washed" checks first,
        then walk the file for actual sinks.
        """

        self.sanitized = self._find_sanitized_names(tree)

        self.visit(tree)

    def _find_sanitized_names(self, tree):
        """
        Find variable names that are checked with a whitelist
        check - either a function call like re.match(pattern,
        variable), or a method call on the variable itself like
        variable.isalnum() - with a return/raise on failure.
        """

        sanitized = set()

        for node in ast.walk(tree):

            if not isinstance(node, ast.If):
                continue

            test = node.test

            if not (
                isinstance(test, ast.UnaryOp)
                and isinstance(test.op, ast.Not)
            ):
                continue

            call = test.operand

            if not isinstance(call, ast.Call):
                continue

            # Trick #1: re.match(pattern, variable)
            # The variable is an ARGUMENT to the call.
            name = get_call_name(call.func)

            if name in WHITELIST_CHECK_FUNCTIONS:

                if len(call.args) >= 2:

                    variable = call.args[1]

                    if isinstance(variable, ast.Name):
                        sanitized.add(variable.id)

                continue

            # Trick #2: variable.isalnum() / .isdigit() / .isalpha()
            # The variable is what the call happens ON, not an
            # argument - e.g. call.func is an Attribute whose
            # .value is the variable itself.
            if (
                isinstance(call.func, ast.Attribute)
                and call.func.attr in WHITELIST_METHOD_CHECKS
                and isinstance(call.func.value, ast.Name)
            ):
                sanitized.add(call.func.value.id)

        return sanitized

    def location(self, node):

        line = getattr(node, "lineno", 1)

        code = ""

        if 0 < line <= len(self.lines):
            code = self.lines[line - 1].strip()

        return CodeLocation(
            file=self.filepath,
            line=line,
            code=code,
        )

    def add_source(self, variable, node):

        source = AttackNode(
            id=f"SOURCE-{len(self.sources) + 1}",
            kind="SOURCE",
            name=variable,
            location=self.location(node),
            description=(
                "Variable receiving potentially "
                "attacker-controlled input."
            ),
        )

        self.sources.append(source)

        self.tainted[variable] = True
        self.taint_sources[variable] = source

    def visit_Assign(self, node):

        if self.contains_external_input(node.value):

            for target in node.targets:

                if isinstance(target, ast.Name):

                    self.add_source(
                        target.id,
                        node,
                    )

        elif self.uses_tainted_variable(node.value):

            source = self.find_source_for_expression(
                node.value
            )

            for target in node.targets:

                if isinstance(target, ast.Name):

                    self.tainted[target.id] = True

                    if source:
                        self.taint_sources[
                            target.id
                        ] = source

        self.generic_visit(node)

    def visit_Call(self, node):

        name = get_call_name(node.func)
        kind = get_sink_kind(name)

        # Dangerous execution sink.
        if kind in DANGEROUS_CALLS:

            category, severity = DANGEROUS_CALLS[kind]

            source = self.find_source_for_call(node)

            # Hands were washed - this source was checked
            # somewhere in the file.
            if source and source.name in self.sanitized:
                self.generic_visit(node)
                return

            sink = AttackNode(
                id=f"SINK-{len(self.sinks) + 1}",
                kind="SINK",
                name=name,
                location=self.location(node),
                description=(
                    "Potentially dangerous execution "
                    "operation."
                ),
            )

            self.sinks.append(sink)

            confirmed_flow = source is not None

            self.suspicious.append({
                "type": category,
                "severity": severity,
                "file": self.filepath,
                "line": sink.location.line,
                "code": sink.location.code,
                "sink": name,
                "tainted_input": confirmed_flow,
            })

            self.build_attack_path(
                source=source,
                sink=sink,
                category=category,
                severity=severity,
                confirmed_flow=confirmed_flow,
            )

        # SQL execution sink.
        elif kind in SQL_SINKS:

            dynamic_sql = self.sql_looks_dynamic(node)

            source = self.find_source_for_call(node)

            # Hands were washed - skip entirely.
            if source and source.name in self.sanitized:
                self.generic_visit(node)
                return

            sink = AttackNode(
                id=f"SINK-{len(self.sinks) + 1}",
                kind="SINK",
                name=name,
                location=self.location(node),
                description=(
                    "Database query execution operation."
                ),
            )

            self.sinks.append(sink)

            confirmed_flow = (
                dynamic_sql
                and source is not None
            )

            if dynamic_sql:

                self.suspicious.append({
                    "type": "SQL_INJECTION",
                    "severity": "HIGH",
                    "file": self.filepath,
                    "line": sink.location.line,
                    "code": sink.location.code,
                    "sink": name,
                    "tainted_input": source is not None,
                })

            if dynamic_sql:
                self.build_attack_path(
                    source=source,
                    sink=sink,
                    category="SQL_INJECTION",
                    severity="HIGH",
                    confirmed_flow=confirmed_flow,
                )

        # File path sink.
        elif kind in FILE_SINKS:

            source = self.find_source_for_call(node)

            if source and source.name in self.sanitized:
                self.generic_visit(node)
                return

            sink = AttackNode(
                id=f"SINK-{len(self.sinks) + 1}",
                kind="SINK",
                name=name,
                location=self.location(node),
                description="File path operation.",
            )

            self.sinks.append(sink)

            if source is not None:

                self.suspicious.append({
                    "type": "PATH_TRAVERSAL",
                    "severity": "HIGH",
                    "file": self.filepath,
                    "line": sink.location.line,
                    "code": sink.location.code,
                    "sink": name,
                    "tainted_input": True,
                })

                self.build_attack_path(
                    source=source,
                    sink=sink,
                    category="PATH_TRAVERSAL",
                    severity="HIGH",
                    confirmed_flow=True,
                )

        self.generic_visit(node)

    def contains_external_input(self, node):

        for child in ast.walk(node):

            if isinstance(child, ast.Call):

                call_name = get_call_name(child.func)

                if call_name.startswith("request."):
                    return True

        return False

    def uses_tainted_variable(self, node):

        for child in ast.walk(node):

            if isinstance(child, ast.Name):

                if child.id in self.tainted:
                    return True

        return False

    def find_source_for_expression(self, node):

        for child in ast.walk(node):

            if isinstance(child, ast.Name):

                source = self.taint_sources.get(
                    child.id
                )

                if source:
                    return source

        return None

    def find_source_for_call(self, node):

        for argument in node.args:

            source = self.find_source_for_expression(
                argument
            )

            if source:
                return source

        return None

    def sql_looks_dynamic(self, node):
        if not node.args:
            return False

        query = node.args[0]

        # A literal SQL query is not dynamically constructed.
        # Parameters supplied separately are handled safely by
        # the database driver.
        if isinstance(query, ast.Constant):
            return False

        # Dynamic string concatenation or formatting.
        if isinstance(query, ast.BinOp):
            if isinstance(query.op, (ast.Add, ast.Mod)):
                return True

        # Dynamic f-string.
        if isinstance(query, ast.JoinedStr):
            return True

        # Query variable whose value is tainted.
        if isinstance(query, ast.Name):
            if query.id in self.tainted:
                return True

        return self.uses_tainted_variable(query)

    def build_attack_path(
        self,
        source,
        sink,
        category,
        severity,
        confirmed_flow,
    ):

        nodes = []

        if source:
            nodes.append(source)

        nodes.append(sink)

        if category == "SQL_INJECTION":

            title = (
                "External input may reach a database "
                "execution sink."
            )

            impact = (
                "Potential attacker-controlled database "
                "query execution."
            )

        elif category == "COMMAND_INJECTION":

            title = (
                "Potential attacker-controlled data "
                "may reach command execution."
            )

            impact = (
                "Potential operating-system command "
                "execution."
            )

        elif category == "CODE_EXECUTION":

            title = (
                "Potential attacker-controlled data "
                "may reach dynamic code execution."
            )

            impact = (
                "Potential execution of attacker-controlled "
                "code."
            )

        elif category == "PATH_TRAVERSAL":

            title = (
                "Potential attacker-controlled data "
                "may reach a file path operation."
            )

            impact = (
                "Potential unauthorized file read, write, "
                "or deletion outside the intended directory."
            )

        else:

            title = "Potential attack path discovered."

            impact = (
                "Potential security boundary violation."
            )

        confidence = (
            0.95
            if confirmed_flow
            else 0.55
        )

        status = (
            "POTENTIAL_ATTACK_PATH"
            if confirmed_flow
            else "SUSPICIOUS_SINK"
        )

        self.paths.append(
            AttackPath(
                id=f"PATH-{len(self.paths) + 1}",
                title=title,
                category=category,
                severity=severity,
                confidence=confidence,
                nodes=nodes,
                impact=impact,
                status=status,
            )
        )


def analyze_python_file(filepath):

    try:

        with open(
            filepath,
            "r",
            encoding="utf-8",
            errors="ignore",
        ) as file:

            source = file.read()

        tree = ast.parse(source)

    except (
        OSError,
        SyntaxError,
    ) as exc:

        return {
            "error": str(exc),
            "sources": [],
            "sinks": [],
            "paths": [],
            "suspicious": [],
        }

    analyzer = PythonSecurityAnalyzer(
        filepath,
        source,
    )

    analyzer.analyze(tree)

    return {
        "sources": analyzer.sources,
        "sinks": analyzer.sinks,
        "paths": analyzer.paths,
        "suspicious": analyzer.suspicious,
    }
