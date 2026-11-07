"""
Server-Side Template Injection (SSTI) Scanner (Penetration Tester & AppSec)
Detects:
- Python Jinja2 / Flask: render_template_string() with untrusted variable interpolation (CWE-1336)
- Python Mako: Template(str).render() with dynamic strings
- Node.js EJS / Handlebars: ejs.render(dynamic), Handlebars.compile(dynamic)
- Java FreeMarker / Velocity: StringReader / Velocity.evaluate() with untrusted input
- PHP Twig / Smarty: createTemplate() from dynamic variables
Mapped to MITRE ATT&CK: T1190 (Exploit Public-Facing Application)
"""

import re
from typing import List, Dict, Any
from cyberaudit.core.base_scanner import BaseScanner
from cyberaudit.core.models import Finding, Severity, Pillar, StrideCategory


class SstiScanner(BaseScanner):
    """
    Scans template rendering invocations across Python, Node.js, Java, and PHP
    for dangerous dynamic string compilation and interpolation vulnerabilities.
    """

    def __init__(self):
        super().__init__()
        self.rules: List[Dict[str, Any]] = [
            {
                "id": "APPSEC-SSTI-JINJA-FLASK-01",
                "title": "SSTI: Dynamic Template String Rendering (Jinja2 / Flask)",
                "pattern": re.compile(
                    r'render_template_string\s*\(\s*(?:f["\']|["\'].*?["\']\s*\%|.*?\.format\(|[a-zA-Z_]\w*|.*?\+\s*(?:req|user|input|param|arg|query|data|msg))',
                    re.IGNORECASE,
                ),
                "severity": Severity.CRITICAL,
                "stride": StrideCategory.TAMPERING.value,
                "description": (
                    "User input is directly concatenated or formatted into a Jinja2 template string before rendering "
                    "via `render_template_string()`. An attacker can escape the template sandbox using Python MRO "
                    "(e.g. `{{ self.__class__.__mro__[2].__subclasses__() }}`) to achieve Remote Code Execution (RCE)."
                ),
                "remediation": (
                    "Never pass user input as the template source. Use `render_template('template.html', var=user_input)` "
                    "and rely on standard Jinja2 context variables which are automatically escaped."
                ),
                "mitre_id": "T1190",
                "mitre_tactic": "Initial Access",
                "mitre_technique": "Exploit Public-Facing Application",
                "cwe_id": "CWE-1336",
            },
            {
                "id": "APPSEC-SSTI-MAKO-01",
                "title": "SSTI: Untrusted String Ingested into Mako Template Engine",
                "pattern": re.compile(
                    r'(?:mako\.template\.)?Template\s*\(\s*(?:f["\']|["\'].*?["\']\s*\%|.*?\.format\(|.*?\+\s*(?:req|user|input|param|arg|query))\s*\)\s*\.render',
                    re.IGNORECASE,
                ),
                "severity": Severity.CRITICAL,
                "stride": StrideCategory.TAMPERING.value,
                "description": (
                    "Instantiating a Mako `Template(...)` directly from dynamic or concatenated user input allows arbitrary Python "
                    "code execution via `<% ... %>` blocks embedded within the template string."
                ),
                "remediation": (
                    "Load static template files from disk using `TemplateLookup` and pass untrusted data as template arguments: `tmpl.render(name=user_input)`."
                ),
                "mitre_id": "T1190",
                "mitre_tactic": "Initial Access",
                "mitre_technique": "Exploit Public-Facing Application",
                "cwe_id": "CWE-1336",
            },
            {
                "id": "APPSEC-SSTI-NODE-EJS-01",
                "title": "SSTI: Dynamic Template Compilation (Node.js EJS / Handlebars / Pug)",
                "pattern": re.compile(
                    r'(?:ejs\.render|Handlebars\.compile|pug\.compile|dot\.template|nunjucks\.renderString)\s*\(\s*(?:`[^`]*\$\{|(?:req|input|param|body|query)\b|\w+\s*\+\s*(?:req|input|param))',
                    re.IGNORECASE,
                ),
                "severity": Severity.CRITICAL,
                "stride": StrideCategory.TAMPERING.value,
                "description": (
                    "Node.js template compiler receives a dynamic template string built from request parameters or template literals. "
                    "In EJS and Handlebars, this can lead to arbitrary JavaScript execution in the Node.js process context via gadget chains."
                ),
                "remediation": (
                    "Compile static templates from trusted file assets. Pass user parameters strictly in the data context object: `ejs.render(staticTemplate, { user: req.body.user })`."
                ),
                "mitre_id": "T1190",
                "mitre_tactic": "Initial Access",
                "mitre_technique": "Exploit Public-Facing Application",
                "cwe_id": "CWE-1336",
            },
            {
                "id": "APPSEC-SSTI-JAVA-FREEMARKER-01",
                "title": "SSTI: Dynamic FreeMarker / Velocity Template Evaluation (Java)",
                "pattern": re.compile(
                    r'(?:new\s+Template\s*\([^,]+,\s*new\s+StringReader\s*\([^)]*?(?:request|param|input|userInput)|Velocity\.evaluate\s*\([^,]+,\s*[^,]+,\s*[^,]+,\s*(?:request|param|input))',
                    re.IGNORECASE,
                ),
                "severity": Severity.CRITICAL,
                "stride": StrideCategory.TAMPERING.value,
                "description": (
                    "Java FreeMarker or Apache Velocity engine evaluates template code originating from an untrusted StringReader "
                    "or HTTP request. FreeMarker allows direct execution of Java methods through `?new()` or Execute built-ins."
                ),
                "remediation": (
                    "Do not evaluate user-supplied strings as templates. Restrict FreeMarker `Configuration` using `TemplateClassResolver.SAFER_RESOLVER` "
                    "and disable the `?new` built-in."
                ),
                "mitre_id": "T1190",
                "mitre_tactic": "Initial Access",
                "mitre_technique": "Exploit Public-Facing Application",
                "cwe_id": "CWE-1336",
            },
            {
                "id": "APPSEC-SSTI-PHP-TWIG-01",
                "title": "SSTI: Dynamic Twig / Smarty Template Creation (PHP)",
                "pattern": re.compile(
                    r'(?:\$twig->createTemplate\s*\(\s*(?:\$_GET|\$_POST|\$_REQUEST|\$input|\$param)|display\s*\(\s*["\']string:)',
                    re.IGNORECASE,
                ),
                "severity": Severity.CRITICAL,
                "stride": StrideCategory.TAMPERING.value,
                "description": (
                    "Twig `createTemplate()` or Smarty `string:` evaluation called with user-controlled input allows attackers "
                    "to invoke PHP functions via filter expressions (`{{ ['id']|filter('system') }}`)."
                ),
                "remediation": (
                    "Render pre-compiled template files and pass user input as parameters: `$twig->render('profile.html.twig', ['name' => $input])`."
                ),
                "mitre_id": "T1190",
                "mitre_tactic": "Initial Access",
                "mitre_technique": "Exploit Public-Facing Application",
                "cwe_id": "CWE-1336",
            },
        ]

    @property
    def name(self) -> str:
        return "Server-Side Template Injection (SSTI) Scanner"

    @property
    def pillar(self) -> Pillar:
        return Pillar.PENETRATION_TESTER

    @property
    def description(self) -> str:
        return "Detects dangerous server-side template injection across Python (Jinja2, Mako), Node.js (EJS, Handlebars), Java, and PHP."

    @property
    def file_extensions(self) -> List[str]:
        return [".py", ".js", ".ts", ".java", ".php", ".rb", ".go", ".html", ".tpl"]

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []

        for rule in self.rules:
            pattern = rule["pattern"]
            matches = list(pattern.finditer(content))
            for match in matches:
                start_char = match.start()
                line_idx = content[:start_char].count("\n") + 1
                matched_text = match.group(0).strip()
                snippet = matched_text[:300] + "..." if len(matched_text) > 300 else matched_text

                findings.append(
                    Finding(
                        id=rule["id"],
                        title=rule["title"],
                        description=rule["description"],
                        severity=rule["severity"],
                        pillar=self.pillar,
                        scanner_name=self.name,
                        file_path=file_path,
                        line_number=line_idx,
                        code_snippet=snippet,
                        remediation=rule["remediation"],
                        mitre_id=rule["mitre_id"],
                        mitre_tactic=rule["mitre_tactic"],
                        mitre_technique=rule["mitre_technique"],
                        cwe_id=rule.get("cwe_id"),
                        stride_category=rule.get("stride"),
                        confidence="HIGH",
                    )
                )

        return findings
