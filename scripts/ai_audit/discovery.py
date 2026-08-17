"""
discovery.py - Discovery Engine + AI Architecture Mapper.

Before hunting anything, build a structural map of what the target actually
is: which LLM SDKs it calls, whether it has an agent/tool-calling layer,
whether it does retrieval (RAG), whether it exposes or consumes MCP, what
vector store it uses. Every other analyzer in this package reads this map
first rather than re-deriving it - the same "map the attack surface before
hunting" discipline as AGENTS.md Phase 1, applied to AI-specific surface.

This is real static analysis (import/pattern detection across the tree),
not an LLM call - deterministic, dependency-free, works on any Python or
JS/TS codebase without needing API keys or network access.
"""

import re
from dataclasses import dataclass, field
from pathlib import Path

SKIP_DIRS = {"node_modules", ".git", "dist", "build", ".next", "__pycache__",
             ".venv", "venv", "vendor", "coverage", ".scanme"}
CODE_EXT = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}

# Every pattern here requires actual import/usage syntax, not a bare word
# match - a comment or docstring mentioning "openai" must not count as
# evidence the SDK is used. This is a false-positive class caught by
# testing against the demo fixture, where a comment explaining a fake SDK
# is NOT used still tripped a bare \bopenai\b match. Precision here is the
# same discipline as everywhere else in this project: a wrong "detected"
# signal is exactly the kind of noise that trains people to stop reading.
SIGNALS = [
    ("llm_sdk", "OpenAI SDK", r"^\s*(?:from\s+openai\s+import|import\s+openai)\b|[^.\w]openai\.\w"),
    ("llm_sdk", "Anthropic SDK", r"^\s*(?:from\s+anthropic\s+import|import\s+anthropic)\b|[^.\w]anthropic\.\w"),
    ("llm_sdk", "Google GenAI SDK", r"google\.generativeai|@google/generative-ai"),
    ("llm_sdk", "Cohere SDK", r"^\s*(?:from\s+cohere\s+import|import\s+cohere)\b|[^.\w]cohere\.\w"),
    ("agent_framework", "LangChain", r"^\s*(?:from|import)\s+langchain|require\(['\"]langchain"),
    ("agent_framework", "LlamaIndex", r"^\s*(?:from|import)\s+llama_index|require\(['\"]llama-index"),
    ("agent_framework", "CrewAI", r"^\s*(?:from|import)\s+crewai"),
    ("agent_framework", "Claude Agent SDK", r"claude[_-]?agent[_-]?sdk|anthropic\.agents\."),
    ("vector_db", "Pinecone", r"^\s*(?:from|import)\s+pinecone|require\(['\"]@?pinecone"),
    ("vector_db", "Chroma", r"^\s*(?:from|import)\s+chromadb|require\(['\"]chromadb"),
    ("vector_db", "Weaviate", r"^\s*(?:from|import)\s+weaviate|require\(['\"]weaviate"),
    ("vector_db", "Qdrant", r"^\s*(?:from|import)\s+qdrant|require\(['\"]@?qdrant"),
    ("vector_db", "pgvector", r"CREATE EXTENSION.{0,10}vector|pgvector"),
    ("vector_db", "FAISS", r"^\s*(?:from|import)\s+faiss"),
    ("mcp", "MCP server/client", r"^\s*(?:from|import)\s+mcp\b|@modelcontextprotocol/"),
    ("tool_calling", "OpenAI function/tool calling", r"\"tool_calls\"|\.tool_calls\b|function_call\s*="),
    ("tool_calling", "Anthropic tool use", r"\"tool_use\"|input_schema\s*="),
]

MCP_CONFIG_NAMES = {"mcp.json", "claude_desktop_config.json", ".mcp.json", "mcp_config.json"}


@dataclass
class ArchSummary:
    root: str
    files_scanned: int = 0
    llm_sdks: set = field(default_factory=set)
    agent_frameworks: set = field(default_factory=set)
    vector_dbs: set = field(default_factory=set)
    has_mcp: bool = False
    mcp_config_files: list = field(default_factory=list)
    has_tool_calling: bool = False
    prompt_assembly_files: list = field(default_factory=list)
    tool_definition_files: list = field(default_factory=list)
    rag_files: list = field(default_factory=list)

    def is_ai_app(self):
        # A known SDK import is the strongest signal, but plenty of real
        # apps wrap an LLM call behind their own function (an in-house
        # client, a raw HTTP call to a provider) rather than importing a
        # named SDK. Structural evidence of prompt construction or
        # retrieval calls counts too - it's what the analyzers themselves
        # already found, not a guess.
        return bool(self.llm_sdks or self.agent_frameworks or self.has_tool_calling
                    or self.prompt_assembly_files or self.rag_files)

    def summary_lines(self):
        out = [
            "AI surface map for {}".format(self.root),
            "  files scanned      : {}".format(self.files_scanned),
            "  LLM SDKs           : {}".format(", ".join(sorted(self.llm_sdks)) or "none detected"),
            "  Agent frameworks   : {}".format(", ".join(sorted(self.agent_frameworks)) or "none detected"),
            "  Vector DBs (RAG)   : {}".format(", ".join(sorted(self.vector_dbs)) or "none detected"),
            "  MCP                : {}".format(
                "yes ({} config file(s))".format(len(self.mcp_config_files)) if self.has_mcp else "no"),
            "  Tool/function calling: {}".format("yes" if self.has_tool_calling else "no"),
        ]
        if not self.is_ai_app():
            out.append("  -> No AI/LLM surface detected. AI Security Mode has nothing to audit here;")
            out.append("     fall back to Audit Mode for standard web app vulnerability classes.")
        return out


def _iter_files(root):
    root = Path(root)
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        if p.name in MCP_CONFIG_NAMES:
            yield p, "mcp_config"
            continue
        if p.suffix in CODE_EXT:
            yield p, "code"


def discover(root):
    """Walk the tree once, classify every file, return a structural summary."""
    summary = ArchSummary(root=str(root))
    compiled = [(cat, label, re.compile(pat, re.I)) for cat, label, pat in SIGNALS]

    for path, kind in _iter_files(root):
        rel = str(path.relative_to(root)).replace("\\", "/")

        if kind == "mcp_config":
            summary.has_mcp = True
            summary.mcp_config_files.append(rel)
            continue

        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        summary.files_scanned += 1

        for cat, label, pattern in compiled:
            if pattern.search(text):
                if cat == "llm_sdk":
                    summary.llm_sdks.add(label)
                elif cat == "agent_framework":
                    summary.agent_frameworks.add(label)
                elif cat == "vector_db":
                    summary.vector_dbs.add(label)
                    if rel not in summary.rag_files:
                        summary.rag_files.append(rel)
                elif cat == "mcp":
                    summary.has_mcp = True
                elif cat == "tool_calling":
                    summary.has_tool_calling = True
                    if rel not in summary.tool_definition_files:
                        summary.tool_definition_files.append(rel)

        # A prompt/messages/context variable built by concatenation or
        # f-string, in a file that also calls something LLM-shaped (a named
        # SDK, or a locally-defined wrapper like call_llm/ask_gpt/complete/
        # chat - real codebases wrap providers behind their own function
        # constantly). Neither signal alone is enough; both together is
        # real evidence of prompt assembly worth the Prompt Analyzer's time.
        has_prompt_var = re.search(
            r"""(?:prompt|messages?|context)\s*=\s*(?:f["']|["'].*?["']\s*\+|`.*\$\{)""", text, re.I)
        has_llm_call = re.search(
            r"""\b\w*(?:llm|gpt|claude|complete|chat_completion|generate_text)\w*\s*\(""", text, re.I)
        if has_prompt_var and has_llm_call:
            summary.prompt_assembly_files.append(rel)

        if re.search(r"\.(query|search|similarity_search|retrieve)\s*\(", text) and \
           re.search(r"embed|vector|index|collection", text, re.I):
            if rel not in summary.rag_files:
                summary.rag_files.append(rel)

    return summary
