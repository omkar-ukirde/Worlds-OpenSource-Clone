# Contributing to OpenWorlds

Thank you for your interest in contributing! OpenWorlds is an open-source project and we welcome contributions of all kinds.

## Getting Started

```bash
# Clone and install with dev dependencies
git clone https://github.com/omkar-ukirde/Worlds-OpenSource-Clone.git
cd Worlds-OpenSource-Clone
pip install -e ".[dev]"
```

## Development Workflow

1. **Fork** the repository and create a feature branch
2. **Make changes** following the code style below
3. **Test** your changes: `make test`
4. **Lint** your code: `make lint && make format`
5. **Submit** a pull request

## Code Style

- Python 3.11+ with type annotations on all functions
- Formatted with **ruff** (line length: 100)
- Type-checked with **mypy** (strict mode)
- Pydantic v2 models for all data structures

## Adding a New Tool Handler

Tool handlers live in `openworlds/tools/handlers/`. To add a new tool:

### 1. Create the handler file

```python
# openworlds/tools/handlers/my_tool_handler.py
from openworlds.tools.handlers.base import BaseHandler


class MyToolHandler(BaseHandler):
    """Simulates my-tool output."""

    def execute(self, args: list[str]) -> str:
        """Execute simulated my-tool.

        Document supported command patterns here.
        """
        # Parse arguments
        target = args[-1] if args else ""

        # Look up data from the manifest
        host = self.find_host(target)
        if not host:
            return "Error: host not found"

        # Build realistic output
        lines = ["my-tool v1.0", f"Scanning {host.fqdn}..."]
        # ... build output from manifest data ...
        return "\n".join(lines)
```

### 2. Register it in the simulator

Add your handler to `openworlds/tools/simulator.py`:

```python
from openworlds.tools.handlers.my_tool_handler import MyToolHandler

# In ToolSimulator.__init__:
self.handlers["my-tool"] = MyToolHandler(manifest)
```

### 3. Test it

```python
from openworlds.tools.simulator import ToolSimulator
sim = ToolSimulator(manifest)
print(sim.execute("my-tool target_ip"))
```

### Key principles for handlers:

- **Match real tool output format** — use the exact same column headers, spacing, and structure as the real tool
- **Validate credentials** — check username/password against the manifest
- **Use `BaseHandler` helpers** — `find_host()`, `find_user()`, `get_dc()`, `parse_credentials()`
- **Return error messages** matching the real tool's error format

## Adding Attack Strategies

To add a new vulnerability type:

1. **Add injection logic** in `openworlds/world_engine/vuln_injector.py`
2. **Add graph edges** in `openworlds/world_engine/path_validator.py`
3. **Update models** in `openworlds/world_engine/models.py` if new data fields are needed

## Reporting Issues

- Use GitHub Issues for bug reports and feature requests
- Include the seed value for reproducible issues: `openworlds manifest generate --seed <your_seed>`

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
