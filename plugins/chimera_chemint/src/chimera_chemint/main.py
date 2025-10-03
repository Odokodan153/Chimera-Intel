import typer
from chimera_intel.core.chemint import chemint_app

app = typer.Typer(
    name="chemint",
    help="Chemical & Materials Intelligence (CHEMINT).",
    no_args_is_help=True
)

# Link the core module's Typer application
app.add_typer(chemint_app, name="chemint_commands")

if __name__ == "__main__":
    app()