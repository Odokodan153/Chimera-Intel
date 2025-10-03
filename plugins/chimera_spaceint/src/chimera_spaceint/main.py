import typer
from chimera_intel.core.spaceint import spaceint_app

app = typer.Typer(
    name="spaceint", help="Space Intelligence (SPACEINT).", no_args_is_help=True
)

# Link the core module's Typer application

app.add_typer(spaceint_app, name="spaceint_commands")

if __name__ == "__main__":
    app()
