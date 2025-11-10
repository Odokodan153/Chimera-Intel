"""
Module for high-value Competitive Image Intelligence (COMPINT).

This module directly addresses high-value use cases by orchestrating
other core modules:
- imint: For AI-based visual analysis (logos, products, SKUs).
- image_forensics_pipeline: For creative attribution (vector search) and reverse search.
- advanced_media_analysis: For deepfake/counterfeit detection.
- evidence_vault: For securing images with an auditable chain-of-custody.
"""

import typer
import logging
import pathlib
from typing import Optional
from PIL import Image
from rich.console import Console
from .imint import analyze_image_content
from .advanced_media_analysis import (
    DeepfakeMultimodal,
    AiGenerationTracer,
    ForensicArtifactScan,
)
from .image_forensics_pipeline import (
    check_similarity_and_log_asset,
    reverse_image_search,
    compute_hashes_and_embeddings,
)
from .evidence_vault import store_evidence
from .schemas import (
    CompetitiveImintResult,
    CreativeAttributionResult,
    BrandMisuseAuditResult,
    CounterDisinfoResult,
    EvidenceReceiptResult,
    DeepfakeAnalysisResult,
    AiGenerationTraceResult,
    ForensicArtifacts,
)
from .utils import save_or_print_results

logger = logging.getLogger(__name__)
console = Console()
compint_app = typer.Typer(
    name="compint",
    help="Competitive Image Intelligence (Products, Ads, Brand Safety)",
)

# --- Pre-defined prompts for use cases (Objective 1) ---

COMPETITIVE_PROMPTS = {
    "product": (
        "Analyze this image for competitive intelligence. Identify all products, "
        "new product SKUs, or unique product features. Extract any visible model numbers or text. "
        "Describe the product's function and appearance."
    ),
    "packaging": (
        "Analyze this image of product packaging. Identify the brand, product name, and any "
        "key features, ingredients, or claims written on it. Extract all legible text. "
        "Note any changes in packaging design or branding."
    ),
    "ad_creative": (
        "Analyze this advertisement creative. Identify the main product, the brand, "
        "the key marketing message, the call to action, and the target audience. "
        "Describe the visual style and sentiment."
    ),
    "event_presence": (
        "Analyze this image from a trade show, conference, or event. "
        "Identify all company logos, brand names, product displays, and booth banners. "
        "Describe the context of the event if possible."
    ),
    "partner_logos": (
        "Analyze this image and identify all partner or sponsor logos present. "
        "List the company names for each logo identified."
    ),
    "manufacturing": (
        "Analyze this image for evidence of manufacturing processes, industrial machinery, "
        "logistics, or supply chain operations (e.g., shipping labels, crates, assembly lines). "
        "Describe the activity shown."
    ),
}

# --- Core Logic Functions ---


def analyze_competitive_image(
    image_path: str, use_case: str
) -> CompetitiveImintResult:
    """
    (Objective 1)
    Analyzes an image for a specific competitive intelligence use case.
    """
    prompt = COMPETITIVE_PROMPTS.get(use_case)
    if not prompt:
        raise ValueError(f"Invalid use case. Must be one of: {list(COMPETITIVE_PROMPTS.keys())}")

    # Reuse the core imint AI analysis function
    analysis_text = analyze_image_content(image_path, prompt)
    return CompetitiveImintResult(
        file_path=image_path, use_case=use_case, analysis=analysis_text
    )


def check_creative_attribution(image_path: str) -> CreativeAttributionResult:
    """
    (Objective 2)
    Checks for reused ad creative by searching the public web (pHash)
    and the internal vector database (CLIP embedding).
    """
    try:
        img = Image.open(image_path)
    except Exception as e:
        raise FileNotFoundError(f"Could not open image {image_path}: {e}")

    # Reuse pipeline functions
    sha256, phash, embedding = compute_hashes_and_embeddings(img)
    emb_shape = str(len(embedding)) if embedding else "None"

    # 1. Check public web
    reverse_hits = reverse_image_search(phash)

    # 2. Check internal vector DB
    internal_hits = check_similarity_and_log_asset(embedding, phash, image_path)

    return CreativeAttributionResult(
        file_path=image_path,
        phash=phash,
        clip_embedding_shape=emb_shape,
        reverse_search_hits=reverse_hits,
        internal_similarity=internal_hits,
    )


def audit_brand_misuse(image_path: str) -> BrandMisuseAuditResult:
    """
    (Objective 3)
    Checks for brand misuse or counterfeits using AI vision and
    forensic artifact scanning.
    """
    # 1. Use AI vision to check for counterfeit indicators
    prompt = (
        "Analyze this image for signs of brand misuse or counterfeit. "
        "Look for inconsistent or low-quality logos, mismatched branding, "
        "poor packaging quality, or unusual text. "
        "Provide a conclusion: 'Likely Legitimate', 'Potential Misuse/Counterfeit', or 'Uncertain'."
    )
    ai_analysis = analyze_image_content(image_path, prompt)

    # 2. Use forensics to check for manipulation (e.g., logos photoshopped on)
    try:
        forensic_scan = ForensicArtifactScan(image_path).analyze()
        # Convert dict to Pydantic model
        artifacts = ForensicArtifacts(**forensic_scan)
    except Exception as e:
        logger.warning(f"Forensic scan failed for {image_path}: {e}")
        artifacts = None

    return BrandMisuseAuditResult(
        file_path=image_path,
        counterfeit_analysis=ai_analysis,
        forensic_artifacts=artifacts,
    )


def run_counter_disinformation_scan(image_path: str) -> CounterDisinfoResult:
    """
    (Objective 4)
    Checks for deepfakes, AI generation, and impersonation.
    """
    p_file = pathlib.Path(image_path)
    deepfake_res = None
    ai_trace_res = None

    # 1. Run deepfake heuristics
    try:
        df_results_dict = DeepfakeMultimodal(image_path).analyze()
        deepfake_res = DeepfakeAnalysisResult(
            file_path=image_path,
            is_deepfake=df_results_dict.get("overall_deepfake_score", 0) > 0.7,
            details=df_results_dict,
        )
    except Exception as e:
        logger.warning(f"Deepfake scan failed for {image_path}: {e}")

    # 2. Run AI generation metadata trace
    try:
        if p_file.suffix.lower() in [".jpg", ".jpeg", ".png"]:
            ai_trace_dict = AiGenerationTracer(image_path).trace_generation()
            ai_trace_res = AiGenerationTraceResult(**ai_trace_dict)
    except Exception as e:
        logger.warning(f"AI trace failed for {image_path}: {e}")

    return CounterDisinfoResult(
        file_path=image_path, deepfake_scan=deepfake_res, ai_trace=ai_trace_res
    )


def secure_image_as_evidence(
    image_path: str, target_project: str
) -> EvidenceReceiptResult:
    """
    (Objective 5)
    Secures an image file in the encrypted vault and creates an
    auditable chain-of-custody.
    """
    p_file = pathlib.Path(image_path)
    if not p_file.exists():
        raise FileNotFoundError(f"File not found: {image_path}")

    try:
        image_bytes = p_file.read_bytes()
    except Exception as e:
        raise IOError(f"Could not read file {image_path}: {e}")

    # Reuse the evidence_vault function
    receipt_id = store_evidence(
        content=image_bytes,
        source=f"file://{image_path}",
        target=target_project,
    )

    return EvidenceReceiptResult(
        file_path=image_path,
        target_project=target_project,
        receipt_id=receipt_id,
    )


# --- CLI Commands ---


@compint_app.command(
    name="analyze", help="(Objective 1) Analyze an image for competitive intel."
)
def cli_analyze_competitive_image(
    image_path: str = typer.Argument(
        ..., exists=True, help="Path to the image file."
    ),
    use_case: str = typer.Option(
        ...,
        "--use-case",
        "-u",
        help=(
            "The CI use case: product, packaging, ad_creative, "
            "event_presence, partner_logos, manufacturing"
        ),
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Runs AI analysis for a specific competitive intelligence use case.
    """
    console.print(
        f"Running Competitive IMINT analysis for '{use_case}' on [cyan]{image_path}[/cyan]..."
    )
    try:
        result = analyze_competitive_image(image_path, use_case)
        save_or_print_results(result.model_dump(), output_file, console)
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(code=1)


@compint_app.command(
    name="attribution",
    help="(Objective 2) Find reused creative on web and in internal DB.",
)
def cli_check_creative_attribution(
    image_path: str = typer.Argument(
        ..., exists=True, help="Path to the ad creative or image."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Performs creative attribution using reverse image search and
    internal vector similarity search.
    """
    console.print(
        f"Running creative attribution for [cyan]{image_path}[/cyan]..."
    )
    try:
        result = check_creative_attribution(image_path)
        save_or_print_results(result.model_dump(exclude_none=True), output_file, console)
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(code=1)


@compint_app.command(
    name="brand-audit",
    help="(Objective 3) Audit image for brand misuse or counterfeit.",
)
def cli_audit_brand_misuse(
    image_path: str = typer.Argument(
        ..., exists=True, help="Path to the image to audit."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Checks for brand misuse/counterfeits using AI vision and forensics.
    """
    console.print(f"Running brand misuse audit on [cyan]{image_path}[/cyan]...")
    try:
        result = audit_brand_misuse(image_path)
        save_or_print_results(result.model_dump(exclude_none=True), output_file, console)
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(code=1)


@compint_app.command(
    name="counter-disinfo",
    help="(Objective 4) Scan image for deepfakes and AI generation.",
)
def cli_run_counter_disinformation_scan(
    image_path: str = typer.Argument(
        ..., exists=True, help="Path to the image/video to scan."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Runs defensive counterintelligence scan for deepfakes and AI traces.
    """
    console.print(
        f"Running counter-disinformation scan on [cyan]{image_path}[/cyan]..."
    )
    try:
        result = run_counter_disinformation_scan(image_path)
        save_or_print_results(result.model_dump(exclude_none=True), output_file, console)
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(code=1)


@compint_app.command(
    name="secure-evidence",
    help="(Objective 5) Secure image in vault with chain-of-custody.",
)
def cli_secure_image_as_evidence(
    image_path: str = typer.Argument(
        ..., exists=True, help="Path to the image file to secure."
    ),
    project: str = typer.Option(
        ...,
        "--project",
        "-p",
        help="The target project or case name (e.g., 'legal_case_001').",
    ),
):
    """
    Encrypts and stores an image as evidence, generating an
    auditable chain-of-custody receipt.
    """
    console.print(
        f"Securing [cyan]{image_path}[/cyan] as evidence for project [bold]{project}[/bold]..."
    )
    try:
        result = secure_image_as_evidence(image_path, project)
        console.print(f"[green]Success:[/green] {result.message}")
        console.print(f"Receipt ID: [bold]{result.receipt_id}[/bold]")
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(code=1)


if __name__ == "__main__":
    compint_app()