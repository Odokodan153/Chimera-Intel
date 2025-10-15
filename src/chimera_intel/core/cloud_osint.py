import typer
import asyncio
import logging
from typing import cast, Optional
from .schemas import (
    CloudOSINTResult,
    S3Bucket,
    AzureBlobContainer,
    GCSBucket,
)
from .http_client import async_client
from .utils import save_or_print_results, console
from .database import save_scan_to_db
from .project_manager import get_active_project

logger = logging.getLogger(__name__)


async def check_s3_bucket(bucket_name: str) -> S3Bucket | None:
    """
    Checks if a given S3 bucket name exists and is publicly accessible.

    Args:
        bucket_name (str): The name of the S3 bucket to check.

    Returns:
        S3Bucket | None: A Pydantic model if the bucket is found, otherwise None.
    """
    url = f"http://{bucket_name}.s3.amazonaws.com"
    try:
        # We use a HEAD request as it's lighter than GET

        response = await async_client.head(url, timeout=5)
        # If we get any successful response (even 403 Forbidden), the bucket exists.
        # A 404 Not Found means it doesn't exist.

        if response.status_code != 404:
            # We can check for public access by trying a GET request

            get_response = await async_client.get(url, timeout=5)
            is_public = get_response.status_code == 200
            return S3Bucket(name=bucket_name, url=url, is_public=is_public)
        return None
    except Exception:
        # Ignore timeouts or connection errors for non-existent domains

        return None


async def check_azure_blob(container_name: str) -> AzureBlobContainer | None:
    """
    Checks if a given Azure Blob Storage container is publicly accessible.
    """
    url = f"https://{container_name}.blob.core.windows.net/?restype=container"
    try:
        # Public Azure containers often respond to anonymous GET requests

        response = await async_client.get(url, timeout=5)
        if response.status_code == 200:
            return AzureBlobContainer(name=container_name, url=url, is_public=True)
        return None
    except Exception:
        return None


async def check_gcs_bucket(bucket_name: str) -> GCSBucket | None:
    """
    Checks if a given Google Cloud Storage bucket is publicly accessible.
    """
    url = f"https://storage.googleapis.com/{bucket_name}"
    try:
        response = await async_client.get(url, timeout=5)
        # Public GCS buckets will return 200 and often list contents

        if response.status_code == 200:
            return GCSBucket(name=bucket_name, url=url, is_public=True)
        return None
    except Exception:
        return None


async def find_cloud_assets(keyword: str) -> CloudOSINTResult:
    """
    Generates potential cloud storage names and checks for their existence.

    Args:
        keyword (str): The keyword to base permutations on (e.g., company name).

    Returns:
        CloudOSINTResult: A Pydantic model containing the scan results.
    """
    logger.info("Starting cloud asset search for keyword: %s", keyword)
    # Common patterns for bucket names

    permutations = [
        f"{keyword}",
        f"{keyword}-assets",
        f"{keyword}-backup",
        f"{keyword}-files",
        f"{keyword}-public",
        f"{keyword}-data",
        f"{keyword}-prod",
        f"{keyword}-dev",
    ]

    s3_tasks = [check_s3_bucket(name) for name in permutations]
    azure_tasks = [check_azure_blob(name) for name in permutations]
    gcs_tasks = [check_gcs_bucket(name) for name in permutations]

    all_tasks = s3_tasks + azure_tasks + gcs_tasks
    results = await asyncio.gather(*all_tasks)

    # Filter out the None results for assets that were not found and cast to the correct type

    found_s3 = [cast(S3Bucket, res) for res in results[: len(s3_tasks)] if res]
    found_azure = [
        cast(AzureBlobContainer, res)
        for res in results[len(s3_tasks) : len(s3_tasks) + len(azure_tasks)]
        if res
    ]
    found_gcs = [
        cast(GCSBucket, res)
        for res in results[len(s3_tasks) + len(azure_tasks) :]
        if res
    ]

    return CloudOSINTResult(
        target_keyword=keyword,
        found_s3_buckets=found_s3,
        found_azure_containers=found_azure,
        found_gcs_buckets=found_gcs,
    )


# --- Typer CLI Application ---


cloud_osint_app = typer.Typer()


@cloud_osint_app.command("run")
def run_cloud_scan(
    keyword: Optional[str] = typer.Argument(
        None,
        help="The keyword to search for. Uses active project's company name if not provided.",
    ),
    output_file: str = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Searches for exposed cloud storage assets (S3, Azure, GCP).
    """
    target_keyword = keyword
    if not target_keyword:
        active_project = get_active_project()
        if active_project and active_project.company_name:
            target_keyword = active_project.company_name.lower().replace(" ", "")
            logger.info(
                f"Using keyword '{target_keyword}' from active project '{active_project.project_name}'."
            )
        else:
            logger.error(
                "Error: No keyword provided and no active project with a company name is set."
            )
            raise typer.Exit(code=1)
    if not target_keyword:
        logger.error("Error: A keyword is required for this scan.")
        raise typer.Exit(code=1)
    results_model = asyncio.run(find_cloud_assets(target_keyword))

    results_dict = results_model.model_dump(exclude_none=True)
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(target=target_keyword, module="cloud_osint", data=results_dict)
    logger.info("Cloud asset scan complete for keyword: %s", target_keyword)
