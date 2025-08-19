import typer
import asyncio
import logging
from .schemas import CloudOSINTResult, S3Bucket
from .http_client import async_client
from .utils import save_or_print_results
from .database import save_scan_to_db

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


async def find_s3_buckets(keyword: str) -> CloudOSINTResult:
    """
    Generates potential S3 bucket names and checks for their existence.

    Args:
        keyword (str): The keyword to base permutations on (e.g., company name).

    Returns:
        CloudOSINTResult: A Pydantic model containing the scan results.
    """
    logger.info("Starting S3 bucket search for keyword: %s", keyword)
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

    tasks = [check_s3_bucket(name) for name in permutations]
    results = await asyncio.gather(*tasks)

    # Filter out the None results for buckets that were not found

    found_buckets = [res for res in results if res]

    return CloudOSINTResult(target_keyword=keyword, found_buckets=found_buckets)


# --- Typer CLI Application ---


cloud_osint_app = typer.Typer()


@cloud_osint_app.command("s3")
def run_s3_scan(
    keyword: str = typer.Argument(
        ..., help="The keyword (e.g., company name) to search for."
    ),
    output_file: str = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Searches for common S3 bucket misconfigurations for a given keyword.
    """
    results_model = asyncio.run(find_s3_buckets(keyword))

    results_dict = results_model.model_dump(exclude_none=True)
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(target=keyword, module="cloud_osint_s3", data=results_dict)
    logger.info("S3 bucket scan complete for keyword: %s", keyword)
