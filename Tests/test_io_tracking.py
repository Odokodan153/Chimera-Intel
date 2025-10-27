from typer.testing import CliRunner
import httpx
from unittest.mock import patch, MagicMock
import tweepy 
from unittest.mock import ANY 
from chimera_intel.core.config_loader import API_KEYS

# Patch the API key *before* importing the io_tracking_app.
with patch.object(API_KEYS, "gnews_api_key", "fake_key_for_import"):
    with patch.object(API_KEYS, "twitter_bearer_token", "fake_token_for_import"):
        from chimera_intel.core.io_tracking import io_tracking_app

runner = CliRunner()

# --- MOCK DATA ---
MOCK_NEWS_ARTICLES = [
    {
        "title": "Rumors of Failure Swirl Around New Product",
        "source": {"name": "Tech News Today"},
        "url": "http://example.com/news1",
    },
    {
        "title": "Product Failure Claims Debunked by Company",
        "source": {"name": "Business Insider"},
        "url": "http://example.com/news2",
    },
]

# --- ORIGINAL TESTS (Corrected) ---

@patch("chimera_intel.core.io_tracking.search_reddit_narrative", return_value=[])
@patch("chimera_intel.core.io_tracking.search_twitter_narrative", return_value=[])
@patch("chimera_intel.core.io_tracking.search_news_narrative", return_value=MOCK_NEWS_ARTICLES)
def test_track_influence_success(
    mock_search_news, mock_search_twitter, mock_search_reddit
):
    """
    Tests the track-influence command with a successful API response
    and multiple news articles.
    """
    # Act
    result = runner.invoke(
        io_tracking_app, ["--narrative", "rumors of product failure"]
    )

    # Assert
    assert result.exit_code == 0
    assert (
        "Tracking influence campaign for narrative: 'rumors of product failure'"
        in result.output
    )
    assert "Found 2 news articles related to the narrative." in result.output
    assert "Tech News Today" in result.output
    assert "Business Insider" in result.output
    mock_search_news.assert_called_with("rumors of product failure", ANY)
    mock_search_twitter.assert_called_with("rumors of product failure")
    mock_search_reddit.assert_called_with("rumors of product failure", ANY)


@patch("chimera_intel.core.io_tracking.search_reddit_narrative", return_value=[])
@patch("chimera_intel.core.io_tracking.search_twitter_narrative", return_value=[])
@patch("chimera_intel.core.io_tracking.search_news_narrative") 
def test_track_influence_no_api_key(
    mock_search_news, mock_search_twitter, mock_search_reddit
):
    """
    Tests the track-influence command when the GNEWS_API_KEY is missing.
    This should cause a Configuration Error and exit code 1.
    """
    # Arrange
    # --- FIX: This test now works as intended due to the refactor of track() ---
    with patch("chimera_intel.core.io_tracking.API_KEYS.gnews_api_key", None):
        # Act
        result = runner.invoke(
            io_tracking_app, ["--narrative", "some narrative"]
        )

    # Assert
    assert result.exit_code == 1
    assert "Configuration Error: GNEWS_API_KEY not found in .env file." in result.output
    mock_search_news.assert_not_called() # Fails before calling


@patch("chimera_intel.core.io_tracking.search_reddit_narrative", return_value=[])
@patch("chimera_intel.core.io_tracking.search_twitter_narrative", return_value=[])
@patch("chimera_intel.core.io_tracking.search_news_narrative")
def test_track_influence_api_error(
    mock_search_news, mock_search_twitter, mock_search_reddit
):
    """
    Tests the track-influence command when the GNews API (the primary one)
    returns an HTTPStatusError. This should fail the command.
    """
    # Arrange
    mock_search_news.side_effect = httpx.HTTPStatusError(
        "API Error", request=MagicMock(), response=httpx.Response(500)
    )

    # Act
    result = runner.invoke(io_tracking_app, ["--narrative", "api failure"])

    # Assert
    assert result.exit_code == 1
    assert "API Error: Failed to fetch data. Status code: 500" in result.output


@patch("chimera_intel.core.io_tracking.search_reddit_narrative", return_value=[{"data": "reddit post"}])
@patch("chimera_intel.core.io_tracking.search_twitter_narrative", return_value=[{"data": "tweet"}])
@patch("chimera_intel.core.io_tracking.search_news_narrative", return_value=[])
def test_track_influence_no_news_success(
    mock_search_news, mock_search_twitter, mock_search_reddit
):
    """
    Tests the scenario where no news articles are found, but other
    sources might have results. This is a successful run (exit code 0).
    """
    # Act
    result = runner.invoke(
        io_tracking_app, ["--narrative", "obscure narrative"]
    )

    # Assert
    assert result.exit_code == 0
    assert "Found 0 news articles related to the narrative." in result.output
    assert "\nNo significant propagation found in news media." in result.output
    # Ensure it doesn't print a table
    assert "News Narrative Analysis" not in result.output
    # Ensure other searches were still called
    mock_search_twitter.assert_called_once()
    mock_search_reddit.assert_called_once()


@patch("chimera_intel.core.io_tracking.search_reddit_narrative", return_value=[])
# --- FIX: Removed mock for search_twitter_narrative to test its internal logic ---
@patch("chimera_intel.core.io_tracking.search_news_narrative", return_value=MOCK_NEWS_ARTICLES)
def test_track_influence_no_twitter_key(
    mock_search_news, mock_search_reddit
):
    """
    Tests that a missing Twitter key prints a warning to stderr
    but does *not* cause the command to fail (exit code 0).
    """
    # Arrange
    # --- FIX: This test now works as intended due to the refactor of track() ---
    with patch("chimera_intel.core.io_tracking.API_KEYS.twitter_bearer_token", None):
        # Act
        result = runner.invoke(
            io_tracking_app, ["--narrative", "test narrative"]
        )

    # Assert
    assert result.exit_code == 0
    # Check for the warning in stderr (via result.output, as CliRunner captures both)
    assert "Warning: TWITTER_BEARER_TOKEN not found." in result.output
    # Check that the rest of the command (news) still worked
    assert "Found 2 news articles related to the narrative." in result.output
    assert "Tech News Today" in result.output
    # The mock function itself won't be called, as the key check fails first
    # (No mock to check, this is now testing the real function's skip logic)


# --- FIX: Mock tweepy.Client, not the function itself ---
@patch("tweepy.Client")
@patch("chimera_intel.core.io_tracking.search_reddit_narrative", return_value=[])
@patch("chimera_intel.core.io_tracking.search_news_narrative", return_value=MOCK_NEWS_ARTICLES)
def test_track_influence_twitter_api_error(
    mock_search_news, mock_search_reddit, mock_tweepy_client
):
    """
    Tests that a non-HTTP error from the Twitter search is caught,
    printed to stderr, and does *not* fail the main command (exit code 0).
    """
    # Arrange
    # --- FIX: Configure the mock client to raise the error ---
    mock_client_instance = mock_tweepy_client.return_value
    mock_client_instance.search_recent_tweets.side_effect = tweepy.TweepyException("Twitter is down")

    # Act
    result = runner.invoke(
        io_tracking_app, ["--narrative", "test narrative"]
    )

    # Assert
    assert result.exit_code == 0
    assert "Error searching Twitter: Twitter is down" in result.output
    # The rest of the command should proceed
    assert "Found 2 news articles related to the narrative." in result.output
    assert "Business Insider" in result.output


# --- FIX: Mock httpx.Client.get, not the function itself ---
# (Mocking search_news_narrative prevents its httpx call, so this mock
#  will only affect search_reddit_narrative, as intended)
@patch("httpx.Client.get", side_effect=httpx.RequestError("Reddit is down"))
@patch("chimera_intel.core.io_tracking.search_twitter_narrative", return_value=[])
@patch("chimera_intel.core.io_tracking.search_news_narrative", return_value=MOCK_NEWS_ARTICLES)
def test_track_influence_reddit_api_error(
    mock_search_news, mock_search_twitter, mock_httpx_get
):
    """
    Tests that a non-HTTP error from the Reddit search is caught,
    printed to stderr, and does *not* fail the main command (exit code 0).
    """
    # Act
    result = runner.invoke(
        io_tracking_app, ["--narrative", "test narrative"]
    )

    # Assert
    assert result.exit_code == 0
    assert "Error searching Reddit: Reddit is down" in result.output
    # The rest of the command should proceed
    assert "Found 2 news articles related to the narrative." in result.output
    assert "Business Insider" in result.output


@patch("chimera_intel.core.io_tracking.search_reddit_narrative", return_value=[])
@patch("chimera_intel.core.io_tracking.search_twitter_narrative", return_value=[])
@patch("chimera_intel.core.io_tracking.search_news_narrative", side_effect=RuntimeError("A generic unexpected error"))
def test_track_influence_generic_exception(
    mock_search_news, mock_search_twitter, mock_search_reddit
):
    """
    Tests the main command's generic 'except Exception' block.
    This should be caught and cause an exit code 1.
    """
    # Act
    result = runner.invoke(
        io_tracking_app, ["--narrative", "test narrative"]
    )

    # Assert
    assert result.exit_code == 1
    assert "An unexpected error occurred: A generic unexpected error" in result.output


def test_track_influence_no_narrative_arg():
    """
    Tests the CLI behavior when the required '--narrative' argument is missing.
    Typer should handle this and exit with code 2.
    """
    # Act
    result = runner.invoke(io_tracking_app, []) # No arguments for "track"

    # Assert
    assert result.exit_code == 2 # Typer's exit code for missing options
    assert "Missing option" in result.output
    assert "--narrative" in result.output


@patch("chimera_intel.core.io_tracking.search_reddit_narrative", return_value=[])
@patch("chimera_intel.core.io_tracking.search_twitter_narrative", return_value=[])
@patch("chimera_intel.core.io_tracking.search_news_narrative", return_value=[])
def test_track_influence_short_arg_and_empty_narrative(
    mock_search_news, mock_search_twitter, mock_search_reddit
):
    """
    Tests using the short-form '-n' argument and provides an empty
    string. This should be a successful run (exit code 0) that finds nothing.
    """
    # Act
    result = runner.invoke(
        io_tracking_app, ["-n", ""] # Use short-form and empty string
    )

    # Assert
    assert result.exit_code == 0
    assert "Tracking influence campaign for narrative: ''" in result.output
    assert "Found 0 news articles related to the narrative." in result.output
    assert "\nNo significant propagation found in news media." in result.output
    
    # Check that searches were called with the empty string
    mock_search_news.assert_called_with("", ANY)
    mock_search_twitter.assert_called_with("")
    mock_search_reddit.assert_called_with("", ANY)