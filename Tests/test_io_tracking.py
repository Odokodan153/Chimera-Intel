import sys
import pytest
from typer.testing import CliRunner
import httpx
from unittest.mock import patch, MagicMock, ANY
import tweepy
from rich.table import Table

from chimera_intel.core.config_loader import API_KEYS

# Patch the API keys *before* importing the app to ensure import-time checks pass
with patch.object(API_KEYS, "gnews_api_key", "fake_gnews_key_for_import"):
    with patch.object(API_KEYS, "twitter_bearer_token", "fake_twitter_token_for_import"):
        from chimera_intel.core.io_tracking import (
            io_tracking_app,
            search_news_narrative,
            search_twitter_narrative,
            search_reddit_narrative,
        )

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

MOCK_GNEWS_RESPONSE = {"articles": MOCK_NEWS_ARTICLES}

MOCK_TWEET_DATA = MagicMock()
MOCK_TWEET_DATA.data = [{"id": "123", "text": "This product is a failure"}]

MOCK_REDDIT_POSTS = [
    {
        "data": {
            "title": "Thoughts on new product failure rumors",
            "author": "user1",
            "url": "http://reddit.com/post1",
        }
    }
]

MOCK_REDDIT_RESPONSE = {"data": {"children": MOCK_REDDIT_POSTS}}


# --- ORIGINAL TESTS (Corrected) ---
# These tests are kept as they are good integration-level tests for the CLI command.

@patch("chimera_intel.core.io_tracking.search_reddit_narrative", return_value=[])
@patch("chimera_intel.core.io_tracking.search_twitter_narrative", return_value=[])
@patch("chimera_intel.core.io_tracking.search_news_narrative", return_value=MOCK_NEWS_ARTICLES)
def test_track_influence_success_high_level(
    mock_search_news, mock_search_twitter, mock_search_reddit
):
    """
    Tests the track-influence command with a successful API response
    and multiple news articles.
    (This is a high-level test that mocks the search functions themselves)
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
    with patch("chimera_intel.core.io_tracking.API_KEYS.gnews_api_key", None):
        # Act
        result = runner.invoke(
            io_tracking_app, ["--narrative", "some narrative"]
        )

    # Assert
    assert result.exit_code == 1
    assert "Configuration Error: GNEWS_API_KEY not found in .env file." in result.output
    mock_search_news.assert_not_called()  # Fails before calling


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
@patch("chimera_intel.core.io_tracking.search_news_narrative", return_value=MOCK_NEWS_ARTICLES)
def test_track_influence_no_twitter_key(
    mock_search_news, mock_search_reddit
):
    """
    Tests that a missing Twitter key prints a warning to stderr
    but does *not* cause the command to fail (exit code 0).
    """
    # Arrange
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
    result = runner.invoke(io_tracking_app, [])  # No arguments for "track"

    # Assert
    assert result.exit_code == 2  # Typer's exit code for missing options
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
        io_tracking_app, ["-n", ""]  # Use short-form and empty string
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


# --- NEW EXTENDED TESTS ---

# --- Tests for search_news_narrative ---

@patch("httpx.Client")
def test_search_news_narrative_success(mock_client):
    """Tests the success path of search_news_narrative."""
    # Arrange
    mock_response = MagicMock()
    mock_response.json.return_value = MOCK_GNEWS_RESPONSE
    mock_client.get.return_value = mock_response
    
    narrative = "test narrative"

    # Act
    articles = search_news_narrative(narrative, mock_client)

    # Assert
    assert articles == MOCK_NEWS_ARTICLES
    mock_client.get.assert_called_once_with(
        "https://gnews.io/api/v4/search",
        params={
            "q": f'"{narrative}"',
            "token": API_KEYS.gnews_api_key,
            "lang": "en",
            "max": "10",
        },
    )
    mock_response.raise_for_status.assert_called_once()


@patch("httpx.Client")
def test_search_news_narrative_http_error(mock_client):
    """Tests the raise_for_status path of search_news_narrative."""
    # Arrange
    mock_response = MagicMock()
    mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
        "Not Found", request=MagicMock(), response=httpx.Response(404)
    )
    mock_client.get.return_value = mock_response

    # Act & Assert
    with pytest.raises(httpx.HTTPStatusError):
        search_news_narrative("test narrative", mock_client)


# --- Tests for search_twitter_narrative ---

@patch("tweepy.Client")
def test_search_twitter_narrative_success(mock_tweepy_client):
    """Tests the success path of search_twitter_narrative."""
    # Arrange
    mock_client_instance = mock_tweepy_client.return_value
    mock_client_instance.search_recent_tweets.return_value = MOCK_TWEET_DATA
    
    narrative = "test narrative"

    # Act
    tweets = search_twitter_narrative(narrative)

    # Assert
    assert tweets == MOCK_TWEET_DATA.data
    mock_tweepy_client.assert_called_with(API_KEYS.twitter_bearer_token)
    mock_client_instance.search_recent_tweets.assert_called_with(
        f'"{narrative}" -is:retweet', max_results=20
    )


@patch("tweepy.Client")
def test_search_twitter_narrative_no_results(mock_tweepy_client):
    """Tests the 'or []' logic when Twitter API returns no data."""
    # Arrange
    mock_response = MagicMock()
    mock_response.data = None  # Simulate no results
    mock_client_instance = mock_tweepy_client.return_value
    mock_client_instance.search_recent_tweets.return_value = mock_response
    
    # Act
    tweets = search_twitter_narrative("test narrative")

    # Assert
    assert tweets == []


@patch("tweepy.Client", side_effect=Exception("Auth Error"))
def test_search_twitter_narrative_client_exception(mock_tweepy_client):
    """Tests when initializing tweepy.Client raises an exception."""
    # Act
    with patch("typer.echo") as mock_echo:
        tweets = search_twitter_narrative("test narrative")

    # Assert
    assert tweets == []
    mock_echo.assert_called_with("Error searching Twitter: Auth Error", err=True)


# --- Tests for search_reddit_narrative ---

@patch("httpx.Client")
def test_search_reddit_narrative_success(mock_client):
    """Tests the success path of search_reddit_narrative."""
    # Arrange
    mock_response = MagicMock()
    mock_response.json.return_value = MOCK_REDDIT_RESPONSE
    mock_client.get.return_value = mock_response
    
    narrative = "test narrative"

    # Act
    posts = search_reddit_narrative(narrative, mock_client)

    # Assert
    assert posts == MOCK_REDDIT_POSTS
    mock_client.get.assert_called_once_with(
        f"https://www.reddit.com/search.json?q={narrative}&sort=new",
        headers={"User-Agent": "Chimera-Intel IO Tracker v1.0"},
    )
    mock_response.raise_for_status.assert_called_once()


@patch("httpx.Client")
def test_search_reddit_narrative_http_error(mock_client):
    """Tests the raise_for_status path of search_reddit_narrative."""
    # Arrange
    mock_response = MagicMock()
    mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
        "Server Error", request=MagicMock(), response=httpx.Response(500)
    )
    mock_client.get.return_value = mock_response

    # Act
    with patch("typer.echo") as mock_echo:
        posts = search_reddit_narrative("test narrative", mock_client)

    # Assert
    assert posts == []
    mock_echo.assert_called_with(
        "Error searching Reddit: Server Error", err=True
    )


@patch("httpx.Client")
def test_search_reddit_narrative_malformed_json(mock_client):
    """Tests the JSON parsing and .get() safety logic."""
    # Arrange
    mock_response = MagicMock()
    # Simulate valid JSON but missing keys
    mock_response.json.return_value = {"foo": "bar"}
    mock_client.get.return_value = mock_response
    
    # Act
    posts = search_reddit_narrative("test narrative", mock_client)
    
    # Assert
    assert posts == []

    # Simulate JSON that is missing the 'children' key
    mock_response.json.return_value = {"data": {"foo": "bar"}}
    posts = search_reddit_narrative("test narrative", mock_client)
    assert posts == []


# --- Comprehensive Test for 'track' command ---

@patch("chimera_intel.core.io_tracking.console")
@patch("tweepy.Client")
@patch("httpx.Client")
def test_track_influence_full_run_with_results(
    mock_httpx_client, mock_tweepy_client, mock_console
):
    """
    Tests the 'track' command by mocking the underlying API clients.
    This allows the search functions to execute and tests the
    table-printing logic.
    """
    # Arrange
    # Mock httpx (for GNews and Reddit)
    mock_http_instance = mock_httpx_client.return_value
    mock_gnews_response = MagicMock()
    mock_gnews_response.json.return_value = MOCK_GNEWS_RESPONSE
    mock_reddit_response = MagicMock()
    mock_reddit_response.json.return_value = MOCK_REDDIT_RESPONSE
    
    # httpx.get will be called twice. First for GNews, second for Reddit.
    mock_http_instance.get.side_effect = [
        mock_gnews_response,
        mock_reddit_response,
    ]

    # Mock tweepy
    mock_tweepy_instance = mock_tweepy_client.return_value
    mock_tweepy_instance.search_recent_tweets.return_value = MOCK_TWEET_DATA

    # Act
    result = runner.invoke(
        io_tracking_app, ["--narrative", "full run test"]
    )

    # Assert
    assert result.exit_code == 0
    
    # Check that httpx.Client was created and used
    mock_httpx_client.assert_called_once()
    assert mock_http_instance.get.call_count == 2
    
    # Check that tweepy.Client was created and used
    mock_tweepy_client.assert_called_once_with(API_KEYS.twitter_bearer_token)
    mock_tweepy_instance.search_recent_tweets.assert_called_once()

    # Check that the table was created and printed
    # We find the call to console.print(Table(...))
    printed_table = None
    for call in mock_console.print.call_args_list:
        if isinstance(call.args[0], Table):
            printed_table = call.args[0]
            break
    
    assert printed_table is not None
    assert printed_table.title == "News Narrative Analysis"
    assert len(printed_table.rows) == 2
    assert printed_table.rows[0].cells == ("Tech News Today", "Rumors of Failure Swirl Around New Product")


@patch("chimera_intel.core.io_tracking.search_news_narrative", side_effect=ValueError("Test value error"))
def test_track_influence_value_error(mock_search_news):
    """
    Tests the main command's 'except ValueError' block.
    This should be caught and cause an exit code 1.
    """
    # Act
    result = runner.invoke(
        io_tracking_app, ["--narrative", "test narrative"]
    )

    # Assert
    assert result.exit_code == 1
    assert "Configuration Error: Test value error" in result.output