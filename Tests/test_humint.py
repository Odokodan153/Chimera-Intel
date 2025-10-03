import pytest
from typer.testing import CliRunner
from unittest.mock import patch, mock_open
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from chimera_intel.core.humint import humint_app
from chimera_intel.core.database import Base
from chimera_intel.core.schemas import HumintSource

runner = CliRunner()

# Setup a temporary in-memory database for testing

engine = create_engine("sqlite:///:memory:")
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(scope="function")
def test_db():
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture
def mock_get_db(mocker, test_db):
    return mocker.patch(
        "chimera_intel.core.humint.get_db", return_value=iter([test_db])
    )


def test_add_and_list_sources(mock_get_db, test_db):
    """
    Tests adding a source and then listing it.
    """
    # Add a source

    result_add = runner.invoke(
        humint_app,
        [
            "add-source",
            "--name",
            "Source-Alpha",
            "--reliability",
            "A1",
            "--expertise",
            "Cybercrime",
        ],
    )
    assert result_add.exit_code == 0
    assert "Source 'Source-Alpha' added successfully" in result_add.stdout

    # Verify it's in the DB

    source = (
        test_db.query(HumintSource).filter(HumintSource.name == "Source-Alpha").first()
    )
    assert source is not None
    assert source.reliability == "A1"

    # List sources

    result_list = runner.invoke(humint_app, ["list-sources"])
    assert result_list.exit_code == 0
    assert "Source-Alpha" in result_list.stdout
    assert "Cybercrime" in result_list.stdout


@patch(
    "chimera_intel.core.humint.perform_generative_task",
    return_value="- Person A is linked to Organization B.",
)
def test_add_report_with_analysis(mock_ai_task, mock_get_db, test_db):
    """
    Tests adding a report with the --analyze flag.
    """
    # First, add a source to the test DB

    source = HumintSource(name="Source-Beta", reliability="B2", expertise="Politics")
    test_db.add(source)
    test_db.commit()

    # Mock the report file

    m = mock_open(read_data="This is the content of the report.")
    with patch("builtins.open", m):
        with patch("os.path.exists", return_value=True):
            result = runner.invoke(
                humint_app,
                [
                    "add-report",
                    "--source",
                    "Source-Beta",
                    "--file",
                    "report.txt",
                    "--analyze",
                ],
            )
    assert result.exit_code == 0
    assert "Report from 'Source-Beta' logged successfully" in result.stdout
    assert "AI-Extracted Relationships" in result.stdout
    assert "Person A is linked to Organization B" in result.stdout
    mock_ai_task.assert_called_once()
