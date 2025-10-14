import pytest
from typer.testing import CliRunner
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from chimera_intel.core.schemas import Base 
from chimera_intel.core.response import response_app
from chimera_intel.core.database import Base
from chimera_intel.core.schemas import ResponseRule

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
        "chimera_intel.core.response.get_db", return_value=iter([test_db])
    )


def test_create_and_list_rules(mock_get_db, test_db):
    """
    Tests creating a response rule and then listing it.
    """
    # Create a rule

    result_create = runner.invoke(
        response_app,
        [
            "create-rule",
            "--name",
            "Leaked Credential Protocol",
            "--trigger",
            "dark-monitor:credential-leak",
            "--action",
            "iam:reset-password",
            "--action",
            "edr:isolate-host",
        ],
    )
    assert result_create.exit_code == 0
    assert (
        "Response rule 'Leaked Credential Protocol' created successfully"
        in result_create.stdout
    )

    # Verify it's in the DB

    rule = (
        test_db.query(ResponseRule)
        .filter(ResponseRule.name == "Leaked Credential Protocol")
        .first()
    )
    assert rule is not None
    assert rule.trigger == "dark-monitor:credential-leak"
    assert "iam:reset-password" in rule.actions

    # List the rules

    result_list = runner.invoke(response_app, ["list-rules"])
    assert result_list.exit_code == 0
    assert "Leaked Credential Protocol" in result_list.stdout
    assert "edr:isolate-host" in result_list.stdout


def test_simulate_trigger(mock_get_db, test_db):
    """
    Tests the simulation of a trigger event.
    """
    # Create a rule to be found by the simulation

    rule = ResponseRule(
        name="Test Rule", trigger="test:event", actions=["action1", "action2"]
    )
    test_db.add(rule)
    test_db.commit()

    result = runner.invoke(response_app, ["simulate-trigger", "test:event"])

    assert result.exit_code == 0
    assert "Rule 'Test Rule' would be executed" in result.stdout
    assert "Simulating action: action1" in result.stdout
    assert "Simulating action: action2" in result.stdout
