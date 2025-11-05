# Tests/test_mlint_trade_correlation.py

import pytest
import pytest_asyncio
from unittest.mock import patch, MagicMock
from datetime import date

from src.chimera_intel.core.mlint_linking import (
    correlate_trade_and_payment,
    TradeRecord,
    PaymentRecord
)

# Mock data for patching
MOCK_TRADE_DB = {
    "bol-100": TradeRecord(
        id="bol-100",
        exporter_name="Perfect Match Exporters Ltd.",
        importer_name="Perfect Match Importers Inc.",
        amount=50000.00,
        currency="USD",
        ship_date=date(2025, 1, 10),
        description_of_goods="Widgets"
    ),
    "bol-200": TradeRecord(
        id="bol-200",
        exporter_name="Fuzzy Name Exporters LLC",
        importer_name="Fuzzy Importers Co.",
        amount=10000.00,
        currency="USD",
        ship_date=date(2025, 2, 1),
        description_of_goods="Gadgets"
    ),
    "bol-300": TradeRecord(
        id="bol-300",
        exporter_name="Amount Mismatch Ltd.",
        importer_name="Acme Inc.",
        amount=75000.00,
        currency="USD",
        ship_date=date(2025, 3, 1),
        description_of_goods="Parts"
    ),
    "bol-400": TradeRecord(
        id="bol-400",
        exporter_name="Date Mismatch Ltd.",
        importer_name="Acme Inc.",
        amount=20000.00,
        currency="USD",
        ship_date=date(2025, 1, 1),
        description_of_goods="Scrap"
    ),
    "bol-500": TradeRecord(
        id="bol-500",
        exporter_name="Currency Mismatch Ltd.",
        importer_name="Acme Inc.",
        amount=10000.00,
        currency="EUR",
        ship_date=date(2025, 4, 1),
        description_of_goods="Software"
    ),
    "bol-600": TradeRecord(
        id="bol-600",
        exporter_name="Name Mismatch Ltd.",
        importer_name="Totally Different Inc.",
        amount=5000.00,
        currency="USD",
        ship_date=date(2025, 5, 1),
        description_of_goods="Manuals"
    ),
}

MOCK_PAYMENT_DB = {
    "pay-100": PaymentRecord(
        id="pay-100",
        sender_name="Perfect Match Exporters Ltd.",
        receiver_name="Perfect Match Importers Inc.",
        amount=50000.00,
        currency="USD",
        payment_date=date(2025, 1, 15),
        origin_bank_country="SGP"
    ),
    "pay-200": PaymentRecord(
        id="pay-200",
        sender_name="Fuzzy Name Exporters", # Good token_set_ratio
        receiver_name="Fuzzy Importers Company", # Good token_set_ratio
        amount=10100.00, # Within 2% tolerance
        currency="USD",
        payment_date=date(2025, 2, 15), # Within 30 days
        origin_bank_country="USA"
    ),
    "pay-300": PaymentRecord(
        id="pay-300",
        sender_name="Amount Mismatch Ltd.",
        receiver_name="Acme Inc.",
        amount=85000.00, # > 2% mismatch
        currency="USD",
        payment_date=date(2025, 3, 5),
        origin_bank_country="CYP"
    ),
    "pay-400": PaymentRecord(
        id="pay-400",
        sender_name="Date Mismatch Ltd.",
        receiver_name="Acme Inc.",
        amount=20000.00,
        currency="USD",
        payment_date=date(2025, 3, 1), # > 30 days
        origin_bank_country="ARE"
    ),
    "pay-500": PaymentRecord(
        id="pay-500",
        sender_name="Currency Mismatch Ltd.",
        receiver_name="Acme Inc.",
        amount=10000.00,
        currency="USD", # Mismatch
        payment_date=date(2025, 4, 1),
        origin_bank_country="USA"
    ),
    "pay-600": PaymentRecord(
        id="pay-600",
        sender_name="Worldwide Goods", # Bad match
        receiver_name="Global Logistics", # Bad match
        amount=5000.00,
        currency="USD",
        payment_date=date(2025, 5, 1),
        origin_bank_country="USA"
    ),
}

# Async mock fetchers
async def mock_fetch_trade(trade_id):
    return MOCK_TRADE_DB.get(trade_id)

async def mock_fetch_payment(payment_id):
    return MOCK_PAYMENT_DB.get(payment_id)


@pytest.mark.asyncio
@patch('src.chimera_intel.core.mlint_linking._fetch_mock_trade_data', new=mock_fetch_trade)
@patch('src.chimera_intel.core.mlint_linking._fetch_mock_payment_data', new=mock_fetch_payment)
class TestTradeCorrelation:

    async def test_perfect_match(self):
        result = await correlate_trade_and_payment("bol-100", "pay-100")
        assert result.is_match is True
        assert result.confidence_score == pytest.approx(1.0)
        assert len(result.mismatch_reasons) == 0

    async def test_good_fuzzy_match(self):
        result = await correlate_trade_and_payment("bol-200", "pay-200")
        assert result.is_match is True
        assert result.confidence_score == pytest.approx(1.0)
        assert len(result.mismatch_reasons) == 0
        assert result.evidence["exporter_sender_score"] == 100 # token_set_ratio
        assert result.evidence["importer_receiver_score"] == 100
        assert result.evidence["amount_diff_percent"] == pytest.approx(0.01)

    async def test_amount_mismatch(self):
        result = await correlate_trade_and_payment("bol-300", "pay-300")
        assert result.is_match is False
        assert result.confidence_score < 0.6 # 0.5 * 1 * 1 * 1
        assert "Amount mismatch" in result.mismatch_reasons[0]
        assert result.evidence["amount_diff_percent"] > 0.02

    async def test_date_mismatch(self):
        result = await correlate_trade_and_payment("bol-400", "pay-400")
        assert result.is_match is False
        assert result.confidence_score < 0.8 # 1 * 0.7 * 1 * 1
        assert "Date proximity mismatch" in result.mismatch_reasons[0]
        assert result.evidence["date_diff_days"] > 30

    async def test_currency_mismatch(self):
        result = await correlate_trade_and_payment("bol-500", "pay-500")
        assert result.is_match is False
        assert result.confidence_score == 0.0
        assert "Currency mismatch" in result.mismatch_reasons[0]

    async def test_party_name_mismatch(self):
        result = await correlate_trade_and_payment("bol-600", "pay-600")
        assert result.is_match is False
        assert result.confidence_score < 0.8
        assert "Exporter/Sender name mismatch" in result.mismatch_reasons
        assert "Importer/Receiver name mismatch" in result.mismatch_reasons
        assert result.evidence["exporter_sender_score"] < 85
        assert result.evidence["importer_receiver_score"] < 85

    async def test_record_not_found(self):
        result = await correlate_trade_and_payment("bol-999", "pay-100")
        assert result.is_match is False
        assert result.confidence_score == 0.0
        assert "Trade record bol-999 not found" in result.mismatch_reasons[0]
        
        result = await correlate_trade_and_payment("bol-100", "pay-999")
        assert result.is_match is False
        assert result.confidence_score == 0.0
        assert "Payment record pay-999 not found" in result.mismatch_reasons[0]