from .schemas import Operation


def check_roe_01(operation: Operation) -> bool:
    """
    Checks for offensive operations targeting civilian infrastructure.

    Args:
        operation: The operation object to be audited.

    Returns:
        True if the operation is compliant, False otherwise.
    """
    if not operation.targets:
        return True  # No targets mean no violation.
    return not (
        operation.is_offensive
        and any(t.category == "civilian_infrastructure" for t in operation.targets)
    )


def check_dp_01(operation: Operation) -> bool:
    """
    Checks for GDPR compliance regarding the legal basis for processing EU citizen data.

    Args:
        operation: The operation object to be audited.

    Returns:
        True if the operation is compliant, False otherwise.
    """
    # This check is safe because the boolean flags are expected to have a default
    # value of False in the Pydantic schema.
    return not (operation.targets_eu_citizen and not operation.has_legal_basis)


def check_roe_02(operation: Operation) -> bool:
    """
    Checks if the operation has a justification of sufficient length.

    Args:
        operation: The operation object to be audited.

    Returns:
        True if the operation is compliant, False otherwise.
    """
    if not operation.justification:
        return False  # A missing justification is considered a violation.
    return len(operation.justification) >= 10
