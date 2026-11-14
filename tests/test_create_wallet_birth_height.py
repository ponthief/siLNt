"""CreateWallet.last_height takes a number or digits (pydantic v2 refuses int->str)."""
import pytest
from pydantic import ValidationError

from models import CreateWallet


@pytest.mark.parametrize("sent,stored", [(123456, "123456"), ("123456", "123456"),
                                          (0, "0"), (" 77 ", "77"), ("007", "7")])
def test_number_or_digits_are_accepted(sent, stored):
    assert CreateWallet(title="w", last_height=sent).last_height == stored


@pytest.mark.parametrize("sent", [None, ""])
def test_absent_means_default_to_tip(sent):
    assert CreateWallet(title="w", last_height=sent).last_height is None
    assert CreateWallet(title="w").last_height is None


@pytest.mark.parametrize("sent", [True, -5, 1.5, "abc", "12.5", "-1", "١٢٣", [1], {}])
def test_anything_else_is_refused_as_a_validation_error(sent):
    with pytest.raises(ValidationError):
        CreateWallet(title="w", last_height=sent)
