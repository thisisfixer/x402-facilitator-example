
from x402.types import (
    PaymentPayload,
    PaymentRequirements
)
from pydantic import BaseModel, ConfigDict
from pydantic.alias_generators import to_camel

class SettleRequest(BaseModel):
    x402_version: int
    payment_payload: PaymentPayload
    payment_requirements: PaymentRequirements

    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        from_attributes=True,
    )


class VerifyRequest(BaseModel):
    x402_version: int
    payment_payload: PaymentPayload
    payment_requirements: PaymentRequirements

    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        from_attributes=True,
    )