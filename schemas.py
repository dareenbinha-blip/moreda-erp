from datetime import date
from decimal import Decimal
from typing import Literal
from pydantic import BaseModel, Field, EmailStr, ConfigDict


class StrictModel(BaseModel):
    model_config = ConfigDict(extra='forbid')


class LoginIn(StrictModel):
    email: str = Field(min_length=5, max_length=255)
    password: str = Field(min_length=1, max_length=200)


Role = Literal['admin', 'sales', 'inventory', 'supervisor', 'employee', 'quality']


class UserIn(StrictModel):
    name: str = Field(min_length=2, max_length=120)
    email: EmailStr
    password: str = Field(min_length=12, max_length=200)
    role: Role = 'employee'


class CustomerIn(StrictModel):
    name: str = Field(min_length=2, max_length=160)
    contact: str = Field(default='', max_length=160)
    phone: str = Field(default='', max_length=50)
    email: str = Field(default='', max_length=255)


class ProductIn(StrictModel):
    sku: str = Field(min_length=1, max_length=60)
    name: str = Field(min_length=2, max_length=160)
    category: str = Field(default='Bags', max_length=100)
    unit_price: Decimal = Field(ge=0, max_digits=12, decimal_places=2)
    standard_minutes: int = Field(default=0, ge=0, le=100000)


class MaterialIn(StrictModel):
    sku: str = Field(min_length=1, max_length=60)
    name: str = Field(min_length=2, max_length=160)
    unit: str = Field(default='sqft', min_length=1, max_length=30)
    reorder_level: Decimal = Field(default=Decimal('0'), ge=0, max_digits=14, decimal_places=3)


class MovementIn(StrictModel):
    kind: Literal['in', 'out']
    quantity: Decimal = Field(gt=0, max_digits=14, decimal_places=3)
    reason: str = Field(min_length=3, max_length=255)


class OrderIn(StrictModel):
    customer_id: int = Field(gt=0)
    product_id: int = Field(gt=0)
    quantity: int = Field(gt=0, le=100000)
    unit_price: Decimal = Field(ge=0, max_digits=12, decimal_places=2)
    due_date: date | None = None
    notes: str = Field(default='', max_length=3000)


class OrderStatusIn(StrictModel):
    status: Literal['confirmed', 'in_production', 'dispatched', 'cancelled']


class JobIn(StrictModel):
    order_id: int = Field(gt=0)
    planned_qty: int = Field(gt=0, le=100000)


class TaskIn(StrictModel):
    job_id: int = Field(gt=0)
    employee_id: int = Field(gt=0)
    stage: Literal['Cutting', 'Skiving', 'Stitching', 'Assembly', 'Finishing', 'Branding', 'Packaging']
    target_qty: int = Field(gt=0, le=100000)


class ProgressIn(StrictModel):
    good_qty: int = Field(ge=0, le=100000)
    rejected_qty: int = Field(ge=0, le=100000)
    note: str = Field(default='', max_length=1000)


class InspectionIn(StrictModel):
    job_id: int = Field(gt=0)
    passed_qty: int = Field(ge=0, le=100000)
    failed_qty: int = Field(ge=0, le=100000)
    note: str = Field(default='', max_length=1000)
