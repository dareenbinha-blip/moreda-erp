from datetime import datetime, timezone
from decimal import Decimal
from sqlalchemy import String, Integer, ForeignKey, DateTime, Date, Numeric, Boolean, Text, CheckConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from database import Base


def now():
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = 'users'
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(30), default='employee')
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Customer(Base):
    __tablename__ = 'customers'
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(160), unique=True)
    contact: Mapped[str] = mapped_column(String(160), default='')
    phone: Mapped[str] = mapped_column(String(50), default='')
    email: Mapped[str] = mapped_column(String(255), default='')


class Product(Base):
    __tablename__ = 'products'
    id: Mapped[int] = mapped_column(primary_key=True)
    sku: Mapped[str] = mapped_column(String(60), unique=True)
    name: Mapped[str] = mapped_column(String(160))
    category: Mapped[str] = mapped_column(String(100), default='Bags')
    unit_price: Mapped[Decimal] = mapped_column(Numeric(12, 2), default=0)
    standard_minutes: Mapped[int] = mapped_column(Integer, default=0)


class Material(Base):
    __tablename__ = 'materials'
    __table_args__ = (CheckConstraint('quantity >= 0', name='material_nonnegative'),)
    id: Mapped[int] = mapped_column(primary_key=True)
    sku: Mapped[str] = mapped_column(String(60), unique=True)
    name: Mapped[str] = mapped_column(String(160))
    unit: Mapped[str] = mapped_column(String(30), default='sqft')
    quantity: Mapped[Decimal] = mapped_column(Numeric(14, 3), default=0)
    reorder_level: Mapped[Decimal] = mapped_column(Numeric(14, 3), default=0)


class StockMovement(Base):
    __tablename__ = 'stock_movements'
    id: Mapped[int] = mapped_column(primary_key=True)
    material_id: Mapped[int] = mapped_column(ForeignKey('materials.id'))
    actor_id: Mapped[int] = mapped_column(ForeignKey('users.id'))
    kind: Mapped[str] = mapped_column(String(10))
    quantity: Mapped[Decimal] = mapped_column(Numeric(14, 3))
    reason: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class SalesOrder(Base):
    __tablename__ = 'sales_orders'
    id: Mapped[int] = mapped_column(primary_key=True)
    reference: Mapped[str] = mapped_column(String(40), unique=True, index=True)
    customer_id: Mapped[int] = mapped_column(ForeignKey('customers.id'))
    product_id: Mapped[int] = mapped_column(ForeignKey('products.id'))
    quantity: Mapped[int] = mapped_column(Integer)
    unit_price: Mapped[Decimal] = mapped_column(Numeric(12, 2))
    status: Mapped[str] = mapped_column(String(30), default='confirmed')
    due_date: Mapped[datetime | None] = mapped_column(Date, nullable=True)
    notes: Mapped[str] = mapped_column(Text, default='')
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    customer: Mapped[Customer] = relationship()
    product: Mapped[Product] = relationship()


class ProductionJob(Base):
    __tablename__ = 'production_jobs'
    id: Mapped[int] = mapped_column(primary_key=True)
    reference: Mapped[str] = mapped_column(String(40), unique=True, index=True)
    order_id: Mapped[int] = mapped_column(ForeignKey('sales_orders.id'))
    planned_qty: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(30), default='planned')
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    order: Mapped[SalesOrder] = relationship()


class ProductionTask(Base):
    __tablename__ = 'production_tasks'
    id: Mapped[int] = mapped_column(primary_key=True)
    job_id: Mapped[int] = mapped_column(ForeignKey('production_jobs.id'))
    employee_id: Mapped[int] = mapped_column(ForeignKey('users.id'))
    stage: Mapped[str] = mapped_column(String(50))
    target_qty: Mapped[int] = mapped_column(Integer)
    good_qty: Mapped[int] = mapped_column(Integer, default=0)
    rejected_qty: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(30), default='assigned')
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    employee: Mapped[User] = relationship()
    job: Mapped[ProductionJob] = relationship()


class ProgressLog(Base):
    __tablename__ = 'progress_logs'
    id: Mapped[int] = mapped_column(primary_key=True)
    task_id: Mapped[int] = mapped_column(ForeignKey('production_tasks.id'))
    employee_id: Mapped[int] = mapped_column(ForeignKey('users.id'))
    good_qty: Mapped[int] = mapped_column(Integer, default=0)
    rejected_qty: Mapped[int] = mapped_column(Integer, default=0)
    note: Mapped[str] = mapped_column(Text, default='')
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class QualityInspection(Base):
    __tablename__ = 'quality_inspections'
    id: Mapped[int] = mapped_column(primary_key=True)
    job_id: Mapped[int] = mapped_column(ForeignKey('production_jobs.id'))
    inspector_id: Mapped[int] = mapped_column(ForeignKey('users.id'))
    passed_qty: Mapped[int] = mapped_column(Integer)
    failed_qty: Mapped[int] = mapped_column(Integer)
    note: Mapped[str] = mapped_column(Text, default='')
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class AuditLog(Base):
    __tablename__ = 'audit_logs'
    id: Mapped[int] = mapped_column(primary_key=True)
    actor_id: Mapped[int] = mapped_column(ForeignKey('users.id'))
    action: Mapped[str] = mapped_column(String(60))
    object_type: Mapped[str] = mapped_column(String(60))
    object_id: Mapped[int] = mapped_column(Integer)
    description: Mapped[str] = mapped_column(String(500), default='')
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
