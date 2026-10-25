"""Moreda ERP: a starter manufacturing-management application.

Security note: this starter is NOT an audited accounting/payroll system.
"""
import hashlib
import hmac
import os
import secrets
import uuid
from contextlib import asynccontextmanager
from datetime import date, datetime, timezone
from decimal import Decimal
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import select, func, or_, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware

load_dotenv()
from database import Base, engine, get_db, SessionLocal  # noqa: E402
from models import (User, Customer, Product, Material, StockMovement, SalesOrder,
                    ProductionJob, ProductionTask, ProgressLog, QualityInspection,
                    AuditLog, now)
from schemas import (LoginIn, UserIn, CustomerIn, ProductIn, MaterialIn, MovementIn,
                     OrderIn, OrderStatusIn, JobIn, TaskIn, ProgressIn, InspectionIn)

ROOT = Path(__file__).resolve().parent
PRODUCTION = os.getenv('APP_ENV') == 'production'
SECRET = os.getenv('SECRET_KEY', '')
if PRODUCTION and (len(SECRET) < 32 or SECRET.startswith('CHANGE_ME')):
    raise RuntimeError('SECRET_KEY must be a strong random value in production')
if not SECRET:
    SECRET = secrets.token_urlsafe(48)  # Development only; sessions reset on restart.


# scrypt avoids depending on a separate native password-hashing package.
def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1, dklen=32)
    return f'scrypt$16384${salt.hex()}${digest.hex()}'


def check_password(password: str, stored: str) -> bool:
    try:
        method, n, salt_hex, digest_hex = stored.split('$')
        if method != 'scrypt' or int(n) != 16384:
            return False
        calculated = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt_hex),
                                    n=16384, r=8, p=1, dklen=32)
        return hmac.compare_digest(calculated, bytes.fromhex(digest_hex))
    except (ValueError, TypeError):
        return False


def flush_or_conflict(db: Session):
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(409, 'Duplicate record or database constraint violation') from exc


def commit(db: Session):
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(409, 'Duplicate record or database constraint violation') from exc


def log_event(db, actor, action, kind, obj_id, description=''):
    db.add(AuditLog(actor_id=actor.id, action=action, object_type=kind,
                    object_id=obj_id, description=description[:500]))


def require_user(request: Request, db: Session = Depends(get_db)) -> User:
    uid = request.session.get('uid')
    user = db.get(User, uid) if isinstance(uid, int) else None
    if not user or not user.active:
        raise HTTPException(401, 'Please sign in')
    if request.method not in ('GET', 'HEAD', 'OPTIONS'):
        token = request.headers.get('X-CSRF-Token', '')
        saved = request.session.get('csrf', '')
        if not saved or not hmac.compare_digest(token, saved):
            raise HTTPException(403, 'Invalid session security token; reload and try again')
    return user


def require_roles(*roles):
    def dependency(user: User = Depends(require_user)):
        if user.role not in roles:
            raise HTTPException(403, 'Your role does not permit this action')
        return user
    return dependency


MANAGERS = ('admin', 'supervisor')
SALES = ('admin', 'sales')
MATERIALS = ('admin', 'inventory', 'supervisor')
QC = ('admin', 'quality', 'supervisor')


def serialize_user(user):
    return {'id': user.id, 'name': user.name, 'email': user.email, 'role': user.role,
            'active': user.active}


def serialize_order(order):
    return {'id': order.id, 'reference': order.reference,
            'customer_id': order.customer_id, 'customer': order.customer.name,
            'product_id': order.product_id, 'product': order.product.name,
            'quantity': order.quantity, 'unit_price': float(order.unit_price),
            'total': float(order.unit_price * order.quantity),
            'status': order.status, 'due_date': str(order.due_date) if order.due_date else '',
            'notes': order.notes}


def serialize_job(job):
    return {'id': job.id, 'reference': job.reference, 'order_id': job.order_id,
            'order': job.order.reference, 'product': job.order.product.name,
            'planned_qty': job.planned_qty, 'status': job.status}


def serialize_task(task):
    return {'id': task.id, 'job_id': task.job_id, 'job': task.job.reference,
            'employee_id': task.employee_id, 'employee': task.employee.name,
            'stage': task.stage, 'target_qty': task.target_qty,
            'good_qty': task.good_qty, 'rejected_qty': task.rejected_qty,
            'status': task.status,
            'percent': round(100 * task.good_qty / task.target_qty, 1)}


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)  # Initial schema only; use migrations for future changes.
    with SessionLocal() as db:
        existing = db.scalar(select(func.count(User.id)))
        if not existing:
            email = os.getenv('ADMIN_EMAIL', '').strip().lower()
            password = os.getenv('ADMIN_PASSWORD', '')
            if not email or len(password) < 12 or password.startswith('CHANGE_ME'):
                raise RuntimeError('Set ADMIN_EMAIL and ADMIN_PASSWORD (12+ chars) in environment before first start')
            db.add(User(name='Moreda Administrator', email=email,
                        password_hash=hash_password(password), role='admin'))
            db.commit()
    yield


app = FastAPI(title='Moreda ERP', version='1.0.0', lifespan=lifespan, docs_url=None, redoc_url=None)
app.add_middleware(SessionMiddleware, secret_key=SECRET, session_cookie='moreda_session',
                   max_age=60 * 60 * 8, same_site='lax', https_only=PRODUCTION)
app.mount('/static', StaticFiles(directory=str(ROOT / 'static')), name='static')


@app.middleware('http')
async def safety_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'self'; frame-ancestors 'none'"
    response.headers['Cache-Control'] = 'no-store'
    if PRODUCTION:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response


@app.get('/')
def home():
    return FileResponse(ROOT / 'static' / 'index.html')


@app.get('/healthz')
def health(db: Session = Depends(get_db)):
    db.execute(text('SELECT 1'))
    return {'ok': True}


@app.post('/api/auth/login')
def login(payload: LoginIn, request: Request, db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.email == payload.email.strip().lower()))
    if not user or not user.active or not check_password(payload.password, user.password_hash):
        raise HTTPException(401, 'Incorrect email or password')
    request.session.clear()
    request.session['uid'] = user.id
    request.session['csrf'] = secrets.token_urlsafe(32)
    return {'user': serialize_user(user), 'csrf': request.session['csrf']}


@app.get('/api/auth/me')
def me(request: Request, user: User = Depends(require_user)):
    return {'user': serialize_user(user), 'csrf': request.session['csrf']}


@app.post('/api/auth/logout')
def logout(request: Request, user: User = Depends(require_user)):
    request.session.clear()
    return {'ok': True}


@app.get('/api/users')
def users(db: Session = Depends(get_db), user: User = Depends(require_roles('admin'))):
    return [serialize_user(x) for x in db.scalars(select(User).order_by(User.name)).all()]


@app.get('/api/employees')
def employees(db: Session = Depends(get_db), user: User = Depends(require_user)):
    # Used to assign tasks; names and roles only, no private email/password.
    return [{'id': x.id, 'name': x.name, 'role': x.role} for x in db.scalars(
        select(User).where(User.active.is_(True)).order_by(User.name)).all()]


@app.post('/api/users', status_code=201)
def add_user(payload: UserIn, db: Session = Depends(get_db), user: User = Depends(require_roles('admin'))):
    record = User(name=payload.name.strip(), email=str(payload.email).lower(),
                  password_hash=hash_password(payload.password), role=payload.role)
    db.add(record)
    flush_or_conflict(db)
    log_event(db, user, 'create', 'user', record.id, record.email)
    commit(db)
    return serialize_user(record)


@app.get('/api/customers')
def customers(db: Session = Depends(get_db), user: User = Depends(require_roles('admin', 'sales', 'supervisor'))):
    return [{'id': c.id, 'name': c.name, 'contact': c.contact, 'phone': c.phone,
             'email': c.email} for c in db.scalars(select(Customer).order_by(Customer.name))]


@app.post('/api/customers', status_code=201)
def add_customer(payload: CustomerIn, db: Session = Depends(get_db), user: User = Depends(require_roles(*SALES))):
    record = Customer(**payload.model_dump())
    db.add(record); flush_or_conflict(db)
    log_event(db, user, 'create', 'customer', record.id, record.name)
    commit(db)
    return {'id': record.id}


@app.get('/api/products')
def products(db: Session = Depends(get_db), user: User = Depends(require_user)):
    return [{'id': p.id, 'sku': p.sku, 'name': p.name, 'category': p.category,
             'unit_price': float(p.unit_price), 'standard_minutes': p.standard_minutes}
            for p in db.scalars(select(Product).order_by(Product.name))]


@app.post('/api/products', status_code=201)
def add_product(payload: ProductIn, db: Session = Depends(get_db), user: User = Depends(require_roles('admin', 'sales'))):
    record = Product(**payload.model_dump())
    db.add(record); flush_or_conflict(db)
    log_event(db, user, 'create', 'product', record.id, record.sku)
    commit(db)
    return {'id': record.id}


@app.get('/api/materials')
def materials(db: Session = Depends(get_db), user: User = Depends(require_roles('admin', 'inventory', 'supervisor'))):
    return [{'id': m.id, 'sku': m.sku, 'name': m.name, 'unit': m.unit,
             'quantity': float(m.quantity), 'reorder_level': float(m.reorder_level),
             'low': m.quantity <= m.reorder_level}
            for m in db.scalars(select(Material).order_by(Material.name))]


@app.post('/api/materials', status_code=201)
def add_material(payload: MaterialIn, db: Session = Depends(get_db), user: User = Depends(require_roles(*MATERIALS))):
    record = Material(**payload.model_dump(), quantity=Decimal('0'))
    db.add(record); flush_or_conflict(db)
    log_event(db, user, 'create', 'material', record.id, record.sku)
    commit(db)
    return {'id': record.id}


@app.post('/api/materials/{material_id}/movements', status_code=201)
def move_stock(material_id: int, payload: MovementIn, db: Session = Depends(get_db), user: User = Depends(require_roles(*MATERIALS))):
    material = db.scalar(select(Material).where(Material.id == material_id).with_for_update())
    if not material:
        raise HTTPException(404, 'Material not found')
    delta = payload.quantity if payload.kind == 'in' else -payload.quantity
    if material.quantity + delta < 0:
        raise HTTPException(400, 'Insufficient stock')
    material.quantity += delta
    db.add(StockMovement(material_id=material_id, actor_id=user.id, kind=payload.kind,
                         quantity=payload.quantity, reason=payload.reason))
    log_event(db, user, 'stock_' + payload.kind, 'material', material.id, f'{payload.quantity} {material.unit}: {payload.reason}')
    commit(db)
    return {'quantity': float(material.quantity)}


@app.get('/api/materials/{material_id}/movements')
def movements(material_id: int, db: Session = Depends(get_db), user: User = Depends(require_roles(*MATERIALS))):
    return [{'id': x.id, 'kind': x.kind, 'quantity': float(x.quantity),
             'reason': x.reason, 'created_at': x.created_at.isoformat()}
            for x in db.scalars(select(StockMovement).where(StockMovement.material_id == material_id).order_by(StockMovement.id.desc()).limit(100))]


@app.get('/api/orders')
def orders(db: Session = Depends(get_db), user: User = Depends(require_roles('admin', 'sales', 'supervisor', 'quality'))):
    return [serialize_order(x) for x in db.scalars(select(SalesOrder).order_by(SalesOrder.id.desc()))]


@app.post('/api/orders', status_code=201)
def add_order(payload: OrderIn, db: Session = Depends(get_db), user: User = Depends(require_roles(*SALES))):
    if not db.get(Customer, payload.customer_id) or not db.get(Product, payload.product_id):
        raise HTTPException(400, 'Select an existing customer and product')
    record = SalesOrder(reference='ORD-' + uuid.uuid4().hex[:8].upper(), **payload.model_dump())
    db.add(record); flush_or_conflict(db)
    log_event(db, user, 'create', 'order', record.id, record.reference)
    commit(db)
    return serialize_order(record)


@app.patch('/api/orders/{order_id}/status')
def change_order_status(order_id: int, payload: OrderStatusIn, db: Session = Depends(get_db), user: User = Depends(require_roles(*SALES))):
    order = db.get(SalesOrder, order_id)
    if not order: raise HTTPException(404, 'Order not found')
    if order.status == 'dispatched':
        raise HTTPException(400, 'Dispatched orders cannot be changed in this starter')
    job = db.scalar(select(ProductionJob).where(ProductionJob.order_id == order_id))
    if payload.status == 'dispatched' and (not job or job.status != 'qc_approved'):
        raise HTTPException(400, 'Dispatch requires a production job approved by quality control')
    if payload.status == 'cancelled' and job and job.status != 'planned':
        raise HTTPException(400, 'Cannot cancel an order after production begins')
    order.status = payload.status
    log_event(db, user, 'status', 'order', order.id, payload.status)
    commit(db)
    return {'status': order.status}


@app.get('/api/jobs')
def jobs(db: Session = Depends(get_db), user: User = Depends(require_user)):
    statement = select(ProductionJob).order_by(ProductionJob.id.desc())
    if user.role == 'employee':
        statement = statement.where(ProductionJob.id.in_(select(ProductionTask.job_id).where(ProductionTask.employee_id == user.id)))
    return [serialize_job(x) for x in db.scalars(statement)]


@app.post('/api/jobs', status_code=201)
def add_job(payload: JobIn, db: Session = Depends(get_db), user: User = Depends(require_roles(*MANAGERS))):
    order = db.get(SalesOrder, payload.order_id)
    if not order: raise HTTPException(404, 'Order not found')
    if order.status in ('cancelled', 'dispatched'):
        raise HTTPException(400, 'Order is not eligible for production')
    if db.scalar(select(ProductionJob.id).where(ProductionJob.order_id == order.id)):
        raise HTTPException(409, 'This order already has a production job')
    if payload.planned_qty != order.quantity:
        raise HTTPException(400, 'Job quantity must match the order quantity in this first version')
    record = ProductionJob(reference='JOB-' + uuid.uuid4().hex[:8].upper(), **payload.model_dump())
    db.add(record); flush_or_conflict(db)
    order.status = 'in_production'
    log_event(db, user, 'create', 'job', record.id, record.reference)
    commit(db)
    return serialize_job(record)


@app.get('/api/tasks')
def tasks(db: Session = Depends(get_db), user: User = Depends(require_user)):
    statement = select(ProductionTask).order_by(ProductionTask.id.desc())
    if user.role == 'employee':
        statement = statement.where(ProductionTask.employee_id == user.id)
    return [serialize_task(x) for x in db.scalars(statement)]


@app.post('/api/tasks', status_code=201)
def add_task(payload: TaskIn, db: Session = Depends(get_db), user: User = Depends(require_roles(*MANAGERS))):
    job = db.get(ProductionJob, payload.job_id)
    employee = db.get(User, payload.employee_id)
    if not job or job.status in ('qc_approved',) or job.order.status == 'cancelled':
        raise HTTPException(400, 'Select an active production job')
    if not employee or not employee.active or employee.role not in ('employee', 'supervisor'):
        raise HTTPException(400, 'Select an active production employee')
    if payload.target_qty > job.planned_qty:
        raise HTTPException(400, 'Task quantity cannot exceed job quantity')
    record = ProductionTask(**payload.model_dump())
    db.add(record); flush_or_conflict(db)
    log_event(db, user, 'assign', 'task', record.id, f'{employee.name}: {record.stage}')
    commit(db)
    return serialize_task(record)


@app.post('/api/tasks/{task_id}/progress', status_code=201)
def progress(task_id: int, payload: ProgressIn, db: Session = Depends(get_db), user: User = Depends(require_user)):
    task = db.scalar(select(ProductionTask).where(ProductionTask.id == task_id).with_for_update())
    if not task: raise HTTPException(404, 'Task not found')
    if user.id != task.employee_id and user.role not in MANAGERS:
        raise HTTPException(403, 'You may only update your assigned tasks')
    if task.job.status == 'qc_approved' or task.job.order.status == 'cancelled':
        raise HTTPException(400, 'This production job is closed')
    if payload.good_qty + payload.rejected_qty == 0:
        raise HTTPException(400, 'Enter at least one completed or rejected unit')
    if task.good_qty + payload.good_qty > task.target_qty:
        raise HTTPException(400, 'Good units exceed the task target')
    task.good_qty += payload.good_qty
    task.rejected_qty += payload.rejected_qty
    task.status = 'completed' if task.good_qty == task.target_qty else 'in_progress'
    if task.job.status == 'planned': task.job.status = 'in_progress'
    db.add(ProgressLog(task_id=task.id, employee_id=user.id,
                       good_qty=payload.good_qty, rejected_qty=payload.rejected_qty, note=payload.note))
    log_event(db, user, 'progress', 'task', task.id, f'good={payload.good_qty}, reject={payload.rejected_qty}')
    commit(db)
    return serialize_task(task)


@app.get('/api/progress')
def progress_history(db: Session = Depends(get_db), user: User = Depends(require_user)):
    statement = select(ProgressLog).order_by(ProgressLog.id.desc()).limit(200)
    if user.role == 'employee':
        statement = statement.where(ProgressLog.task_id.in_(select(ProductionTask.id).where(ProductionTask.employee_id == user.id)))
    return [{'id': p.id, 'task_id': p.task_id, 'reported_by': p.employee_id,
             'good_qty': p.good_qty, 'rejected_qty': p.rejected_qty,
             'note': p.note, 'at': p.created_at.isoformat()} for p in db.scalars(statement)]


@app.get('/api/inspections')
def inspections(db: Session = Depends(get_db), user: User = Depends(require_roles('admin', 'quality', 'supervisor', 'sales'))):
    return [{'id': q.id, 'job_id': q.job_id, 'inspector_id': q.inspector_id,
             'passed_qty': q.passed_qty, 'failed_qty': q.failed_qty,
             'note': q.note, 'at': q.created_at.isoformat()}
            for q in db.scalars(select(QualityInspection).order_by(QualityInspection.id.desc()))]


@app.post('/api/inspections', status_code=201)
def add_inspection(payload: InspectionIn, db: Session = Depends(get_db), user: User = Depends(require_roles(*QC))):
    job = db.scalar(select(ProductionJob).where(ProductionJob.id == payload.job_id).with_for_update())
    if not job: raise HTTPException(404, 'Job not found')
    if job.status == 'qc_approved': raise HTTPException(400, 'Already approved by quality control')
    if not payload.passed_qty + payload.failed_qty:
        raise HTTPException(400, 'Enter inspected quantities')
    all_tasks = db.scalars(select(ProductionTask).where(ProductionTask.job_id == job.id)).all()
    packaging = [t for t in all_tasks if t.stage == 'Packaging']
    if not packaging or sum(t.good_qty for t in packaging) < job.planned_qty:
        raise HTTPException(400, 'Complete packaging of the full job quantity before QC')
    if any(t.status != 'completed' for t in all_tasks):
        raise HTTPException(400, 'All assigned production tasks must be completed before QC')
    past_passed = db.scalar(select(func.coalesce(func.sum(QualityInspection.passed_qty), 0)).where(QualityInspection.job_id == job.id)) or 0
    if past_passed + payload.passed_qty > job.planned_qty:
        raise HTTPException(400, 'Passed quantity would exceed the ordered job quantity')
    record = QualityInspection(**payload.model_dump(), inspector_id=user.id)
    db.add(record); flush_or_conflict(db)
    job.status = 'qc_approved' if past_passed + payload.passed_qty == job.planned_qty else 'qc_attention'
    log_event(db, user, 'inspect', 'job', job.id, f'passed={payload.passed_qty}, failed={payload.failed_qty}')
    commit(db)
    return {'id': record.id, 'job_status': job.status}


@app.get('/api/performance')
def performance(db: Session = Depends(get_db), user: User = Depends(require_user)):
    statement = select(User).where(User.active.is_(True), User.role.in_(['employee', 'supervisor'])).order_by(User.name)
    if user.role == 'employee':
        statement = statement.where(User.id == user.id)
    result = []
    for employee in db.scalars(statement):
        assigned = db.scalars(select(ProductionTask).where(ProductionTask.employee_id == employee.id)).all()
        result.append({'employee_id': employee.id, 'employee': employee.name,
                       'assigned_tasks': len(assigned),
                       'completed_tasks': sum(t.status == 'completed' for t in assigned),
                       'target_qty': sum(t.target_qty for t in assigned),
                       'good_qty': sum(t.good_qty for t in assigned),
                       'rejected_qty': sum(t.rejected_qty for t in assigned),
                       'progress_percent': round(100 * sum(t.good_qty for t in assigned) / sum(t.target_qty for t in assigned), 1) if assigned else 0})
    return result


@app.get('/api/dashboard')
def dashboard(db: Session = Depends(get_db), user: User = Depends(require_user)):
    if user.role == 'employee':
        own = db.scalars(select(ProductionTask).where(ProductionTask.employee_id == user.id)).all()
        return {'role': 'employee', 'assigned_tasks': len(own),
                'completed_tasks': sum(t.status == 'completed' for t in own),
                'good_qty': sum(t.good_qty for t in own),
                'rejected_qty': sum(t.rejected_qty for t in own)}
    stats = {
        'role': user.role,
        'open_orders': db.scalar(select(func.count(SalesOrder.id)).where(SalesOrder.status.in_(['confirmed', 'in_production']))) or 0,
        'active_jobs': db.scalar(select(func.count(ProductionJob.id)).where(ProductionJob.status.in_(['planned', 'in_progress', 'qc_attention']))) or 0,
        'completed_jobs': db.scalar(select(func.count(ProductionJob.id)).where(ProductionJob.status == 'qc_approved')) or 0,
        'active_employees': db.scalar(select(func.count(User.id)).where(User.active.is_(True), User.role.in_(['employee', 'supervisor']))) or 0,
    }
    if user.role in ('admin', 'inventory', 'supervisor'):
        stats['low_stock_items'] = db.scalar(select(func.count(Material.id)).where(Material.quantity <= Material.reorder_level)) or 0
    if user.role in ('admin', 'sales'):
        order_records = db.scalars(select(SalesOrder).where(SalesOrder.status != 'cancelled')).all()
        stats['sales_order_value_usd'] = round(sum(float(o.unit_price * o.quantity) for o in order_records), 2)
    return stats


@app.get('/api/audit')
def audit(db: Session = Depends(get_db), user: User = Depends(require_roles('admin'))):
    return [{'id': a.id, 'actor_id': a.actor_id, 'action': a.action,
             'object_type': a.object_type, 'object_id': a.object_id,
             'description': a.description, 'at': a.created_at.isoformat()}
            for a in db.scalars(select(AuditLog).order_by(AuditLog.id.desc()).limit(100))]
