import os
import tempfile
from pathlib import Path

# Environment is set before importing main/database.
TEST_DIR = tempfile.mkdtemp(prefix='moreda_tests_')
os.environ['DATABASE_URL'] = f'sqlite:///{TEST_DIR}/testing.db'
os.environ['ADMIN_EMAIL'] = 'owner@test.example'
os.environ['ADMIN_PASSWORD'] = 'SuperStrongTestingPassword!!'
os.environ['SECRET_KEY'] = 'test-secret-session-key-minimum-32-chars-long'
os.environ['APP_ENV'] = 'development'

from fastapi.testclient import TestClient  # noqa: E402
from database import Base, engine  # noqa: E402
from main import app  # noqa: E402
import pytest  # noqa: E402


@pytest.fixture
def client():
    Base.metadata.drop_all(bind=engine)
    with TestClient(app) as c:
        yield c


def signed_in(client, email='owner@test.example', password='SuperStrongTestingPassword!!'):
    resp=client.post('/api/auth/login', json={'email': email,'password': password})
    assert resp.status_code == 200, resp.text
    return {'X-CSRF-Token': resp.json()['csrf']}


def post(client, path, json, headers):
    return client.post(path, json=json, headers=headers)


def make_user(client, headers, name='Maker', email='maker@test.example', role='employee'):
    result=post(client, '/api/users', {'name':name,'email':email,'password':'LongSecureStaffPassword99!', 'role':role},headers)
    assert result.status_code == 201, result.text
    return result.json()['id']


def fixtures(client, headers):
    customer=post(client,'/api/customers',{'name':'First Capital','contact':'','phone':'','email':''},headers)
    product=post(client,'/api/products',{'sku':'LAP-01','name':'Executive Sleeve','category':'Laptop Bags','unit_price':125.99,'standard_minutes':45},headers)
    assert customer.status_code == product.status_code == 201, (customer.text,product.text)
    order=post(client,'/api/orders',{'customer_id':customer.json()['id'],'product_id':product.json()['id'],'quantity':10,'unit_price':125.99,'notes':''},headers)
    assert order.status_code == 201,order.text
    job=post(client,'/api/jobs',{'order_id':order.json()['id'],'planned_qty':10},headers)
    assert job.status_code == 201,job.text
    return order.json()['id'],job.json()['id']


def test_health_and_protection(client):
    assert client.get('/healthz').json() == {'ok':True}
    assert client.get('/api/products').status_code == 401
    headers=signed_in(client)
    assert client.get('/api/dashboard').status_code == 200
    assert client.post('/api/customers',json={'name':'No token'}).status_code == 403
    assert client.get('/').status_code == 200
    assert 'MOREDA' in client.get('/').text


def test_full_manufacturing_workflow(client):
    headers=signed_in(client)
    employee_id=make_user(client,headers)
    order_id,job_id=fixtures(client,headers)
    job=client.get('/api/jobs').json()[0]
    assert job['status']=='planned'
    task=post(client,'/api/tasks',{'job_id':job_id,'employee_id':employee_id,'stage':'Packaging','target_qty':10},headers)
    assert task.status_code==201,task.text
    task_id=task.json()['id']
    incomplete=post(client,'/api/inspections',{'job_id':job_id,'passed_qty':10,'failed_qty':0},headers)
    assert incomplete.status_code==400
    # Employee cannot see sales or change other users' tasks.
    maker=signed_in(client,'maker@test.example','LongSecureStaffPassword99!')
    assert client.get('/api/orders').status_code==403
    assert post(client,'/api/tasks',{'job_id':job_id,'employee_id':employee_id,'stage':'Cutting','target_qty':10},maker).status_code==403
    progress=post(client,f'/api/tasks/{task_id}/progress',{'good_qty':6,'rejected_qty':1,'note':'First batch'},maker)
    assert progress.status_code==201,progress.text
    assert progress.json()['percent']==60
    # Rejected units may be reworked: 4 more good units complete the target.
    assert post(client,f'/api/tasks/{task_id}/progress',{'good_qty':5,'rejected_qty':0},maker).status_code==400
    assert post(client,f'/api/tasks/{task_id}/progress',{'good_qty':4,'rejected_qty':0,'note':'Reworked'},maker).json()['status']=='completed'
    assert client.get('/api/performance').json()[0]['good_qty']==10
    admin=signed_in(client)
    qc=post(client,'/api/inspections',{'job_id':job_id,'passed_qty':10,'failed_qty':0,'note':'QC passed'},admin)
    assert qc.status_code==201,qc.text
    assert qc.json()['job_status']=='qc_approved'
    shipped=client.patch(f'/api/orders/{order_id}/status',json={'status':'dispatched'},headers=admin)
    assert shipped.status_code==200,shipped.text
    assert shipped.json()['status']=='dispatched'
    assert len(client.get('/api/audit').json())>=5


def test_stock_cannot_become_negative(client):
    headers=signed_in(client)
    m=post(client,'/api/materials',{'sku':'LEATHER-BLK','name':'Black bovine hide','unit':'sqft','reorder_level':4},headers)
    assert m.status_code==201,m.text
    mid=m.json()['id']
    assert post(client,f'/api/materials/{mid}/movements',{'kind':'out','quantity':1,'reason':'Cutting'},headers).status_code==400
    assert post(client,f'/api/materials/{mid}/movements',{'kind':'in','quantity':12,'reason':'Supplier receipt'},headers).status_code==201
    assert post(client,f'/api/materials/{mid}/movements',{'kind':'out','quantity':5,'reason':'Job usage'},headers).status_code==201
    assert client.get('/api/materials').json()[0]['quantity']==7
    assert len(client.get(f'/api/materials/{mid}/movements').json())==2


def test_dispatch_requires_qc_and_duplicate_sku_conflict(client):
    h=signed_in(client)
    order_id,job_id=fixtures(client,h)
    assert client.patch(f'/api/orders/{order_id}/status',json={'status':'dispatched'},headers=h).status_code==400
    p=post(client,'/api/products',{'sku':'LAP-01','name':'Duplicate','unit_price':3,'standard_minutes':1},h)
    assert p.status_code==409,p.text
    assert post(client,'/api/jobs',{'order_id':order_id,'planned_qty':10},h).status_code==409
