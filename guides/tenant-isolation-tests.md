# Tenant isolation tests: the bugs no scanner finds

> Source: OTLC Guardian. Written 2026-11-10 from a security audit of a multi-customer
> portal. This guide is original to this repo, so it can be edited here.

## What this covers

A scanner matches shapes in code. These three bugs have no shape. Each one is correct
code that does the wrong thing for the business:

1. **A customer changes something that belongs to someone else.** The audit case: files
   were matched by name only, so a customer uploading `P&ID.pdf` became the newest
   revision of the company's own `P&ID.pdf`.
2. **A login that is bound to a customer is not kept to that customer's data.** The audit
   case: a customer account missing one module flag was treated as low-privilege staff
   and could read other customers' sites and tickets.
3. **A limit that resets itself.** The audit case: five wrong sign-in codes locked the
   code, but asking for a new link reset the count, so guessing never had to stop.

`guardian audit` has rules next to this class (`AUTHZ-003`, `AUTHZ-013`), and they catch
a handler that never mentions an owner or tenant at all. They cannot tell you that a
check which IS present is wrong. Only a test that acts as two different customers can.

## The rule

Every project with more than one customer, team, or account gets these tests before the
first real customer logs in. They run in CI on every commit.

## The fixture

Two customers and one staff user. Every test below uses them.

```python
# tests/conftest.py
import pytest

@pytest.fixture
def world(client, make_customer, make_staff):
    """Two customers who must never see each other, plus staff."""
    a = make_customer(name="Customer A")
    b = make_customer(name="Customer B")
    staff = make_staff()
    return {"a": a, "b": b, "staff": staff}
```

`client`, `make_customer` and `make_staff` are yours to write: an HTTP test client for
the app, and factories that create the account and return something that can log in
(`a.login()` returning auth headers is a good shape).

## Test 1: read across tenants

For EVERY endpoint that returns customer data, B asks for A's record by its real ID.

```python
import pytest

# One row per endpoint that returns customer-owned data. Add a row with every new route.
CUSTOMER_READS = [
    ("/api/v1/sites/{id}",     "site"),
    ("/api/v1/tickets/{id}",   "ticket"),
    ("/api/v1/documents/{id}", "document"),
]

@pytest.mark.parametrize("route, kind", CUSTOMER_READS)
def test_customer_cannot_read_another_customers_record(client, world, make_record, route, kind):
    theirs = make_record(kind, owner=world["a"])
    response = client.get(route.format(id=theirs.id), headers=world["b"].login())
    # 404, not 403: a 403 confirms the record exists.
    assert response.status_code == 404

def test_list_endpoints_only_return_own_records(client, world, make_record):
    make_record("ticket", owner=world["a"])
    mine = make_record("ticket", owner=world["b"])
    response = client.get("/api/v1/tickets", headers=world["b"].login())
    assert [t["id"] for t in response.json()["data"]] == [mine.id]
```

## Test 2: write across tenants, and across the customer/staff line

```python
CUSTOMER_WRITES = [
    ("put",    "/api/v1/tickets/{id}",          {"title": "changed"}),
    ("delete", "/api/v1/documents/{id}",        None),
    ("post",   "/api/v1/tickets/{id}/comments", {"body": "hello"}),
]

@pytest.mark.parametrize("method, route, body", CUSTOMER_WRITES)
def test_customer_cannot_write_another_customers_record(client, world, make_record, method, route, body):
    kind = route.split("/")[3].rstrip("s")
    theirs = make_record(kind, owner=world["a"])
    response = client.request(method, route.format(id=theirs.id), json=body, headers=world["b"].login())
    assert response.status_code == 404
    assert theirs.reload() == theirs  # nothing changed

def test_customer_upload_never_replaces_a_staff_document(client, world, make_record):
    """The name-collision case. Same file name, different owner, must stay two documents."""
    original = make_record("document", owner=world["staff"], filename="P&ID.pdf", customer=world["a"])
    client.post("/api/v1/documents", files={"file": ("P&ID.pdf", b"customer bytes")}, headers=world["a"].login())
    assert original.reload().latest_revision.uploaded_by == world["staff"].id
```

## Test 3: every account shape is still a customer

Do not test only the fully configured account. Build each combination of flags, modules
and roles a customer login can have, and run the cross-tenant read on all of them.

```python
ACCOUNT_SHAPES = [
    {"modules": ["portal"]},
    {"modules": []},                 # the audit case: a module missing
    {"modules": ["portal"], "role": None},
]

@pytest.mark.parametrize("shape", ACCOUNT_SHAPES)
def test_any_customer_bound_login_is_scoped_to_its_customer(client, world, make_login, make_record, shape):
    login = make_login(customer=world["b"], **shape)
    theirs = make_record("site", owner=world["a"])
    assert client.get(f"/api/v1/sites/{theirs.id}", headers=login.headers()).status_code == 404

@pytest.mark.parametrize("shape", ACCOUNT_SHAPES)
def test_customer_bound_login_never_reaches_staff_routes(client, world, make_login, shape):
    login = make_login(customer=world["b"], **shape)
    assert client.get("/api/v1/staff/customers", headers=login.headers()).status_code in (403, 404)
```

## Test 4: limits that must not reset

```python
def test_wrong_codes_lock_the_email_even_across_new_links(client, world):
    email = world["a"].email
    for _ in range(2):                       # two separate sign-in links
        client.post("/api/v1/auth/link", json={"email": email})
        for _ in range(5):
            client.post("/api/v1/auth/code", json={"email": email, "code": "000000"})
    # Ten wrong codes in total. A new link must not have reset the count.
    client.post("/api/v1/auth/link", json={"email": email})
    response = client.post("/api/v1/auth/code", json={"email": email, "code": world["a"].current_code()})
    assert response.status_code == 429
```

## Checklist

- [ ] Every route that returns or changes customer data has a row in `CUSTOMER_READS`
      or `CUSTOMER_WRITES`
- [ ] A new route cannot merge without its row (make the review check it)
- [ ] Cross-tenant requests return 404, not 403
- [ ] Each account shape a customer can have is in `ACCOUNT_SHAPES`
- [ ] Every counter that protects sign-in is keyed on the account, not on the link or
      the session, and has a test that tries to reset it
- [ ] Uploads from a customer never merge into a record a customer does not own

## Prompt to hand to an assistant

> List every route in this project that returns or changes data belonging to one
> customer. For each one, tell me which line scopes the query to the caller's customer.
> Where there is no such line, say so. Then add the missing rows to `CUSTOMER_READS` and
> `CUSTOMER_WRITES` in the tenant isolation tests and run them.
