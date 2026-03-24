# CHAI - Auth API

Authentication API written in Go using Chi for a PostgreSQL database.

## Easy implementation and setup

- Configure with `JSON` and `.env` (you can check out examples)
- Use golang-migrate commands to force db version(to generate table)
- Start it and use available API endpoints that you can see in router/chi.go

## Notice

### Tested with Postman  
But watch out for:

- Postgres version
- Mailing option: it hasnt been tested yet
- Every, even subtle changes can crash the DB
- Check what is passed through as Cookies vs what needs to be manually added to Headers
- Some Errors are Frontend - oriented; it doesn't mean something went wrong, just that something needs to be sorted before full implementation

> Tip: Pay close attention to database setup and headers to avoid unexpected issues.

## Future improvements

- Finishing admin actions, /internal endpoint for /health and /metrics
- Identifier in-memory caching and rate limiting per user
- Global cleanup (in-memory and db)
- Test package for automatic testing
- Adding Redis

## Run it

1. Make sure you have PostgreSQL installed and know the username and password
2. Have the database created and know its name
3. You can create the database tables manually (schema inside database/postgresql/migrations/1_init.up) but using golang-migrate is recommended
3. Configure your `.env` and `JSON` files
4. Run

```bash
go run main.go
```

If you see:

```text
"Database ok"
```

everything is fine.

## Have fun!