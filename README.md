# CHAI - Auth API

Authentication API written in Go using Chi for a PostgreSQL database.

## Easy implementation and setup

- Configure with `JSON` and `.env` (you can check out examples)
- Just start it
- Table creation on startup
- Will deal with Redis and migrations (migranes...) in the future

## Notice

### Tested with Postman  
But watch out for:

- Postgres version matters
- Every, even subtle changes can crash the DB
- Check what is passed through as cookies vs what needs to be manually added to headers
- Some errors are frontend-oriented; it doesn't mean something went wrong, just that something needs to be sorted before full implementation

> Tip: Pay close attention to database setup and headers to avoid unexpected issues.

## Future improvements

- DB transactions for safety
- Adding Redis and figuring out DB flexibility + migrations
- Rate limiting and IP checking
- Email verification
- Other ideas may come to mind...

## Run it

1. Make sure you have PostgreSQL installed and know the username and password  
2. Have the database created and know its name  
3. Configure your `.env` and `JSON` files

```bash
go run main.go
```

If you see:

```text
"Database ok"
"Tables created/exist"
```

everything is fine.

## Have fun!