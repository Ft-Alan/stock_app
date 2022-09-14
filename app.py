import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    portfolio = {}
    gt = 0
    rows = db.execute("SELECT symbol,shares FROM info WHERE user_id = ?", session['user_id'])
    cash = db.execute("SELECT cash FROM users WHERE id = ?", session['user_id'])[0]['cash']
    for row in rows:
        symbol, shares = row["symbol"], row["shares"]
        portfolio[symbol] = portfolio.setdefault(symbol, 0) + shares
    portfolio = {k: v for k, v in portfolio.items() if v != 0}

    for symbol, shares in portfolio.items():
        sbl = lookup(symbol)
        price = sbl["price"]
        value = shares * price
        gt += value
        portfolio[symbol] = (shares, usd(price), usd(value))

    gt += cash

    return render_template("index.html", portfolio=portfolio, cash=usd(cash), gt=usd(gt))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "GET":
        return render_template("buy.html")

    sbl = lookup(request.form.get("symbol"))
    if sbl is None:
        return apology("must provide valid symbol", 400)

    if not request.form.get("shares").isdigit():
        return apology("must be a number")

    price = sbl["price"]
    symbol = sbl["symbol"]
    shares = int(request.form.get("shares"))
    user_id = session["user_id"]

    if not request.form.get("symbol"):
        return apology("must provide symbol")

    elif not shares:
        return apology("must provide no. of shares")

    if not (shares - (shares//1)) == 0.00:
        return apology("share must be a positive integer", 400)

    try:
        if shares < 1:
            return apology("share must be a positive integer", 400)

    except ValueError:
        return apology("share must be a positive integer", 400)

    cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]['cash']

    rem = cash - price * shares
    if rem < 0:
        return apology("Not enough cash")

    else:
        db.execute("UPDATE users SET cash = ? WHERE id = ?", rem, user_id)
        db.execute("INSERT INTO info (user_id, symbol, shares, price) VALUES (?, ?, ?, ?)", user_id, symbol, shares, price)
        flash("Success")
        return redirect("/")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    rows = db.execute("SELECT * FROM info WHERE user_id = ?", session['user_id'])
    return render_template("history.html", rows=rows)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        if not request.form.get("symbol"):
            return apology("must provide symbol")
        sbl = lookup(request.form.get("symbol"))
        if not sbl:
            return apology("invalid symbol")

        return render_template("quoted.html", sbl=sbl)
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    # Forget any user_id
    session.clear()

    if request.method == "GET":
        return render_template("register.html")

    # check username and password
    username = request.form.get("username")
    password = request.form.get("password")
    confirmation = request.form.get("confirmation")

    if username == "" or len(db.execute('SELECT username FROM users WHERE username = ?', username)) > 0:
        return apology("Invalid Username")
    if password == "" or password != confirmation:
        return apology("Invalid Password")

    # Add new user to users db (includes: username and HASH of password)
    db.execute('INSERT INTO users (username, hash) VALUES(?, ?)', username, generate_password_hash(password))

    # Query database for username
    rows = db.execute("SELECT * FROM users WHERE username = ?", username)

    # Log user in, i.e. Remember that this user has logged in
    session["user_id"] = rows[0]["id"]

    # Redirect user to home page
    return redirect("/")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        if not request.form.get("symbol"):
            return apology("must provide symbol")

        elif not request.form.get("shares"):
            return apology("must provide no. of shares")

        elif int(request.form.get("shares")) < 1:
            return apology("must provide positive no. of shares")

        user_id = session["user_id"]
        portfolio = {}
        rows = db.execute("SELECT symbol, shares FROM info WHERE user_id = ?", user_id)
        for row in rows:
            sym, sha = row["symbol"], row["shares"]
            portfolio[sym] = portfolio.setdefault(sym, 0) + sha
        portfolio = {k: v for k, v in portfolio.items() if v != 0}

        symbol = request.form.get("symbol").upper()
        shares = int(request.form.get("shares"))

        if portfolio[symbol] < shares:
            return apology("You don't have enough shares")

        sbl = lookup(symbol)
        cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]['cash']
        price = sbl["price"]
        rem = cash + price * shares
        db.execute("UPDATE users SET cash = ? WHERE id = ?", rem, user_id)
        db.execute("INSERT INTO info (user_id, symbol, shares, price) VALUES (?, ?, ?, ?)", user_id, symbol, -shares, price)
        return redirect("/")
    else:
        user_id = session["user_id"]
        portfolio = {}
        rows = db.execute("SELECT symbol, shares FROM info WHERE user_id = ?", user_id)
        for row in rows:
            sym, sha = row["symbol"], row["shares"]
            portfolio[sym] = portfolio.setdefault(sym, 0) + sha
        portfolio = {k: v for k, v in portfolio.items() if v != 0}
        return render_template("sell.html", values=portfolio.keys())


@app.route("/cash", methods=["GET", "POST"])
@login_required
def cash():
    if request.method == "GET":
        return render_template("cash.html")

    user_id = session["user_id"]
    money = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]['cash']
    add1 = int(request.form.get("cash"))
    add2 = int(request.form.get("confirm"))
    if not add1:
        return apology("Amount must be entered")
    if add1 < 1:
        return apology("Amount must be positive")
    if not add2:
        return apology("Amount must be entered to confirm")
    if not add1 == add2:
        return apology("Entered Amounts doesn't match")
    money2 = money + add1
    db.execute("UPDATE users SET cash = ? WHERE id = ?", money2, user_id)
    return redirect("/")