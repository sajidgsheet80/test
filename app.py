from fyers_apiv3 import fyersModel
from flask import Flask, request, render_template_string, jsonify, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import webbrowser
import pandas as pd
import os
import threading
import time
import json
import requests
import hashlib
from datetime import datetime
from pymongo import MongoClient

app = Flask(__name__)

# ===== Configuration for Render & MongoDB =====
# Render automatically sets the PORT environment variable
port = int(os.environ.get("PORT", 5000))

# Secret Key for Flask Sessions (Set this in Render Environment Variables)
app.secret_key = os.environ.get("SECRET_KEY", "sajid_secret_key_fallback")

# MongoDB Atlas Connection
# IMPORTANT: Set MONGO_URI in Render Environment Variables
# Example: mongodb+srv://user:pass@cluster0.fytyq.mongodb.net/?retryWrites=true&w=majority
MONGO_URI = os.environ.get("MONGO_URI", "mongodb+srv://sajidgsheet80:S@jid123@cluster0.fytyq.mongodb.net/?appName=Cluster0")

# Fixed API secret for all users (Set this in Render Environment Variables)
MSTOCK_API_SECRET = os.environ.get("MSTOCK_API_SECRET", "<your_api_secret_here>")

# Initialize MongoDB
try:
    client = MongoClient(MONGO_URI)
    # Ping the database to check connection
    client.admin.command('ping')
    print("✅ MongoDB Connected Successfully!")
    db = client['algo_trading_db'] # Creates a database named 'algo_trading_db'
    users_collection = db['users'] # Collection for user login info
    credentials_collection = db['user_credentials'] # Collection for API keys
except Exception as e:
    print(f"❌ MongoDB Connection Error: {e}")
    # Fallback or exit logic if needed

# ---- User Management Functions (MongoDB) ----

def save_user(username, password, email):
    """Saves a new user to MongoDB."""
    if users_collection.find_one({'username': username}):
        return False # User exists
    hashed_pw = generate_password_hash(password)
    users_collection.insert_one({
        'username': username,
        'password': hashed_pw,
        'email': email
    })
    return True

def get_user(username):
    """Retrieves user from MongoDB."""
    user = users_collection.find_one({'username': username})
    if user:
        return {'username': user['username'], 'password': user['password'], 'email': user['email']}
    return None

def verify_user(username, password):
    """Verifies user login credentials."""
    user = get_user(username)
    if user and check_password_hash(user['password'], password):
        return user
    return None

def save_user_credentials(username, client_id=None, secret_key=None, auth_code=None, mstock_api_key=None):
    """Saves or updates user API credentials in MongoDB."""
    update_fields = {}
    if client_id is not None: update_fields['client_id'] = client_id
    if secret_key is not None: update_fields['secret_key'] = secret_key
    if auth_code is not None: update_fields['auth_code'] = auth_code
    if mstock_api_key is not None: update_fields['mstock_api_key'] = mstock_api_key

    if update_fields:
        credentials_collection.update_one(
            {'username': username},
            {'$set': update_fields},
            upsert=True
        )

def get_user_credentials(username):
    """Retrieves user API credentials from MongoDB."""
    creds = credentials_collection.find_one({'username': username})
    if creds:
        return {
            'client_id': creds.get('client_id', ''),
            'secret_key': creds.get('secret_key', ''),
            'auth_code': creds.get('auth_code', ''),
            'mstock_api_key': creds.get('mstock_api_key', '')
        }
    # Return default empty dict if not found
    return {
        'client_id': '', 
        'secret_key': '', 
        'auth_code': '',
        'mstock_api_key': ''
    }

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated_function

# ---- User-specific sessions (In-Memory) ----
# Note: On Render free tier, if the service sleeps, this dictionary resets.
user_sessions = {}

def get_user_session(username):
    if username not in user_sessions:
        user_sessions[username] = {
            'fyers': None,
            'atm_strike': None,
            'initial_data': None,
            'atm_ce_plus20': 20,
            'atm_pe_plus20': 20,
            'symbol_prefix': 'NSE:NIFTY26FEB',
            'selected_index': 'NSE:NIFTY50-INDEX',
            'signals': [],
            'placed_orders': set(),
            'open_orders': [],
            'bot_running': False,
            'bot_thread': None,
            'redirect_uri': f'http://127.0.0.1:5000/callback/{username}', # Update this for production URL if needed
            'quantity': 75,
            'ce_offset': -300,
            'pe_offset': 300,
            'mstock_access_token': None,
            'mstock_access_token_expiry': None,
            'mstock_refresh_token': None,
            'mstock_refresh_token_expiry': None
        }
    return user_sessions[username]

# ===== mStock Authentication Routes =====
@app.route("/mstock/login", methods=["GET", "POST"])
@login_required
def login_mstock():
    """OTP-based m.Stock authentication"""
    username = session['username']
    user_sess = get_user_session(username)
    creds = get_user_credentials(username)
    
    if not creds or not creds['mstock_api_key']:
        return jsonify({
            "status": "error",
            "message": "mStock API key not configured. Please setup your mStock credentials first."
        }), 400
    
    if request.method == "GET":
        access_token = user_sess.get('mstock_access_token')
        if access_token and user_sess.get('mstock_access_token_expiry', 0) > time.time():
            return jsonify({
                "status": "authenticated",
                "access_token": access_token,
                "access_token_expiry": user_sess.get('mstock_access_token_expiry'),
                "refresh_token": user_sess.get('mstock_refresh_token'),
                "refresh_token_expiry": user_sess.get('mstock_refresh_token_expiry')
            })
        else:
            return jsonify({
                "status": "not_authenticated",
                "message": "Please provide OTP to authenticate"
            })
    
    # POST request - authenticate with OTP
    totp = request.form.get("totp", "").strip() or request.json.get("totp", "").strip()
    if not totp:
        return jsonify({
            "status": "error",
            "message": "OTP is required"
        }), 400
    
    checksum = hashlib.sha256(f"{creds['mstock_api_key']}{totp}{MSTOCK_API_SECRET}".encode()).hexdigest()
    headers = {'X-Mirae-Version': '1', 'Content-Type': 'application/x-www-form-urlencoded'}
    data = {'api_key': creds['mstock_api_key'], 'totp': totp, 'checksum': checksum}
    
    try:
        response = requests.post(
            'https://api.mstock.trade/openapi/typea/session/verifytotp',
            headers=headers,
            data=data
        )
        resp_json = response.json()
        
        if resp_json.get("status") == "success":
            access_token = resp_json["data"]["access_token"]
            access_token_expiry = time.time() + resp_json["data"].get("expires_in", 3600)
            user_sess['mstock_access_token'] = access_token
            user_sess['mstock_access_token_expiry'] = access_token_expiry
            
            if "refresh_token" in resp_json["data"]:
                refresh_token = resp_json["data"]["refresh_token"]
                refresh_token_expiry = time.time() + resp_json["data"].get("refresh_token_expires_in", 86400)
                user_sess['mstock_refresh_token'] = refresh_token
                user_sess['mstock_refresh_token_expiry'] = refresh_token_expiry
                
                return jsonify({
                    "status": "success",
                    "message": "mStock Authentication successful",
                    "access_token": access_token,
                    "access_token_expiry": access_token_expiry,
                    "refresh_token": refresh_token,
                    "refresh_token_expiry": refresh_token_expiry
                })
            else:
                return jsonify({
                    "status": "success",
                    "message": "mStock Authentication successful",
                    "access_token": access_token,
                    "access_token_expiry": access_token_expiry
                })
        else:
            return jsonify({
                "status": "error",
                "message": resp_json.get("message", "Failed to generate session")
            }), 400
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Error verifying OTP: {str(e)}"
        }), 500

@app.route("/mstock/refresh_token", methods=["POST"])
@login_required
def refresh_mstock_token():
    """Refresh mStock access token using refresh token"""
    username = session['username']
    user_sess = get_user_session(username)
    refresh_token = user_sess.get('mstock_refresh_token')
    
    if not refresh_token:
        return jsonify({
            "status": "error",
            "message": "No refresh token available. Please authenticate first."
        }), 400
    
    try:
        headers = {
            'X-Mirae-Version': '1',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        data = {
            'api_key': get_user_credentials(username)['mstock_api_key'],
            'refresh_token': refresh_token
        }
        
        response = requests.post(
            'https://api.mstock.trade/openapi/typea/session/refresh',
            headers=headers,
            data=data
        )
        
        resp_json = response.json()
        if resp_json.get("status") == "success":
            access_token = resp_json["data"]["access_token"]
            access_token_expiry = time.time() + resp_json["data"].get("expires_in", 3600)
            user_sess['mstock_access_token'] = access_token
            user_sess['mstock_access_token_expiry'] = access_token_expiry
            
            if "refresh_token" in resp_json["data"]:
                new_refresh_token = resp_json["data"]["refresh_token"]
                refresh_token_expiry = time.time() + resp_json["data"].get("refresh_token_expires_in", 86400)
                user_sess['mstock_refresh_token'] = new_refresh_token
                user_sess['mstock_refresh_token_expiry'] = refresh_token_expiry
                
                return jsonify({
                    "status": "success",
                    "message": "Token refreshed successfully",
                    "access_token": access_token,
                    "access_token_expiry": access_token_expiry,
                    "refresh_token": new_refresh_token,
                    "refresh_token_expiry": refresh_token_expiry
                })
            else:
                return jsonify({
                    "status": "success",
                    "message": "Token refreshed successfully",
                    "access_token": access_token,
                    "access_token_expiry": access_token_expiry
                })
        else:
            return jsonify({
                "status": "error",
                "message": resp_json.get("message", "Failed to refresh token")
            }), 400
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Error refreshing token: {str(e)}"
        }), 500

@app.route("/mstock/logout", methods=["POST"])
@login_required
def logout_mstock():
    """Logout from mStock and clear session"""
    username = session['username']
    user_sess = get_user_session(username)
    user_sess['mstock_access_token'] = None
    user_sess['mstock_access_token_expiry'] = None
    user_sess['mstock_refresh_token'] = None
    user_sess['mstock_refresh_token_expiry'] = None
    
    return jsonify({
        "status": "success",
        "message": "Logged out from mStock successfully"
    })

@app.route("/mstock/status", methods=["GET"])
@login_required
def mstock_status():
    """Check mStock authentication status"""
    username = session['username']
    user_sess = get_user_session(username)
    access_token = user_sess.get('mstock_access_token')
    
    if access_token and user_sess.get('mstock_access_token_expiry', 0) > time.time():
        return jsonify({
            "status": "authenticated",
            "access_token": access_token,
            "access_token_expiry": user_sess.get('mstock_access_token_expiry'),
            "refresh_token": user_sess.get('mstock_refresh_token'),
            "refresh_token_expiry": user_sess.get('mstock_refresh_token_expiry')
        })
    else:
        return jsonify({
            "status": "not_authenticated",
            "message": "No active mStock session"
        })

# New route for mStock authentication UI
@app.route("/mstock_auth", methods=["GET", "POST"])
@login_required
def mstock_auth_page():
    """m.Stock authentication UI page"""
    username = session['username']
    user_sess = get_user_session(username)
    creds = get_user_credentials(username)
    access_token = user_sess.get('mstock_access_token')
    error = None

    if request.method == "POST" and not access_token:
        totp = request.form.get("totp", "").strip()
        if not totp:
            error = "OTP is required!"
        else:
            if not creds or not creds['mstock_api_key']:
                error = "mStock API key not configured. Please setup your mStock credentials first."
            else:
                checksum = hashlib.sha256(f"{creds['mstock_api_key']}{totp}{MSTOCK_API_SECRET}".encode()).hexdigest()
                headers = {'X-Mirae-Version': '1', 'Content-Type': 'application/x-www-form-urlencoded'}
                data = {'api_key': creds['mstock_api_key'], 'totp': totp, 'checksum': checksum}
                try:
                    response = requests.post(
                        'https://api.mstock.trade/openapi/typea/session/verifytotp',
                        headers=headers,
                        data=data
                    )
                    resp_json = response.json()
                    if resp_json.get("status") == "success":
                        access_token = resp_json["data"]["access_token"]
                        access_token_expiry = time.time() + resp_json["data"].get("expires_in", 3600)
                        user_sess['mstock_access_token'] = access_token
                        user_sess['mstock_access_token_expiry'] = access_token_expiry
                        
                        if "refresh_token" in resp_json["data"]:
                            refresh_token = resp_json["data"]["refresh_token"]
                            refresh_token_expiry = time.time() + resp_json["data"].get("refresh_token_expires_in", 86400)
                            user_sess['mstock_refresh_token'] = refresh_token
                            user_sess['mstock_refresh_token_expiry'] = refresh_token_expiry
                    else:
                        error = resp_json.get("message", "Failed to generate session")
                except Exception as e:
                    error = f"Error verifying OTP: {str(e)}"

    return render_template_string(MSTOCK_AUTH_TEMPLATE, access_token=access_token, error=error, mstock_api_key=creds['mstock_api_key'] if creds else "")

# New route for mStock option chain page
@app.route("/mstock_option_chain")
@login_required
def mstock_option_chain_page():
    """Display mStock option chain page (only after login)"""
    username = session['username']
    user_sess = get_user_session(username)
    access_token = user_sess.get('mstock_access_token')
    if not access_token:
        return "<h3>⚠ Please authenticate with mStock first. <a href='/mstock_auth'>Go to mStock Authentication</a></h3>"
    return render_template_string(MSTOCK_OPTION_CHAIN_TEMPLATE)

# New route for fetching mStock option chain data
@app.route("/fetch_mstock_option_chain")
@login_required
def fetch_mstock_option_chain():
    """Fetch live option chain data from m.Stock API"""
    username = session['username']
    user_sess = get_user_session(username)
    creds = get_user_credentials(username)
    access_token = user_sess.get('mstock_access_token')
    
    if not access_token:
        return jsonify({"error": "Please authenticate with mStock first!"})

    try:
        # Example endpoint (replace with real m.Stock option chain endpoint)
        url = "https://api.mstock.trade/api/optionchain"
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
            "X-Mirae-Version": "1"
        }
        payload = {"symbol": "NSE:NIFTY50-INDEX", "strikecount": 20}
        resp = requests.post(url, headers=headers, json=payload)
        data = resp.json()

        if "data" not in data or "optionsChain" not in data["data"]:
            return jsonify({"error": f"Invalid response: {data}"})

        df = pd.DataFrame(data["data"]["optionsChain"])
        df_pivot = df.pivot_table(
            index="strike_price",
            columns="option_type",
            values=["ltp", "oi", "ltpch", "oich"],  # Include OI, change and OI change
            aggfunc="first"
        ).reset_index()
        df_pivot = df_pivot.rename(columns={
            "ltp_CE": "CE_LTP", 
            "ltp_PE": "PE_LTP", 
            "oi_CE": "CE_OI", 
            "oi_PE": "PE_OI", 
            "ltpch_CE": "CE_Chng", 
            "ltpch_PE": "PE_Chng",
            "oich_CE": "CE_OI_Chng",
            "oich_PE": "PE_OI_Chng"
        })

        return df_pivot.to_json(orient="records")

    except Exception as e:
        return jsonify({"error": str(e)})

# ===== Fyers Authentication Routes =====
@app.route("/fyers_auth", methods=["GET", "POST"])
@login_required
def fyers_auth():
    """Fyers authentication page with login button"""
    username = session['username']
    creds = get_user_credentials(username)
    user_sess = get_user_session(username)
    
    if request.method == "POST":
        if not creds or not creds['client_id'] or not creds['secret_key']:
            return render_template_string(FYERS_AUTH_TEMPLATE, 
                                         error="Please setup your Fyers credentials first!",
                                         show_login_button=False)
        
        appSession = fyersModel.SessionModel(
            client_id=creds['client_id'],
            secret_key=creds['secret_key'],
            redirect_uri=user_sess['redirect_uri'],
            response_type="code",
            grant_type="authorization_code",
            state="sample"
        )
        
        login_url = appSession.generate_authcode()
        return redirect(login_url)
    
    # Check if Fyers is already initialized
    is_authenticated = user_sess['fyers'] is not None
    
    return render_template_string(FYERS_AUTH_TEMPLATE, 
                                is_authenticated=is_authenticated,
                                show_login_button=True)

# ---- Fyers Functions ----
def init_fyers_for_user(username, client_id, secret_key, auth_code):
    user_sess = get_user_session(username)
    try:
        appSession = fyersModel.SessionModel(
            client_id=client_id,
            secret_key=secret_key,
            redirect_uri=user_sess['redirect_uri'],
            response_type="code",
            grant_type="authorization_code",
            state="sample"
        )
        appSession.set_token(auth_code)
        token_response = appSession.generate_token()
        access_token = token_response.get("access_token")
        if not access_token:
            print(f"❌ Failed to get access token for {username}")
            return False

        user_sess['fyers'] = fyersModel.FyersModel(
            client_id=client_id,
            token=access_token,
            is_async=False,
            log_path=""
        )
        print(f"✅ Fyers initialized for {username}")
        return True
    except Exception as e:
        print(f"❌ Failed to init Fyers for {username}:", e)
        return False

def set_atm_strike(username):
    """Set ATM strike based on current market price"""
    user_sess = get_user_session(username)
    
    if user_sess['fyers'] is None:
        print(f"❌ Fyers not initialized for {username}")
        return False
    
    try:
        data = {"symbol": user_sess['selected_index'], "strikecount": 20, "timestamp": ""}
        response = user_sess['fyers'].optionchain(data=data)
        
        if "data" not in response or "optionsChain" not in response["data"]:
            print(f"❌ Failed to get option chain for ATM calculation for {username}")
            return False
            
        options_data = response["data"]["optionsChain"]
        if not options_data:
            print(f"❌ No options data for ATM calculation for {username}")
            return False
            
        df = pd.DataFrame(options_data)
        nifty_spot = response["data"].get("underlyingValue", None)
        
        if nifty_spot is None:
            nifty_spot = df["strike_price"].iloc[len(df) // 2]
        
        user_sess['atm_strike'] = min(df["strike_price"], key=lambda x: abs(x - nifty_spot))
        
        df_pivot = df.pivot_table(
            index="strike_price",
            columns="option_type",
            values=["ltp", "ltpch", "oich", "volume", "oi"],  # Added 'oi' for Open Interest
            aggfunc="first"
        ).reset_index()
        
        df_pivot.columns = [f"{col[0]}_{col[1]}" if col[1] else col[0] for col in df_pivot.columns]
        df_pivot = df_pivot.rename(columns={
            "ltp_CE": "CE_LTP",
            "ltp_PE": "PE_LTP",
            "ltpch_CE": "CE_Chng",
            "ltpch_PE": "PE_Chng",
            "oich_CE": "CE_OI_Chng",
            "oich_PE": "PE_OI_Chng",
            "volume_CE": "CE_VOLUME",
            "volume_PE": "PE_VOLUME",
            "oi_CE": "CE_OI",
            "oi_PE": "PE_OI"
        })
        
        user_sess['initial_data'] = df_pivot.to_dict(orient="records")
        user_sess['signals'].clear()
        user_sess['placed_orders'].clear()
        
        print(f"✅ ATM strike set to {user_sess['atm_strike']} for {username}")
        return True
        
    except Exception as e:
        print(f"❌ Error setting ATM strike for {username}: {e}")
        return False

def place_mstock_order(username, symbol, transaction_type, quantity, order_type="MARKET", price=0, product="MIS"):
    """Place an order with mStock broker"""
    user_sess = get_user_session(username)
    creds = get_user_credentials(username)
    access_token = user_sess.get('mstock_access_token')
    
    if not access_token:
        print(f"❌ mStock not authenticated for {username}")
        return None
    
    try:
        # Prepare order data
        data = {
            'tradingsymbol': symbol,
            'exchange': 'NFO',  # Assuming NFO for options
            'transaction_type': transaction_type,  # BUY or SELL
            'order_type': order_type,  # MARKET, LIMIT, etc.
            'quantity': quantity,
            'product': product,  # MIS for intraday
            'validity': 'DAY',
            'price': price,
            'variety': 'regular'  # Regular order
        }
        
        # Prepare headers
        headers = {
            'X-Mirae-Version': '1',
            'Authorization': f'token {creds["mstock_api_key"]}:{access_token}',
            'Content-Type': 'application/x-www-form-urlencoded',
        }
        
        # Make API request
        response = requests.post(
            f'https://api.mstock.trade/openapi/typea/orders/regular',
            headers=headers,
            data=data
        )
        
        resp_json = response.json()
        
        if resp_json.get("status") == "success":
            order_id = resp_json.get("data", {}).get("orderid")
            print(f"✅ mStock order placed for {username}: {order_id}")
            
            return {
                "status": "success",
                "order_id": order_id,
                "broker": "mStock"
            }
        else:
            error_message = resp_json.get("message", "Failed to place order")
            print(f"❌ mStock order failed for {username}: {error_message}")
            return {
                "status": "error",
                "message": error_message,
                "broker": "mStock"
            }
            
    except Exception as e:
        print(f"❌ mStock order error for {username}: {e}")
        return {
            "status": "error",
            "message": str(e),
            "broker": "mStock"
        }

def place_order(username, symbol, price, side):
    """Place order with both Fyers and mStock brokers"""
    user_sess = get_user_session(username)
    fyers_response = None
    mstock_response = None
    
    # Place order with Fyers (existing code)
    try:
        if user_sess['fyers'] is None:
            print(f"❌ Fyers not initialized for {username}")
            fyers_response = {"status": "error", "message": "Fyers not initialized"}
        else:
            data = {
                "symbol": symbol,
                "qty": user_sess['quantity'],
                "type": 1,
                "side": side,
                "productType": "INTRADAY",
                "limitPrice": price,
                "stopPrice": 0,
                "validity": "DAY",
                "disclosedQty": 0,
                "offlineOrder": False,
                "orderTag": "signalorder"
            }
            fyers_response = user_sess['fyers'].place_order(data=data)
            print(f"✅ Fyers order placed for {username}:", fyers_response)
    except Exception as e:
        print(f"❌ Fyers order error for {username}:", e)
        fyers_response = {"status": "error", "message": str(e)}
    
    # Place order with mStock
    try:
        # Convert Fyers symbol format to mStock format if needed
        mstock_symbol = symbol
        if ":" in symbol:  # Convert NSE:NIFTY25-25000CE to NIFTY25N1124500CE format
            parts = symbol.split(":")
            if len(parts) > 1:
                mstock_symbol = parts[1].replace("-", "")
        
        # Convert side (1=BUY, -1=SELL) to transaction_type
        transaction_type = "BUY" if side == 1 else "SELL"
        
        # Place the order with mStock
        mstock_response = place_mstock_order(
            username, 
            mstock_symbol, 
            transaction_type, 
            user_sess['quantity'],
            order_type="LIMIT" if price > 0 else "MARKET",
            price=price
        )
    except Exception as e:
        print(f"❌ mStock order error for {username}:", e)
        mstock_response = {"status": "error", "message": str(e), "broker": "mStock"}
    
    # Return both responses
    return {
        "fyers": fyers_response,
        "mstock": mstock_response
    }

def process_option_chain(username, df_pivot, response):
    """Process option chain data and place orders with both brokers if conditions are met"""
    user_sess = get_user_session(username)

    if user_sess['atm_strike'] is None:
        print(f"❌ ATM strike not set for {username}")
        return

    ce_target_strike = user_sess['atm_strike'] + user_sess['ce_offset']
    pe_target_strike = user_sess['atm_strike'] + user_sess['pe_offset']

    for row in df_pivot.itertuples():
        strike = row.strike_price
        ce_ltp = getattr(row, "CE_LTP", None)
        pe_ltp = getattr(row, "PE_LTP", None)

        if strike == ce_target_strike and ce_ltp is not None:
            initial_ce = next((item["CE_LTP"] for item in user_sess['initial_data'] if item["strike_price"] == strike), None)
            if initial_ce is not None and ce_ltp > initial_ce + user_sess['atm_ce_plus20']:
                signal_name = f"CE_OFFSET_{strike}"
                if signal_name not in user_sess['placed_orders']:
                    user_sess['signals'].append(f"{strike} {ce_ltp} CE Offset Strike")
                    # Place order with both brokers
                    place_order(username, f"{user_sess['symbol_prefix']}{strike}CE", ce_ltp, side=1)
                    user_sess['placed_orders'].add(signal_name)

        if strike == pe_target_strike and pe_ltp is not None:
            initial_pe = next((item["PE_LTP"] for item in user_sess['initial_data'] if item["strike_price"] == strike), None)
            if initial_pe is not None and pe_ltp > initial_pe + user_sess['atm_pe_plus20']:
                signal_name = f"PE_OFFSET_{strike}"
                if signal_name not in user_sess['placed_orders']:
                    user_sess['signals'].append(f"{strike} {pe_ltp} PE Offset Strike")
                    # Place order with both brokers
                    place_order(username, f"{user_sess['symbol_prefix']}{strike}PE", pe_ltp, side=1)
                    user_sess['placed_orders'].add(signal_name)

def background_bot_worker(username):
    """Background bot worker that processes option chain and places orders"""
    user_sess = get_user_session(username)
    print(f"🤖 Background bot started for {username}")

    while user_sess['bot_running']:
        if user_sess['fyers'] is None:
            time.sleep(5)
            continue

        try:
            data = {"symbol": user_sess['selected_index'], "strikecount": 20, "timestamp": ""}
            response = user_sess['fyers'].optionchain(data=data)

            if "data" not in response or "optionsChain" not in response["data"]:
                time.sleep(2)
                continue

            options_data = response["data"]["optionsChain"]
            if not options_data:
                time.sleep(2)
                continue

            df = pd.DataFrame(options_data)

            df_pivot = df.pivot_table(
                index="strike_price",
                columns="option_type",
                values=["ltp", "ltpch", "oich", "volume", "oi"],  # Added 'oi' for Open Interest
                aggfunc="first"
            ).reset_index()

            df_pivot.columns = [f"{col[0]}_{col[1]}" if col[1] else col[0] for col in df_pivot.columns]

            df_pivot = df_pivot.rename(columns={
                "ltp_CE": "CE_LTP",
                "ltp_PE": "PE_LTP",
                "ltpch_CE": "CE_Chng",
                "ltpch_PE": "PE_Chng",
                "oich_CE": "CE_OI_Chng",
                "oich_PE": "PE_OI_Chng",
                "volume_CE": "CE_VOLUME",
                "volume_PE": "PE_VOLUME",
                "oi_CE": "CE_OI",
                "oi_PE": "PE_OI"
            })

            process_option_chain(username, df_pivot, response)

        except Exception as e:
            print(f"❌ Background bot error for {username}: {e}")

        time.sleep(2)

    print(f"🤖 Background bot stopped for {username}")

# ---- Auth Routes ----
@app.route('/sp', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')

        if not username or not password or not email:
            return render_template_string(SIGNUP_TEMPLATE, error="All fields are required!")

        if get_user(username):
            return render_template_string(SIGNUP_TEMPLATE, error="Username already exists!")

        save_user(username, password, email)
        return redirect(url_for('login_page'))

    return render_template_string(SIGNUP_TEMPLATE)

@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = verify_user(username, password)

        if user:
            session['username'] = user['username']
            session['email'] = user['email']

            creds = get_user_credentials(username)
            if creds and creds['client_id'] and creds['secret_key'] and creds['auth_code']:
                if init_fyers_for_user(username, creds['client_id'], creds['secret_key'], creds['auth_code']):
                    set_atm_strike(username)

            return redirect(url_for('index'))
        else:
            return render_template_string(LOGIN_TEMPLATE, error="Invalid credentials!")

    return render_template_string(LOGIN_TEMPLATE)

@app.route('/logout')
def logout():
    username = session.get('username')
    if username and username in user_sessions:
        user_sessions[username]['bot_running'] = False
    session.clear()
    return redirect(url_for('login_page'))

# ---- Main App Routes ----
@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    username = session['username']
    user_sess = get_user_session(username)
    
    # Check Fyers authentication status
    fyers_authenticated = user_sess['fyers'] is not None

    if request.method == "POST":
        try:
            user_sess['atm_ce_plus20'] = float(request.form.get("atm_ce_plus20", 20))
        except (ValueError, TypeError):
            user_sess['atm_ce_plus20'] = 20
        try:
            user_sess['atm_pe_plus20'] = float(request.form.get("atm_pe_plus20", 20))
        except (ValueError, TypeError):
            user_sess['atm_pe_plus20'] = 20
        try:
            user_sess['quantity'] = int(request.form.get("quantity", 75))
        except (ValueError, TypeError):
            user_sess['quantity'] = 75
        try:
            user_sess['ce_offset'] = int(request.form.get("ce_offset", -300))
        except (ValueError, TypeError):
            user_sess['ce_offset'] = -300
        try:
            user_sess['pe_offset'] = int(request.form.get("pe_offset", 300))
        except (ValueError, TypeError):
            user_sess['pe_offset'] = 300

        prefix = request.form.get("symbol_prefix")
        if prefix:
            user_sess['symbol_prefix'] = prefix.strip()

    if user_sess['atm_strike'] is None and user_sess['fyers'] is not None:
        set_atm_strike(username)

    return render_template_string(
        MAIN_TEMPLATE,
        atm_ce_plus20=user_sess['atm_ce_plus20'],
        atm_pe_plus20=user_sess['atm_pe_plus20'],
        symbol_prefix=user_sess['symbol_prefix'],
        bot_running=user_sess['bot_running'],
        username=username,
        quantity=user_sess['quantity'],
        ce_offset=user_sess['ce_offset'],
        pe_offset=user_sess['pe_offset'],
        atm_strike=user_sess['atm_strike'],
        fyers_authenticated=fyers_authenticated
    )

@app.route("/setup_credentials", methods=["GET", "POST"])
@login_required
def setup_credentials():
    username = session['username']
    creds = get_user_credentials(username)

    if request.method == "POST":
        client_id = request.form.get("client_id")
        secret_key = request.form.get("secret_key")
        mstock_api_key = request.form.get("mstock_api_key")

        if client_id and secret_key:
            save_user_credentials(username, client_id=client_id, secret_key=secret_key, mstock_api_key=mstock_api_key)
            return redirect(url_for('fyers_login'))

    return render_template_string(CREDENTIALS_TEMPLATE,
                                   client_id=creds['client_id'] if creds else "",
                                   secret_key=creds['secret_key'] if creds else "",
                                   mstock_api_key=creds['mstock_api_key'] if creds else "")

@app.route("/fyers_login")
@login_required
def fyers_login():
    username = session['username']
    creds = get_user_credentials(username)
    user_sess = get_user_session(username)

    if not creds or not creds['client_id'] or not creds['secret_key']:
        return redirect(url_for('setup_credentials'))

    appSession = fyersModel.SessionModel(
        client_id=creds['client_id'],
        secret_key=creds['secret_key'],
        redirect_uri=user_sess['redirect_uri'],
        response_type="code",
        grant_type="authorization_code",
        state="sample"
    )

    login_url = appSession.generate_authcode()
    webbrowser.open(login_url, new=1)
    return redirect(login_url)

@app.route("/callback/<username>")
def callback(username):
    auth_code = request.args.get("auth_code")
    if auth_code:
        creds = get_user_credentials(username)
        if creds:
            save_user_credentials(username, auth_code=auth_code)
            if init_fyers_for_user(username, creds['client_id'], creds['secret_key'], auth_code):
                set_atm_strike(username)
                return "<h2>✅ Authentication Successful! You can return to app 🚀</h2>"
    return "❌ Authentication failed. Please retry."

@app.route("/fetch")
@login_required
def fetch_option_chain():
    username = session['username']
    user_sess = get_user_session(username)

    if user_sess['fyers'] is None:
        return jsonify({"error": "⚠ Please setup credentials and login first!"})

    if user_sess['atm_strike'] is None:
        if not set_atm_strike(username):
            return jsonify({"error": "Failed to set ATM strike. Please try again."})

    try:
        data = {"symbol": user_sess['selected_index'], "strikecount": 20, "timestamp": ""}
        response = user_sess['fyers'].optionchain(data=data)

        if "data" not in response or "optionsChain" not in response["data"]:
            return jsonify({"error": f"Invalid response from API"})

        options_data = response["data"]["optionsChain"]
        if not options_data:
            return jsonify({"error": "No options data found!"})

        df = pd.DataFrame(options_data)

        df_pivot = df.pivot_table(
            index="strike_price",
            columns="option_type",
            values=["ltp", "ltpch", "oich", "volume", "oi"],  # Added 'oi' for Open Interest
            aggfunc="first"
        ).reset_index()

        df_pivot.columns = [f"{col[0]}_{col[1]}" if col[1] else col[0] for col in df_pivot.columns]

        df_pivot = df_pivot.rename(columns={
            "ltp_CE": "CE_LTP",
            "ltp_PE": "PE_LTP",
            "ltpch_CE": "CE_Chng",
            "ltpch_PE": "PE_Chng",
            "oich_CE": "CE_OI_Chng",
            "oich_PE": "PE_OI_Chng",
            "volume_CE": "CE_VOLUME",
            "volume_PE": "PE_VOLUME",
            "oi_CE": "CE_OI",
            "oi_PE": "PE_OI"
        })

        process_option_chain(username, df_pivot, response)

        result = df_pivot.to_json(orient="records")
        result_dict = json.loads(result)
        result_dict.append({"atm_strike": user_sess['atm_strike']})
        
        return jsonify(result_dict)
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route("/start_bot", methods=["POST"])
@login_required
def start_bot():
    username = session['username']
    user_sess = get_user_session(username)

    if user_sess['fyers'] is None:
        return jsonify({"error": "⚠️ Please login first!"})

    if user_sess['bot_running']:
        return jsonify({"error": "⚠️ Bot is already running!"})

    if user_sess['atm_strike'] is None:
        if not set_atm_strike(username):
            return jsonify({"error": "Failed to set ATM strike. Please try again."})

    user_sess['bot_running'] = True
    user_sess['bot_thread'] = threading.Thread(target=background_bot_worker, args=(username,), daemon=True)
    user_sess['bot_thread'].start()

    return jsonify({"message": "✅ Bot started! Running in background!"})

@app.route("/stop_bot", methods=["POST"])
@login_required
def stop_bot():
    username = session['username']
    user_sess = get_user_session(username)
    user_sess['bot_running'] = False
    return jsonify({"message": "✅ Bot stopped!"})

@app.route("/bot_status")
@login_required
def bot_status():
    username = session['username']
    user_sess = get_user_session(username)
    return jsonify({
        "running": user_sess['bot_running'],
        "signals": user_sess['signals'],
        "placed_orders": list(user_sess['placed_orders']),
        "atm_strike": user_sess['atm_strike']
    })

@app.route("/reset", methods=["POST"])
@login_required
def reset_orders():
    username = session['username']
    user_sess = get_user_session(username)
    
    user_sess['placed_orders'].clear()
    user_sess['signals'].clear()
    user_sess['atm_strike'] = None
    user_sess['initial_data'] = None
    
    if user_sess['fyers'] is not None:
        set_atm_strike(username)
    
    return jsonify({"message": "✅ Reset successful! ATM strike updated."})

# New routes for dual broker operations
@app.route("/place_dual_order", methods=["POST"])
@login_required
def place_dual_order():
    username = session['username']
    
    # Get order parameters from request
    symbol = request.json.get('symbol')
    price = float(request.json.get('price', 0))
    side = int(request.json.get('side', 1))  # 1 for BUY, -1 for SELL
    
    if not symbol:
        return jsonify({
            "status": "error",
            "message": "Symbol is required"
        }), 400
    
    # Place orders with both brokers
    response = place_order(username, symbol, price, side)
    
    # Check if at least one order was successful
    fyers_success = response.get("fyers", {}).get("s") == "ok"
    mstock_success = response.get("mstock", {}).get("status") == "success"
    
    if fyers_success or mstock_success:
        return jsonify({
            "status": "success",
            "message": "Orders placed successfully",
            "fyers": response.get("fyers"),
            "mstock": response.get("mstock")
        })
    else:
        return jsonify({
            "status": "error",
            "message": "Failed to place orders with both brokers",
            "fyers": response.get("fyers"),
            "mstock": response.get("mstock")
        }), 400

# ---- HTML Templates ----
# (Templates remain exactly the same, so I will collapse them for brevity, but they should be included in your actual file)
SIGNUP_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Sign Up</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: Arial, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
               display: flex; justify-content: center; align-items: center; min-height: 100vh; }
        .container { background: white; padding: 40px; border-radius: 10px; box-shadow: 0 10px 25px rgba(0,0,0,0.2); width: 400px; }
        h2 { color: #333; text-align: center; margin-bottom: 30px; }
        input { width: 100%; padding: 12px; margin: 10px 0; border: 1px solid #ddd; border-radius: 5px; }
        button { width: 100%; padding: 12px; background: #667eea; color: white; border: none; border-radius: 5px;
                 cursor: pointer; font-size: 16px; margin-top: 10px; }
        button:hover { background: #5568d3; }
        .error { color: red; text-align: center; margin-bottom: 10px; }
        .link { text-align: center; margin-top: 20px; }
        .link a { color: #667eea; text-decoration: none; }
    </style>
</head>
<body>
    <div class="container">
        <h2>📝 Sign Up</h2>
        {% if error %}<div class="error">{{ error }}</div>{% endif %}
        <form method="POST">
            <input type="text" name="username" placeholder="Username" required>
            <input type="email" name="email" placeholder="Email" required>
            <input type="password" name="password" placeholder="Password" minlength="6" required>
            <button type="submit">Create Account</button>
        </form>
        <div class="link">Already have an account? <a href="/login">Login</a></div>
    </div>
</body>
</html>
"""

LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: Arial, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
               display: flex; justify-content: center; align-items: center; min-height: 100vh; }
        .container { background: white; padding: 40px; border-radius: 10px; box-shadow: 0 10px 25px rgba(0,0,0,0.2); width: 400px; }
        h2 { color: #333; text-align: center; margin-bottom: 30px; }
        input { width: 100%; padding: 12px; margin: 10px 0; border: 1px solid #ddd; border-radius: 5px; }
        button { width: 100%; padding: 12px; background: #667eea; color: white; border: none; border-radius: 5px;
                 cursor: pointer; font-size: 16px; margin-top: 10px; }
        button:hover { background: #5568d3; }
        .error { color: red; text-align: center; margin-bottom: 10px; }
        .link { text-align: center; margin-top: 20px; }
        .link a { color: #667eea; text-decoration: none; }
    </style>
</head>
<body>
    <div class="container">
        <h2>🔐 Login</h2>
        {% if error %}<div class="error">{{ error }}</div>{% endif %}
        <form method="POST">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Login</button>
        </form>
        <div class="link">Don't have an account? contact Sajid Shaikh for Sign Up</div>
    </div>
</body>
</html>
"""

CREDENTIALS_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Setup Credentials</title>
    <style>
        body { font-family: Arial, sans-serif; background: #f4f4f9; padding: 20px; }
        .container { max-width: 600px; margin: 50px auto; background: white; padding: 40px;
                     border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h2 { color: #1a73e8; text-align: center; }
        input { width: 100%; padding: 12px; margin: 10px 0; border: 1px solid #ddd; border-radius: 5px; }
        button { width: 100%; padding: 12px; background: #1a73e8; color: white; border: none;
                 border-radius: 5px; cursor: pointer; font-size: 16px; margin-top: 10px; }
        .info { background: #e3f2fd; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .section { margin-bottom: 25px; }
        .section h3 { color: #333; margin-bottom: 10px; }
    </style>
</head>
<body>
    <div class="container">
        <h2>🔑 Setup API Credentials</h2>
        
        <div class="section">
            <h3>Fyers API Credentials</h3>
            <div class="info"><strong>Note:</strong> Enter your Fyers API credentials.</div>
            <form method="POST">
                <input type="text" name="client_id" placeholder="Fyers Client ID" value="{{ client_id }}" required>
                <input type="text" name="secret_key" placeholder="Fyers Secret Key" value="{{ secret_key }}" required>
        </div>
        
        <div class="section">
            <h3>mStock API Credentials</h3>
            <div class="info"><strong>Note:</strong> Enter your mStock API Key. The API secret is fixed.</div>
                <input type="text" name="mstock_api_key" placeholder="mStock API Key" value="{{ mstock_api_key }}" required>
                <button type="submit">Save & Continue to Login</button>
            </form>
        </div>
    </div>
</body>
</html>
"""

MSTOCK_AUTH_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>m.Stock OTP Authentication</title>
    <style>
        body { font-family: Arial; max-width: 800px; margin: 0 auto; padding: 20px; background-color: #f5f5f5; }
        .container { background-color: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h2, h3 { text-align: center; }
        .form-container { background-color: #f9f9f9; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        input[type="text"], input[type="submit"] { width: 100%; padding: 12px; border-radius: 4px; font-size: 16px; }
        input[type="submit"] { background-color: #4CAF50; color: white; border: none; cursor: pointer; }
        input[type="submit"]:hover { background-color: #45a049; }
        .success { color: green; background-color: #dff0d8; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .error { color: red; background-color: #f2dede; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .token-info { background-color: #e9f7ef; padding: 15px; border-radius: 5px; margin-bottom: 20px; word-break: break-all; }
        .logout-btn { background-color: #f44336; }
        .logout-btn:hover { background-color: #d32f2f; }
        .hidden { display: none; }
        .back-link { text-align: center; margin-top: 20px; }
        .back-link a { color: #667eea; text-decoration: none; }
        .api-key-info { background-color: #e3f2fd; padding: 10px; border-radius: 5px; margin-bottom: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <h2>m.Stock API Authentication</h2>
        
        {% if mstock_api_key %}
            <div class="api-key-info">
                <strong>Using API Key:</strong> {{ mstock_api_key }}
            </div>
        {% else %}
            <div class="error">
                <strong>Error:</strong> mStock API key not configured. Please <a href="/setup_credentials">setup your mStock credentials</a> first.
            </div>
        {% endif %}

        <div id="otp-section" class="form-container {% if access_token %}hidden{% endif %}">
            <h3>Enter OTP to Generate Session</h3>
            <form method="POST">
                <div class="form-group">
                    <label for="totp">OTP:</label>
                    <input type="text" id="totp" name="totp" required placeholder="Enter your OTP">
                </div>
                <input type="submit" value="Verify OTP">
            </form>
        </div>

        {% if access_token %}
            <div class="success">
                <h3>✅ Authentication Successful!</h3>
            </div>

            <div class="token-info">
                <p><strong>Access Token:</strong> {{ access_token }}</p>
            </div>

            <div class="form-container">
                <a href="/mstock_option_chain" style="text-decoration:none;">
                    <input type="button" value="View Option Chain" style="background:#007bff;color:white;cursor:pointer;">
                </a>
            </div>

            <div class="form-container">
                <form method="POST" action="/mstock/logout">
                    <input type="submit" value="Logout" class="logout-btn">
                </form>
            </div>
        {% elif error %}
            <div class="error">
                <strong>Error:</strong> {{ error }}
            </div>
        {% endif %}

        <div class="back-link">
            <a href="/">← Back to Main Dashboard</a>
        </div>
    </div>
</body>
</html>
"""

MSTOCK_OPTION_CHAIN_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
  <title>m.Stock Option Chain</title>
  <style>
    body { font-family: Arial, sans-serif; background: #f7f7f7; padding: 20px; }
    h2 { color: #007bff; text-align: center; }
    table { border-collapse: collapse; width: 95%; margin: 20px auto; font-size: 12px; }
    th, td { border: 1px solid #aaa; padding: 6px; text-align: center; }
    th { background-color: #007bff; color: white; }
    tr:nth-child(even) { background-color: #f2f2f2; }
    .back-link { text-align: center; margin-top: 20px; }
    .back-link a { color: #667eea; text-decoration: none; }
    .strike-column { font-weight: bold; min-width: 60px; }
    .ltp-column { min-width: 60px; }
    .change-column { min-width: 60px; font-weight: bold; }
    .oi-column { min-width: 70px; font-weight: bold; }
    .volume-column { min-width: 70px; }
    .negative { color: red; }
    .positive { color: green; }
    .section-header { background-color: #e9ecef; font-weight: bold; }
  </style>
  <script>
    function formatNumber(num) {
        if (num === null || num === undefined || num === '-') return '-';
        return parseInt(num).toLocaleString();
    }
    
    function formatChange(num) {
        if (num === null || num === undefined || num === '-') return '-';
        const value = parseFloat(num);
        const formatted = value > 0 ? `+${value.toFixed(2)}` : value.toFixed(2);
        const className = value < 0 ? 'negative' : 'positive';
        return `<span class="${className}">${formatted}</span>`;
    }

    async function fetchChain(){
        let res = await fetch("/fetch_mstock_option_chain");
        let data = await res.json();
        let tbl = document.getElementById("chain");
        tbl.innerHTML = "";

        if(data.error){
            tbl.innerHTML = `<tr><td colspan="9">${data.error}</td></tr>`;
            return;
        }

        data.forEach(row=>{
            tbl.innerHTML += `<tr>
                <td class="strike-column">${row.strike_price}</td>
                <td class="ltp-column">${row.CE_LTP || '-'}</td>
                <td class="change-column">${formatChange(row.CE_Chng)}</td>
                <td class="oi-column">${formatNumber(row.CE_OI)}</td>
                <td class="change-column">${formatChange(row.CE_OI_Chng)}</td>
                <td class="volume-column">${formatNumber(row.CE_VOLUME)}</td>
                <td class="volume-column">${formatNumber(row.PE_VOLUME)}</td>
                <td class="change-column">${formatChange(row.PE_OI_Chng)}</td>
                <td class="oi-column">${formatNumber(row.PE_OI)}</td>
                <td class="change-column">${formatChange(row.PE_Chng)}</td>
                <td class="ltp-column">${row.PE_LTP || '-'}</td>
            </tr>`;
        });
    }

    setInterval(fetchChain, 3000);
    window.onload = fetchChain;
  </script>
</head>
<body>
  <h2>Live NIFTY50 Option Chain (m.Stock)</h2>
  <table>
    <thead>
        <tr>
            <th rowspan="2">Strike</th>
            <th colspan="5" class="section-header">Call Option</th>
            <th colspan="5" class="section-header">Put Option</th>
        </tr>
        <tr>
            <th>LTP</th>
            <th>Change</th>
            <th>OI</th>
            <th>OI Chg</th>
            <th>Volume</th>
            <th>Volume</th>
            <th>OI Chg</th>
            <th>OI</th>
            <th>Change</th>
            <th>LTP</th>
        </tr>
    </thead>
    <tbody id="chain"></tbody>
  </table>
  <div class="back-link">
    <a href="/mstock_auth">← Back to mStock Authentication</a> | 
    <a href="/">← Main Dashboard</a>
  </div>
</body>
</html>
"""

FYERS_AUTH_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Fyers Authentication</title>
    <style>
        body { font-family: Arial; max-width: 800px; margin: 0 auto; padding: 20px; background-color: #f5f5f5; }
        .container { background-color: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h2, h3 { text-align: center; }
        .form-container { background-color: #f9f9f9; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        input[type="text"], input[type="submit"] { width: 100%; padding: 12px; border-radius: 4px; font-size: 16px; }
        input[type="submit"] { background-color: #007bff; color: white; border: none; cursor: pointer; }
        input[type="submit"]:hover { background-color: #0069d9; }
        .success { color: green; background-color: #dff0d8; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .error { color: red; background-color: #f2dede; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .logout-btn { background-color: #dc3545; }
        .logout-btn:hover { background-color: #c82333; }
        .hidden { display: none; }
        .back-link { text-align: center; margin-top: 20px; }
        .back-link a { color: #667eea; text-decoration: none; }
        .auth-status { text-align: center; margin: 20px 0; }
        .status-badge { padding: 5px 15px; border-radius: 20px; font-weight: bold; }
        .status-success { background-color: #d4edda; color: #155724; }
        .status-warning { background-color: #fff3cd; color: #856404; }
    </style>
</head>
<body>
    <div class="container">
        <h2>Fyers API Authentication</h2>
        
        {% if is_authenticated %}
            <div class="auth-status">
                <span class="status-badge status-success">✅ Fyers is Authenticated</span>
            </div>
        {% else %}
            <div class="auth-status">
                <span class="status-badge status-warning">⚠️ Fyers is Not Authenticated</span>
            </div>
        {% endif %}

        {% if show_login_button and not is_authenticated %}
            <div class="form-container">
                <h3>Login to Fyers</h3>
                <form method="POST">
                    <input type="submit" value="Login with Fyers">
                </form>
            </div>
        {% endif %}

        {% if error %}
            <div class="error">
                <strong>Error:</strong> {{ error }}
            </div>
        {% endif %}

        <div class="back-link">
            <a href="/">← Back to Main Dashboard</a>
        </div>
    </div>
</body>
</html>
"""

MAIN_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Algo Trading Bot - Sajid Shaikh</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; }
        .header { background: rgba(255,255,255,0.95); padding: 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header h1 { color: #333; text-align: center; }
        .nav { text-align: center; margin-top: 10px; }
        .nav a { margin: 0 15px; color: #667eea; text-decoration: none; font-weight: bold; }
        .nav a:hover { text-decoration: underline; }
        .container { max-width: 1600px; margin: 20px auto; padding: 0 20px; }
        .card { background: white; border-radius: 10px; padding: 25px; margin-bottom: 20px; box-shadow: 0 4px 15px rgba(0,0,0,0.1); }
        .card h2 { color: #333; margin-bottom: 20px; border-bottom: 2px solid #667eea; padding-bottom: 10px; }
        .form-group { margin-bottom: 15px; }
        .form-group label { display: block; margin-bottom: 5px; font-weight: bold; color: #555; }
        .form-group input { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 5px; font-size: 14px; }
        .form-row { display: flex; gap: 15px; }
        .form-row .form-group { flex: 1; }
        .btn { padding: 12px 24px; border: none; border-radius: 5px; cursor: pointer; font-size: 14px; font-weight: bold; margin-right: 10px; margin-bottom: 10px; }
        .btn-primary { background: #667eea; color: white; }
        .btn-success { background: #28a745; color: white; }
        .btn-danger { background: #dc3545; color: white; }
        .btn-warning { background: #ffc107; color: black; }
        .btn-info { background: #17a2b8; color: white; }
        .btn:hover { opacity: 0.9; }
        .status { padding: 10px; border-radius: 5px; margin: 10px 0; }
        .status-success { background: #d4edda; color: #155724; }
        .status-error { background: #f8d7da; color: #721c24; }
        .status-info { background: #d1ecf1; color: #0c5460; }
        .table { width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 12px; }
        .table th, .table td { padding: 8px; text-align: center; border-bottom: 1px solid #ddd; }
        .table th { background: #f8f9fa; font-weight: bold; }
        .table tr:hover { background: #f5f5f5; }
        .atm-strike { font-size: 18px; font-weight: bold; color: #667eea; text-align: center; margin: 15px 0; }
        .signals { max-height: 200px; overflow-y: auto; border: 1px solid #ddd; padding: 10px; border-radius: 5px; }
        .signal-item { padding: 5px; margin: 2px 0; background: #e9ecef; border-radius: 3px; }
        .user-info { text-align: right; color: #666; font-size: 14px; }
        .auth-status { text-align: center; margin: 20px 0; }
        .status-badge { padding: 5px 15px; border-radius: 20px; font-weight: bold; }
        .status-success { background-color: #d4edda; color: #155724; }
        .status-warning { background-color: #fff3cd; color: #856404; }
        
        /* Option chain styling */
        .strike-column { font-weight: bold; min-width: 60px; }
        .ltp-column { min-width: 60px; }
        .change-column { min-width: 60px; font-weight: bold; }
        .oi-column { min-width: 70px; font-weight: bold; }
        .volume-column { min-width: 70px; }
        .negative { color: red; }
        .positive { color: green; }
        .section-header { background-color: #e9ecef; font-weight: bold; }
        
        /* Highlighting styles for option chain */
        .atm-row { background-color: #e3f2fd !important; font-weight: bold; }
        .ce-offset-row { background-color: #e8f5e9 !important; font-weight: bold; }
        .pe-offset-row { background-color: #fff3e0 !important; font-weight: bold; }
        .row-label { display: inline-block; padding: 2px 6px; border-radius: 3px; font-size: 12px; margin-right: 5px; font-weight: bold; color: white; }
        .atm-row .row-label { background-color: #2196f3; }
        .ce-offset-row .row-label { background-color: #4caf50; }
        .pe-offset-row .row-label { background-color: #ff9800; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🚀 Algo Trading Bot - Sajid Shaikh (Dual Broker)</h1>
        <div class="user-info">Logged in as: {{ username }}</div>
        <div class="nav">
            <a href="/">Dashboard</a>
            <a href="/mstock_auth">mStock Auth</a>
            <a href="/fyers_auth">Fyers Auth</a>
            <a href="/setup_credentials">API Setup</a>
            <a href="/logout">Logout</a>
        </div>
    </div>

    <div class="container">
        <div class="card">
            <h2>⚙️ Bot Configuration</h2>
            <form method="POST">
                <div class="form-row">
                    <div class="form-group">
                        <label>CE Offset Points:</label>
                        <input type="number" name="ce_offset" value="{{ ce_offset }}" required>
                    </div>
                    <div class="form-group">
                        <label>PE Offset Points:</label>
                        <input type="number" name="pe_offset" value="{{ pe_offset }}" required>
                    </div>
                </div>
                <div class="form-row">
                    <div class="form-group">
                        <label>CE Trigger Points:</label>
                        <input type="number" name="atm_ce_plus20" value="{{ atm_ce_plus20 }}" step="0.05" required>
                    </div>
                    <div class="form-group">
                        <label>PE Trigger Points:</label>
                        <input type="number" name="atm_pe_plus20" value="{{ atm_pe_plus20 }}" step="0.05" required>
                    </div>
                </div>
                <div class="form-row">
                    <div class="form-group">
                        <label>Quantity:</label>
                        <input type="number" name="quantity" value="{{ quantity }}" required>
                    </div>
                    <div class="form-group">
                        <label>Symbol Prefix:</label>
                        <input type="text" name="symbol_prefix" value="{{ symbol_prefix }}" required>
                    </div>
                </div>
                <button type="submit" class="btn btn-primary">Save Configuration</button>
            </form>
        </div>

        <div class="card">
            <h2>📊 Market Data</h2>
            <div class="auth-status">
                {% if fyers_authenticated %}
                    <span class="status-badge status-success">✅ Fyers is Authenticated</span>
                {% else %}
                    <span class="status-badge status-warning">⚠️ Fyers is Not Authenticated</span>
                    <p>Please <a href="/fyers_auth">login with Fyers</a> to access market data</p>
                {% endif %}
            </div>
            {% if atm_strike %}
                <div class="atm-strike">ATM Strike: {{ atm_strike }}</div>
            {% endif %}
            <button onclick="fetchOptionChain()" class="btn btn-info">Fetch Option Chain</button>
            <button onclick="startBot()" class="btn btn-success">Start Bot</button>
            <button onclick="stopBot()" class="btn btn-danger">Stop Bot</button>
            <button onclick="resetBot()" class="btn btn-warning">Reset Bot</button>
            <div id="status"></div>
            <div id="option-chain"></div>
        </div>

        <div class="card">
            <h2>📈 Trading Signals</h2>
            <div id="signals" class="signals"></div>
        </div>
    </div>

    <script>
        let botInterval;

        function showStatus(message, type = 'info') {
            const statusDiv = document.getElementById('status');
            statusDiv.innerHTML = `<div class="status status-${type}">${message}</div>`;
            setTimeout(() => statusDiv.innerHTML = '', 5000);
        }

        function formatNumber(num) {
            if (num === null || num === undefined || num === '-') return '-';
            return parseInt(num).toLocaleString();
        }
        
        function formatChange(num) {
            if (num === null || num === undefined || num === '-') return '-';
            const value = parseFloat(num);
            const formatted = value > 0 ? `+${value.toFixed(2)}` : value.toFixed(2);
            const className = value < 0 ? 'negative' : 'positive';
            return `<span class="${className}">${formatted}</span>`;
        }

        async function fetchOptionChain() {
            try {
                const response = await fetch('/fetch');
                const data = await response.json();
                
                if (data.error) {
                    showStatus(data.error, 'error');
                    return;
                }

                const atmStrike = data.pop().atm_strike;
                // Get the offset values from the form inputs
                const ceOffset = parseInt(document.querySelector('input[name="ce_offset"]').value) || -300;
                const peOffset = parseInt(document.querySelector('input[name="pe_offset"]').value) || 300;
                
                // Calculate the offset strikes
                const ceOffsetStrike = atmStrike + ceOffset;
                const peOffsetStrike = atmStrike + peOffset;
                
                let html = `<div class="atm-strike">ATM Strike: ${atmStrike}</div>`;
                html += '<table class="table"><thead>';
                html += '<tr>';
                html += '<th rowspan="2">Strike</th>';
                html += '<th colspan="5" class="section-header">Call Option</th>';
                html += '<th colspan="5" class="section-header">Put Option</th>';
                html += '</tr>';
                html += '<tr>';
                html += '<th>LTP</th>';
                html += '<th>Change</th>';
                html += '<th>OI</th>';
                html += '<th>OI Chg</th>';
                html += '<th>Volume</th>';
                html += '<th>Volume</th>';
                html += '<th>OI Chg</th>';
                html += '<th>OI</th>';
                html += '<th>Change</th>';
                html += '<th>LTP</th>';
                html += '</tr>';
                html += '</thead><tbody>';
                
                data.forEach(row => {
                    // Determine if this row should be highlighted
                    let rowClass = '';
                    let rowLabel = '';
                    
                    if (row.strike_price === atmStrike) {
                        rowClass = 'atm-row';
                        rowLabel = '<span class="row-label">ATM</span>';
                    } else if (row.strike_price === ceOffsetStrike) {
                        rowClass = 'ce-offset-row';
                        rowLabel = '<span class="row-label">CE Offset</span>';
                    } else if (row.strike_price === peOffsetStrike) {
                        rowClass = 'pe-offset-row';
                        rowLabel = '<span class="row-label">PE Offset</span>';
                    }
                    
                    html += `<tr class="${rowClass}">
                        <td class="strike-column">${rowLabel} ${row.strike_price}</td>
                        <td class="ltp-column">${row.CE_LTP || '-'}</td>
                        <td class="change-column">${formatChange(row.CE_Chng)}</td>
                        <td class="oi-column">${formatNumber(row.CE_OI)}</td>
                        <td class="change-column">${formatChange(row.CE_OI_Chng)}</td>
                        <td class="volume-column">${formatNumber(row.CE_VOLUME)}</td>
                        <td class="volume-column">${formatNumber(row.PE_VOLUME)}</td>
                        <td class="change-column">${formatChange(row.PE_OI_Chng)}</td>
                        <td class="oi-column">${formatNumber(row.PE_OI)}</td>
                        <td class="change-column">${formatChange(row.PE_Chng)}</td>
                        <td class="ltp-column">${row.PE_LTP || '-'}</td>
                    </tr>`;
                });
                
                html += '</tbody></table>';
                document.getElementById('option-chain').innerHTML = html;
                showStatus('Option chain updated successfully', 'success');
            } catch (error) {
                showStatus('Error fetching option chain: ' + error.message, 'error');
            }
        }

        async function startBot() {
            try {
                const response = await fetch('/start_bot', { method: 'POST' });
                const data = await response.json();
                
                if (data.error) {
                    showStatus(data.error, 'error');
                } else {
                    showStatus(data.message, 'success');
                    startBotStatusCheck();
                }
            } catch (error) {
                showStatus('Error starting bot: ' + error.message, 'error');
            }
        }

        async function stopBot() {
            try {
                const response = await fetch('/stop_bot', { method: 'POST' });
                const data = await response.json();
                
                if (data.error) {
                    showStatus(data.error, 'error');
                } else {
                    showStatus(data.message, 'success');
                    clearInterval(botInterval);
                }
            } catch (error) {
                showStatus('Error stopping bot: ' + error.message, 'error');
            }
        }

        async function resetBot() {
            try {
                const response = await fetch('/reset', { method: 'POST' });
                const data = await response.json();
                
                if (data.error) {
                    showStatus(data.error, 'error');
                } else {
                    showStatus(data.message, 'success');
                    document.getElementById('signals').innerHTML = '';
                }
            } catch (error) {
                showStatus('Error resetting bot: ' + error.message, 'error');
            }
        }

        async function startBotStatusCheck() {
            botInterval = setInterval(async () => {
                try {
                    const response = await fetch('/bot_status');
                    const data = await response.json();
                    
                    let signalsHtml = '';
                    data.signals.forEach(signal => {
                        signalsHtml += `<div class="signal-item">${signal}</div>`;
                    });
                    document.getElementById('signals').innerHTML = signalsHtml;
                } catch (error) {
                    console.error('Error checking bot status:', error);
                }
            }, 2000);
        }

        // Auto-refresh option chain every 5 seconds
        setInterval(fetchOptionChain, 5000);
        
        // Initial load
        window.onload = function() {
            fetchOptionChain();
        };
    </script>
</body>
</html>
"""

if __name__ == "__main__":
    print("\n" + "="*60)
    print("🚀 Sajid Shaikh Algo Trading Bot - MongoDB Version")
    print("="*60)
    print(f"📍 Server running on port: {port}")
    print("="*60 + "\n")
    app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)
