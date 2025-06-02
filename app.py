#app.py

from flask import Flask, render_template, request, redirect, url_for, send_file, flash, session,jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import ForeignKey, case, or_, func
from sqlalchemy.dialects.postgresql import TIMESTAMP
from sqlalchemy import Column, Integer, Float, String, DateTime, ForeignKey, Text, Boolean
from sqlalchemy.orm import relationship, joinedload
from flask_caching import Cache
from flask_mail import Mail, Message
from flask_login import LoginManager,UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer as Serializer
import string
from scrapy.selector import Selector
from crawler import crawl, save_to_json
from bs4 import BeautifulSoup
from utils.link_analyzer import analyze_robots_txt
import csv
import json
import re
import requests
import logging
import os
import aiohttp
import asyncio
import traceback
import random

from concurrent.futures import ThreadPoolExecutor
import uuid
from markupsafe import Markup


from io import BytesIO, StringIO, StringIO as io
from PIL import Image
from collections import Counter
from datetime import datetime, timedelta, timezone, UTC, date
import time
from pytz import UTC
import pytz

import decimal 
from urllib.error import URLError
from urllib.parse import quote, urljoin, urlparse


from utils.link_analyzer import analyze_links
from utils.heading_extractor import extract_headings_in_order
from utils.text_extractor import extract_text, correct_text, process_keywords
from utils.image_extractor import extract_images
from utils.seo_analyzer import extract_seo_data

import razorpay


from decimal import Decimal, ROUND_HALF_UP
from dateutil.relativedelta import relativedelta
# Import CSRFProtect for CSRF protection
from flask_wtf.csrf import CSRFProtect


# Initialize app
app = Flask(__name__)
app.secret_key = "crawlersecretkey123"  # Needed for sessions
executor = ThreadPoolExecutor(max_workers=5)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # Ensure users are redirected to login page
login_manager.login_message = 'You need to log in to access this page.'
login_manager.login_message_category = 'info'

# Track crawling progress
crawl_status = {}

# For WSGI deployment, expose the Flask app as 'application'
application = app
#----------------------
# CSRF Protection
#----------------------
# Initialize CSRF protection
app.config['SECRET_KEY'] = os.urandom(24)  # Generate a random secret key
app.config['WTF_CSRF_ENABLED'] = True  # Enable CSRF protection
app.config['WTF_CSRF_SECRET_KEY'] = os.urandom(24)  # Generate a random CSRF secret key
# Initialize CSRF protection
from flask_wtf.csrf import CSRFProtect
from flask import request, flash, redirect, url_for
from flask_wtf.csrf import CSRFProtect
from flask import Flask, session
from flask import request, flash, redirect, url_for 
app.config['WTF_CSRF_ENABLED'] = False  # Disable global CSRF protection
csrf = CSRFProtect(app)
# Configure token expiration
app.config['WTF_CSRF_TIME_LIMIT'] = 3600  # Token valid for 1 hour

app.config['SESSION_COOKIE_SECURE'] = True  # HTTPS only
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Strict site origin control
#Selective Route Protection
@app.before_request
def csrf_protect():
    """
    Conditionally apply CSRF protection only to authentication routes
    
    Mental Model: 
    - Like a selective security checkpoint
    - Only validates tokens for specific, sensitive routes
    """
    if request.method == "POST":
        # List of routes that require CSRF protection
        protected_routes = [
            'login', 
            'signup', 
            'reset_token', 
            'reset_request', 
            'resend_verification'
        ]
        
        # Check if current route needs protection
        if request.endpoint in protected_routes:
            csrf.protect()

from flask_wtf.csrf import CSRFError

@app.context_processor
def utility_processor():
    def get_current_year():
        return datetime.now().year
    
    return dict(get_current_year=get_current_year)

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    """
    Provide clear, user-friendly error handling for CSRF token failures
    
    Key Principles:
    - Log the security event
    - Inform user without revealing sensitive details
    - Redirect to a safe page
    """
    # Log the security event for monitoring
    app.logger.warning(
        f"CSRF Token Validation Failed: "
        f"Route: {request.endpoint}, "
        f"Method: {request.method}"
    )
    
    # User-friendly error message
    flash(
        'Your form submission was invalid. Please try again. '
        'If the problem persists, clear your browser cookies and reload the page.', 
        'danger'
    )
    
    # Context-aware redirection
    if request.endpoint == 'login':
        return redirect(url_for('login'))
    elif request.endpoint == 'signup':
        return redirect(url_for('signup'))
    
    return redirect(url_for('index'))

import pytz

@app.template_filter('to_ist_time')
def to_ist_time(dt):
    """Convert UTC datetime to Indian Standard Time (IST)."""
    if dt is None:
        return "N/A"
    
    # If datetime has no timezone info, assume it's UTC
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    
    # Convert to IST (Asia/Calcutta)
    ist_timezone = pytz.timezone('Asia/Calcutta')
    ist_time = dt.astimezone(ist_timezone)
    
    # Format nicely for display
    return ist_time.strftime('%d %b %Y, %H:%M %p IST')
#----------------------

# Logging configuration
#----------------------
log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'flask_app.log')
logging.basicConfig(filename=log_path, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logging.info("Flask app started successfully")

# Ensure download directory exists
download_dir = "download_files"
os.makedirs(download_dir, exist_ok=True)


# Configure Flask-Caching (simple in-memory)
app.config['CACHE_TYPE'] = 'simple'
app.config['CACHE_DEFAULT_TIMEOUT'] = 300
cache = Cache(app)


# Add Razorpay configuration in your app config section
app.config['RAZORPAY_KEY_ID'] = 'rzp_test_omIBrvMFqrjDyN'
app.config['RAZORPAY_KEY_SECRET'] = 'XThGZMtibOTjFjG4wGsuXFD7'

# Initialize Razorpay client
razorpay_client = razorpay.Client(auth=(app.config['RAZORPAY_KEY_ID'], app.config['RAZORPAY_KEY_SECRET']))

# Flask-Mail configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'callincegoodsonmarialouis@gmail.com'
app.config['MAIL_PASSWORD'] = 'zfol bflm xqsf wtuq'

mail = Mail(app)


# Database configuration
DB_USERNAME = "postgres"
DB_PASSWORD = "nithya"  # URL-encode the password
DB_HOST = "localhost"
DB_PORT = "5432"
DB_NAME = "defaultdb"
DATABASE_URL = f"postgresql://{DB_USERNAME}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

# Flask app configuration
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize SQLAlchemy
db = SQLAlchemy(app)

# ----------------------
# Database Model
# ----------------------
# Update User model to include email verification fields
class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    company_email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    email_confirmed = db.Column(db.Boolean, default=False)
    email_confirm_token = db.Column(db.String(100), nullable=True)
    email_token_created_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.now(UTC))  

    def __init__(self, **kwargs):
        # Always normalize email to lowercase when creating a user
        if 'company_email' in kwargs:
            kwargs['company_email'] = kwargs['company_email'].lower().strip()
        super(User, self).__init__(**kwargs)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    # Token Generation
    def get_reset_token(self, expires_sec=1800):
        s = Serializer(app.secret_key)
        return s.dumps({'user_id': self.id})
    
    # Generate email confirmation token
    def get_email_confirm_token(self):
        s = Serializer(app.secret_key)
        token = s.dumps({'user_id': self.id})
        self.email_confirm_token = token
        self.email_token_created_at = datetime.now(UTC)
        return token

    # Verify email confirmation token
    @staticmethod
    def verify_email_token(token):
        s = Serializer(app.secret_key)
        try:
            user_id = s.loads(token, max_age=86400)['user_id']  # 24 hours expiry
        except:
            return None
        return User.query.get(user_id)

    # Token Verification
    @staticmethod
    def verify_reset_token(token):
        s = Serializer(app.secret_key)
        try:
            user_id = s.loads(token, max_age=1800)['user_id']
        except:
            return None
        return User.query.get(user_id)



# Enhanced Subscription Model

class Subscription(db.Model):
    __tablename__ = 'subscriptions'
    
    S_ID = db.Column(db.Integer, primary_key=True)
    plan = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)
    days = db.Column(db.Integer, nullable=False)
    usage_per_day = db.Column(db.Integer, nullable=False)
    tier = db.Column(db.Integer, nullable=False)  # Added tier for upgrade/downgrade logic
    features = db.Column(db.Text, nullable=True)  # JSON string of features
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    archived_at = db.Column(db.DateTime, nullable=True)
    # Relationship with SubscribedUser
    subscribed_users = relationship("SubscribedUser", back_populates="subscription", overlaps="subscribers")
    
    def __repr__(self):
        return f"<Subscription {self.plan}>"
        
    @property
    def daily_price(self):
        """Calculate price per day"""
        return self.price / self.days if self.days > 0 else 0


class SubscribedUser(db.Model):
    __tablename__ = 'subscribed_users'
    
    id = db.Column(db.Integer, primary_key=True)
    U_ID = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    S_ID = db.Column(db.Integer, db.ForeignKey('subscriptions.S_ID'), nullable=False)
    start_date = db.Column(db.DateTime, default=datetime.now(UTC))
    end_date = db.Column(db.DateTime, nullable=False)
    current_usage = db.Column(db.Integer, default=0)
    last_usage_reset = db.Column(db.DateTime, default=datetime.now(UTC))
    is_auto_renew = db.Column(db.Boolean, default=True)
    _is_active = db.Column('is_active', db.Boolean, default=True, nullable=False)

    # Relationships
    user = db.relationship('User', backref=db.backref('subscriptions', lazy=True))
    subscription = db.relationship('Subscription', backref=db.backref('subscribers', lazy=True))

    
    
    def remaining_value(self):
        now = datetime.now(UTC)
        
        # Ensure both start_date and end_date are timezone-aware
        start_date = self.start_date.replace(tzinfo=UTC) if self.start_date.tzinfo is None else self.start_date
        end_date = self.end_date.replace(tzinfo=UTC) if self.end_date.tzinfo is None else self.end_date
        
        if end_date <= now:
            return 0
        
        # Calculate total days in subscription period
        total_days = (end_date - start_date).total_seconds() / (24 * 3600)
        
        # Calculate remaining days
        remaining_days = (end_date - now).total_seconds() / (24 * 3600)
        
        # Calculate the daily rate and remaining value
        subscription = Subscription.query.get(self.S_ID)
        daily_rate = subscription.price / total_days if total_days > 0 else 0
        
        return daily_rate * remaining_days
    
    @property
    def daily_usage_percent(self):
        """
        Calculate the percentage of daily usage
        """
        if not hasattr(self.subscription, 'usage_per_day') or not self.subscription.usage_per_day:
            return 0
            
        return min(100, (self.current_usage / self.subscription.usage_per_day) * 100)
    
    @property
    def is_active(self):
        now = datetime.now(timezone.utc)
        end_date = self.end_date

        if end_date and end_date.tzinfo is None:
            end_date = end_date.replace(tzinfo=timezone.utc)

        return self._is_active and end_date > now
    @is_active.setter
    def is_active(self, value):
        """
        Setter for is_active that only updates the underlying _is_active column
        """
        self._is_active = value

    @property
    def days_remaining(self):
        """
        Calculate the number of days remaining in the subscription
        """
        now = datetime.now(UTC)
        
        # Ensure end_date is timezone-aware
        if self.end_date.tzinfo is None:
            # If end_date is naive, make it timezone-aware using UTC
            end_date = self.end_date.replace(tzinfo=UTC)
        else:
            end_date = self.end_date
        
        if end_date <= now:
            return 0
        
        # Use total_seconds() to handle timezone-aware dates
        remaining_seconds = (end_date - now).total_seconds()
        return max(0, int(remaining_seconds / (24 * 3600)))

class InvoiceAddress(db.Model):
    __tablename__ = 'invoice_addresses'
    
    id = db.Column(db.Integer, primary_key=True)
    payment_id = db.Column(db.Integer, db.ForeignKey('payments.iid'), nullable=False)  # Updated to 'payments.iid'
    
    # Billing Address Details
    company_name = db.Column(db.String(255), nullable=True)
    full_name = db.Column(db.String(255), nullable=False)
    street_address = db.Column(db.String(255), nullable=False)
    city = db.Column(db.String(100), nullable=False)
    state = db.Column(db.String(100), nullable=False)
    postal_code = db.Column(db.String(20), nullable=False)
    country = db.Column(db.String(100), default='India')
    
    # Additional Contact Information
    email = db.Column(db.String(255), nullable=True)
    phone_number = db.Column(db.String(20), nullable=True)
    
    # Tax Identification Numbers
    gst_number = db.Column(db.String(20), nullable=True)
    pan_number = db.Column(db.String(20), nullable=True)
    
    # Relationship
    payment = relationship("Payment", back_populates="invoice_address")

    
class Payment(db.Model):
    __tablename__ = 'payments'
    
    iid = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    subscription_id = db.Column(db.Integer, db.ForeignKey('subscriptions.S_ID', ondelete='SET NULL'), nullable=False)
    razorpay_order_id = db.Column(db.String(100), nullable=False)
    razorpay_payment_id = db.Column(db.String(100), nullable=True)
    
    # Invoice-specific Details
    invoice_number = db.Column(db.String(50), unique=True, nullable=False)
    invoice_date = db.Column(db.DateTime, default=datetime.now(UTC))
    
    # Extended Payment Information
    order_number = db.Column(db.String(50), nullable=True)
    customer_number = db.Column(db.String(50), nullable=True)
    purchase_order = db.Column(db.String(50), nullable=True)
    payment_terms = db.Column(db.String(100), default='Credit Card')
    
    # Base amount and tax calculations
    base_amount = db.Column(db.Float, nullable=False)
    gst_rate = db.Column(db.Float, default=0.18)  # Default 18% GST
    gst_amount = db.Column(db.Float, nullable=False)
    total_amount = db.Column(db.Float, nullable=False)
    
    # Additional tax-related information
    hsn_code = db.Column(db.String(20), nullable=True)
    cin_number = db.Column(db.String(50), nullable=True)
    
    currency = db.Column(db.String(10), default='INR')
    status = db.Column(db.String(20), default='created')
    created_at = db.Column(db.DateTime, default=datetime.now(UTC))
    payment_type = db.Column(db.String(20), default='new')
    previous_subscription_id = db.Column(db.Integer, db.ForeignKey('subscriptions.S_ID'), nullable=True)
    credit_applied = db.Column(db.Float, default=0.0)
    
    # Additional notes or special instructions
    notes = db.Column(db.Text, nullable=True)
    
    # Relationships
    user = relationship("User", backref="payments")
    subscription = relationship("Subscription", foreign_keys=[subscription_id], backref="payments")
    previous_subscription = relationship("Subscription", foreign_keys=[previous_subscription_id])
    invoice_address = relationship("InvoiceAddress", back_populates="payment", uselist=False)
    
    def __init__(self, *args, **kwargs):
        # Get the base_amount from kwargs with a default value of 0
        base_amount = kwargs.pop('base_amount', 0)
        gst_rate = kwargs.pop('gst_rate', 0.18)
        
        # Validate inputs more robustly
        try:
            base_amount = float(base_amount)
            if base_amount < 0:
                raise ValueError("Base amount must be a non-negative number")
        except (TypeError, ValueError):
            raise ValueError("Invalid base amount provided")
        
        super().__init__(*args, **kwargs)
        
        self.base_amount = base_amount
        self.gst_rate = gst_rate
        
        self._generate_invoice_details()
        self._calculate_total_amount()
    
    def _generate_invoice_details(self):
        """
        Generate unique invoice details with more robust generation
        """
        timestamp = datetime.now(UTC).strftime("%Y%m%d")
        unique_id = str(uuid.uuid4().hex)[:6].upper()
        self.invoice_number = f"INV-{timestamp}-{unique_id}"
        self.invoice_date = datetime.now(UTC)
    
    def _calculate_total_amount(self):
        """
        Enhanced total amount calculation with comprehensive error handling
        """
        try:
            base = Decimal(str(self.base_amount)).quantize(Decimal('0.01'))
            gst_rate = Decimal(str(self.gst_rate)).quantize(Decimal('0.01'))
            
            gst_amount = base * gst_rate
            gst_amount = gst_amount.quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
            
            total_amount = base + gst_amount
            total_amount = total_amount.quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
            
            self.gst_amount = float(gst_amount)
            self.total_amount = float(total_amount)
        except (TypeError, ValueError, decimal.InvalidOperation) as e:
            # Log the error and set default values
            print(f"Error in amount calculation: {e}")
            self.gst_amount = 0
            self.total_amount = self.base_amount
    
    def generate_invoice_pdf(self):
        """
        Placeholder method for generating invoice PDF
        Can be implemented with a library like ReportLab
        """
        # Future implementation for PDF generation
        pass
    
    def get_invoice_summary(self):
        """
        Return a comprehensive invoice summary
        
        :return: Dictionary with invoice details
        """
        return {
            'invoice_number': self.invoice_number,
            'invoice_date': self.invoice_date,
            'order_number': self.order_number,
            'customer_number': self.customer_number,
            'base_amount': self.base_amount,
            'gst_rate': self.gst_rate * 100,
            'gst_amount': self.gst_amount,
            'total_amount': self.total_amount,
            'currency': self.currency,
            'status': self.status
        }
    
    def __repr__(self):
        return f"<Payment {self.invoice_number} - {self.total_amount}>"

# Subscription History to track changes
class SubscriptionHistory(db.Model):
    __tablename__ = 'subscription_history'
    
    id = db.Column(db.Integer, primary_key=True)
    U_ID = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    S_ID = db.Column(db.Integer, db.ForeignKey('subscriptions.S_ID'), nullable=False)
    action = db.Column(db.String(20), nullable=False)  # new, upgrade, downgrade, cancel, expire
    previous_S_ID = db.Column(db.Integer, db.ForeignKey('subscriptions.S_ID'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.now(UTC))
    
    # Relationships
    user = relationship("User", backref="subscription_history")
    subscription = relationship("Subscription", foreign_keys=[S_ID])
    previous_subscription = relationship("Subscription", foreign_keys=[previous_S_ID])
    
    def __repr__(self):
        return f"<SubscriptionHistory {self.action} for {self.user.name}>"



# Update the SearchHistory model
class SearchHistory(db.Model):
    __tablename__ = 'search_history'  # Add this line to explicitly set table name
    id = db.Column(db.Integer, primary_key=True)
    u_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    user_name = db.Column(db.String(100), nullable=False)
    usage_tool = db.Column(db.String(100), nullable=False)
    search_history = db.Column(db.String(255), nullable=False)
    search_count = db.Column(db.Integer, default=1)
    # Store UTC time
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(UTC))
   
    # Relationship to User for easy access to user details
    user = db.relationship('User', backref='search_histories')
   
    # Property to get IST time
    @property
    def ist_time(self):
        # Add 5 hours and 30 minutes to UTC time to get IST
        if self.created_at:
            if self.created_at.tzinfo is None:  # If naive datetime
                return pytz.timezone('UTC').localize(self.created_at).astimezone(pytz.timezone('Asia/Kolkata'))
            return self.created_at.astimezone(pytz.timezone('Asia/Kolkata'))
        return None
    
    def __repr__(self):
        return f"<SearchHistory id={self.id}, u_id={self.u_id}, usage_tool='{self.usage_tool}', search_count={self.search_count}>"


def add_search_history(user_id, usage_tool, search_query):
    """Utility to record a search query for a given user/tool."""
    # Ensure user_id is valid
    if not user_id:
        return False
        
    try:
        # Fetch the user's name
        user = db.session.get(User, user_id)
        if not user:
            return False
            
        user_name = user.name
        
        # Check if the entry already exists - use a lock to prevent race conditions
        entry = SearchHistory.query.filter_by(
            u_id=user_id, 
            usage_tool=usage_tool, 
            search_history=search_query
        ).with_for_update().first()
        
        if entry:
            entry.search_count += 1
            # Update the timestamp to current time
            entry.created_at = datetime.now(UTC)
        else:
            # Use datetime.now(UTC) for current UTC time
            current_utc_time = datetime.now(UTC)
            
            entry = SearchHistory(
                u_id=user_id,
                user_name=user_name,
                usage_tool=usage_tool,
                search_history=search_query,
                search_count=1,
                created_at=current_utc_time
            )
            db.session.add(entry)
        
        # Explicitly commit the change
        db.session.commit()
        return True
    except Exception as e:
        # Log the error and rollback
        print(f"Error adding search history: {str(e)}")
        db.session.rollback()
        return False
# ----------------------
# Search history
# ----------------------

def add_search_history(user_id, usage_tool, search_query):
    """Utility to record a search query for a given user/tool."""
    # Fetch the user's name
    user = db.session.get(User, user_id)
    user_name = user.name if user else "Guest"  # Ensure user_name is available
    
    # Check if the entry already exists
    entry = SearchHistory.query.filter_by(u_id=user_id, usage_tool=usage_tool, search_history=search_query).first()
    
    if entry:
        entry.search_count += 1  # If the entry exists, increment the search count
    else:
        entry = SearchHistory(u_id=user_id, user_name=user_name, usage_tool=usage_tool, search_history=search_query, search_count=1)
        db.session.add(entry)
    
    db.session.commit()

#-----------------------
# Admin calss DB schema
#-----------------------
class UsageLog(db.Model):
    __tablename__ = 'usage_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    subscription_id = db.Column(db.Integer, db.ForeignKey('subscribed_users.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.now(UTC))
    operation_type = db.Column(db.String(100), nullable=False)  # e.g., 'url_analysis', 'keyword_search', etc.
    details = db.Column(db.Text, nullable=True)  # Additional details in JSON format
    
    # Relationships
    user = db.relationship('User', backref=db.backref('usage_logs', lazy=True))
    subscription = db.relationship('SubscribedUser', backref=db.backref('usage_logs', lazy=True))
    
    def __repr__(self):
        return f"<UsageLog id={self.id}, user_id={self.user_id}, operation={self.operation_type}>"
# ----------------------
# Define the Admin model
# Admin class DB schema
# ----------------------
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy import JSON

class Admin(db.Model):
    __tablename__ = 'admin'

    id = db.Column(db.Integer, primary_key=True)
    email_id = db.Column(db.String(120), nullable=False, unique=True)
    NAME = db.Column(db.String(50), nullable=False)
    role = db.Column(db.String(50), nullable=False)
    phone_number = db.Column(db.String(15), nullable=True)
    assigned_by = db.Column(db.String(50), nullable=False)
    permission = db.Column(db.ARRAY(db.String(50))) 
    password_hash = db.Column(db.String(256), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.now(UTC))
    updated_at = db.Column(db.DateTime, onupdate=datetime.now(UTC))
    is_active = db.Column(db.Boolean, default=True)

    def set_password(self, password):
        """Set the password hash."""
        if password and password.strip():
            try:
                self.password_hash = generate_password_hash(password)
                return True
            except Exception as e:
                app.logger.error(f"Password hashing error: {str(e)}")
                return False
        return False
    def check_password(self, password):
        """Check the password against the stored hash."""
        if not self.password_hash or not password:
            return False
        try:
            return check_password_hash(self.password_hash, password)
        except Exception as e:
            app.logger.error(f"Password check error: {str(e)}")
            return False
    def admin_permissions(self, required_permission):
        """
        Check if the admin has the specified permission based on their email and stored permissions
        """
        if request.method == 'POST':
            email_id = request.form.get('email_id')
            permissions = request.form.getlist('permissions[]')
            
            # Check if this instance's email matches the form email
            if self.email_id == email_id:
                return required_permission in permissions
            
        # For non-POST requests or if emails don't match, check stored permissions
        return required_permission in self.permission if self.permission else False

    @staticmethod
    def check_permission(email_id, required_permission):
        """Static method to check permissions by email"""
        admin = Admin.query.filter_by(email_id=email_id).first()
        if not admin:
            return False
            
        # For POST requests, check against form data
        if request.method == 'POST':
            form_email = request.form.get('email_id')
            if form_email == email_id:
                permissions = request.form.getlist('permissions[]')
                return required_permission in permissions
                
        # Otherwise check stored permissions
        return admin.admin_permissions(required_permission)

    def __repr__(self):
        return f"<Admin {self.NAME} - {self.role}>"

def create_super_admin():
    """
    Create a super admin user if it doesn't already exist
    """
    # Check if super admin already exists
    super_admin_email = "Nithyalakshmi22sk@gmail.com"  # Change this to your desired email
    existing_admin = Admin.query.filter_by(email_id=super_admin_email).first()
    
    if existing_admin:
        logging.info("Super admin already exists")
        return
    
    # Create super admin with all permissions
    super_admin = Admin(
        email_id=super_admin_email,
        NAME="Super Admin",
        role="Super Admin",
        phone_number="8122156835",  # Change this if needed
        assigned_by="System",
        permission=[
            "dashboard",
            "manage_roles", 
            "subscription_management", 
            "subscribed_users_view", 
            "user_management",
            "payments"
        ],  
        is_active=True,
        created_at=datetime.utcnow()
    )
    
    # Set a password - CHANGE THIS TO A STRONG PASSWORD!
    super_admin_password = "Nithya@22092001"  # CHANGE THIS!
    super_admin.set_password(super_admin_password)
    
    # Add and commit
    try:
        db.session.add(super_admin)
        db.session.commit()
        logging.info(f"Super admin created successfully: {super_admin_email}")
        print(f"Super admin created successfully: {super_admin_email}")
        print(f"Password: {super_admin_password}")
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error creating super admin: {str(e)}")
        print(f"Error creating super admin: {str(e)}")        


# ----------------------
#custom email validation
# ----------------------

# Function to send email verification
def send_verification_email(user):
    token = user.get_email_confirm_token()
    msg = Message('Email Verification',
                  sender=app.config['MAIL_USERNAME'],
                  recipients=[user.company_email])
    msg.body = f'''To verify your email address, please click the following link:

{url_for('verify_email', token=token, _external=True)}

This link will expire in 24 hours.

If you did not create an account, please ignore this email.

Thanks,
Your Team
'''
    mail.send(msg)

def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('Password Reset Request',
                  sender=app.config['MAIL_USERNAME'],
                  recipients=[user.company_email])
    msg.body = f'''To reset your password, click the following link:

{url_for('reset_token', token=token, _external=True)}

If you did not request this, please ignore this email.

Thanks,
Your Team
'''
    mail.send(msg)

#----------------------
# Custom Filter Registration
# ----------------------
def highlight_keywords(text, keywords_colors):
    """
    Wrap each occurrence of each keyword (case-insensitive) in the text with a <span> tag
    that styles it with the specified color and bold font.
    The matched text preserves its original case.
    """
    highlighted = text
    for keyword, color in keywords_colors.items():
        pattern = re.compile(re.escape(keyword), re.IGNORECASE)
        highlighted = pattern.sub(
            lambda m: f'<span style="color: {color}; font-weight: bold;">{m.group(0)}</span>',
            highlighted
        )
    return Markup(highlighted)

app.jinja_env.filters['highlight_keywords'] = highlight_keywords

def load_results():
    # Retrieve the crawl job ID from the session
    job_id = session.get('job_id')
    if not job_id:
        flash("No crawl job found. Please start a new crawl and upload the files again.")
        return {"status_codes": {}, "home_links": {}, "other_links": {}}
    
    # Build the JSON file path using the job ID
    crawled_data = f"crawled_data/crawl_{job_id}.json"
    if os.path.exists(crawled_data):
        with open(crawled_data, "r", encoding="utf-8") as file:
            return json.load(file)
    
    flash("Crawl results file not found or expired. Please start a new crawl and upload the files again.")
    return {"status_codes": {}, "home_links": {}, "other_links": {}}


# Helper function to run async code in a thread
def run_async_in_thread(coro):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()

# ----------------------
# Login Required Decorator
# ----------------------
from functools import wraps

def login_required(f):
    @wraps(f)  # Preserve function metadata
    def wrap(*args, **kwargs):
        if 'user_id' not in session:
            flash("You need to log in first.", "warning")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrap



# ----------------------
# Admin required decorator
#-----------------------
def admin_required(f):
    """
    Decorator to check if user is logged in as admin.
    If not, redirects to admin login page.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if admin is logged in
        if 'admin_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function
# ----------------------
# admin panel routes
# ----------------------
@app.route('/admin')
@admin_required
def admin_dashboard():
    now = datetime.now(UTC)

    
    # Create a custom RecentPayment class to match template expectations and add safety
    class RecentPayment:
        def __init__(self, user, subscription, payment):
            self.user = user
            self.subscription = subscription
            self.payment = payment
        
        def format_amount(self):
            # Safety method to handle potential undefined values
            try:
                return "{:,.2f}".format(self.payment.total_amount if hasattr(self.payment, 'total_amount') else self.payment.amount)
            except (AttributeError, TypeError):
                return "0.00"
    
    # Get statistics with more detailed information
    total_users = User.query.count()
    active_users = User.query.filter_by(email_confirmed=True).count()
    unconfirmed_users = total_users - active_users
    
    # Calculate active and expired subscriptions with timezone-aware comparison
    active_subscriptions = SubscribedUser.query.filter(SubscribedUser.end_date > now).count()
    expired_subscriptions = SubscribedUser.query.filter(SubscribedUser.end_date <= now).count()
    
    # Calculate subscription revenue metrics with enhanced payment details and proper timezone handling
    thirty_days_ago = now - timedelta(days=30)
    
    total_revenue = db.session.query(func.sum(Payment.total_amount)).filter(Payment.status == 'completed').scalar() or 0
    monthly_revenue = db.session.query(func.sum(Payment.total_amount)).filter(
        Payment.status == 'completed',
        Payment.created_at >= thirty_days_ago
    ).scalar() or 0
    
    # Get recent payments with enhanced details including invoice information
    recent_payments_query = (
        db.session.query(
            Payment,
            User,
            Subscription,
            InvoiceAddress
        )
        .join(User, Payment.user_id == User.id)
        .join(Subscription, Payment.subscription_id == Subscription.S_ID)
        .outerjoin(InvoiceAddress, Payment.iid == InvoiceAddress.payment_id)
        .order_by(Payment.created_at.desc())
        .limit(10)
        .all()
    )
    
    # Prepare payment summaries with additional details
    recent_payments = []
    for payment, user, subscription, invoice_address in recent_payments_query:
        recent_payments.append(
            RecentPayment(
                user=user,
                subscription=subscription,
                payment=payment
            )
        )
    
    # Get most popular subscription plans
    popular_plans = (
        db.session.query(
            Subscription.plan,
            func.count(SubscribedUser.id).label('subscribers')
        )
        .join(SubscribedUser, Subscription.S_ID == SubscribedUser.S_ID)
        .group_by(Subscription.plan)
        .order_by(func.count(SubscribedUser.id).desc())
        .limit(3)
        .all()
    )
    
    # Get users about to expire soon (in next 7 days) with timezone-aware comparison
    seven_days_from_now = now + timedelta(days=7)
    expiring_soon = (
        db.session.query(
            User,
            Subscription,
            SubscribedUser
        )
        .join(SubscribedUser, User.id == SubscribedUser.U_ID)
        .join(Subscription, SubscribedUser.S_ID == Subscription.S_ID)
        .filter(
            SubscribedUser.end_date > now,
            SubscribedUser.end_date <= seven_days_from_now
        )
        .all()
    )
    # Ensure all end_date values are timezone-aware
    for i, (user, subscription, subscribed_user) in enumerate(expiring_soon):
        if subscribed_user.end_date.tzinfo is None:
            subscribed_user.end_date = subscribed_user.end_date.replace(tzinfo=UTC)

    # Add subscription history analytics with proper timezone handling
    subscription_actions = (
        db.session.query(
            SubscriptionHistory.action,
            func.count(SubscriptionHistory.id).label('count')
        )
        .filter(SubscriptionHistory.created_at >= thirty_days_ago)
        .group_by(SubscriptionHistory.action)
        .all()
    )
    
    # Add auto-renewal statistics with timezone-aware comparison
    auto_renewal_count = SubscribedUser.query.filter(
        SubscribedUser.is_auto_renew == True,
        SubscribedUser.end_date > now
    ).count()
    
    non_renewal_count = SubscribedUser.query.filter(
        SubscribedUser.is_auto_renew == False,
        SubscribedUser.end_date > now
    ).count()
    
    # Calculate payment type distribution with more details
    payment_types = (
        db.session.query(
            Payment.payment_type,
            Payment.currency,
            func.count(Payment.iid).label('count'),
            func.sum(Payment.total_amount).label('total_revenue')
        )
        .filter(Payment.status == 'completed')
        .group_by(Payment.payment_type, Payment.currency)
        .all()
    )
    
    # Tax revenue breakdown
    tax_breakdown = (
        db.session.query(
            Payment.gst_rate,
            func.sum(Payment.gst_amount).label('total_tax'),
            func.count(Payment.iid).label('payment_count')
        )
        .filter(Payment.status == 'completed')
        .group_by(Payment.gst_rate)
        .all()
    )
    
    return render_template('admin/dashboard.html', 
                          now=now, 
                          total_users=total_users,
                          active_users=active_users,
                          unconfirmed_users=unconfirmed_users,
                          active_subscriptions=active_subscriptions,
                          expired_subscriptions=expired_subscriptions,
                          recent_payments=recent_payments,
                          total_revenue=total_revenue,
                          monthly_revenue=monthly_revenue,
                          popular_plans=popular_plans,
                          expiring_soon=expiring_soon,
                          subscription_actions=subscription_actions,
                          auto_renewal_count=auto_renewal_count,
                          non_renewal_count=non_renewal_count,
                          payment_types=payment_types,
                          tax_breakdown=tax_breakdown)


#-------------------------
# Admin login and logout
#-------------------------

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        # Input validation
        if not email or not password:
            flash('Email and password are required.', 'danger')
            return render_template('admin/login.html')

        # Get admin user
        admin = Admin.query.filter_by(email_id=email).first()
        
        # Check if admin exists and has password set
        if not admin:
            flash('Invalid email or password.', 'danger')
            return render_template('admin/login.html')

        # Check if password hash exists
        if not admin.password_hash:
            flash('Password not set for this admin account.', 'danger')
            return render_template('admin/login.html')
            
        # Verify password
        try:
            if admin.check_password(password):
                session['admin_id'] = admin.id
                session['admin_name'] = admin.NAME
                session['email_id'] = admin.email_id
                # Store permissions as list
                session['admin_permissions'] = admin.permission if isinstance(admin.permission, list) else []
                
                flash('Login successful!', 'success')
                return redirect(url_for('admin_dashboard'))
            else:
                flash('Invalid email or password.', 'danger')
        except Exception as e:
            app.logger.error(f"Password verification error: {str(e)}")
            flash('Error verifying password. Please contact administrator.', 'danger')

    return render_template('admin/login.html')
@app.route('/admin/logout')
@admin_required
def admin_logout():
    session.pop('admin_id', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('admin_login'))


# Route to add and display roles
@app.route('/admin/roles', methods=['GET', 'POST'])
@admin_required
def manage_roles():
    # Check if the user has permission to manage roles
    email_id = session.get('email_id')
    if not Admin.check_permission(email_id, 'manage_roles'):
        flash("You don't have permission to manage roles.", "danger")
        return redirect(url_for('admin_dashboard'))

        
    if request.method == 'POST':
        try:
            # Get form data
            name = request.form.get('NAME')
            email_id = request.form.get('email_id')
            role = request.form.get('role')
            phone_number = request.form.get('phone_number')
            password = request.form.get('password')
            permissions = request.form.getlist('permissions[]')
            # Validate required fields
            if not all([name, email_id, role]):
                flash('Name, email and role are required fields.', 'danger')
                return redirect(url_for('manage_roles'))

            admin_role = Admin.query.filter_by(email_id=email_id).first()

            if admin_role:
                # Update existing admin
                admin_role.NAME = name
                admin_role.role = role
                admin_role.phone_number = phone_number
                admin_role.permission = permissions
                admin_role.updated_at = datetime.now(UTC)
                
                 # Only update password if provided
                if password and password.strip():
                    if not admin_role.set_password(password):
                        flash('Error setting password.', 'danger')
                        return redirect(url_for('manage_roles'))
                
                flash(f'Role updated successfully for {name}!', 'success')
            else:
                # Create new admin
                if not password:
                    flash('Password is required for new admin roles.', 'danger')
                    return redirect(url_for('manage_roles'))

                new_role = Admin(
                    NAME=name,
                    email_id=email_id,
                    role=role,
                    phone_number=phone_number,
                    permission=permissions,
                    assigned_by=session.get('admin_name', 'System'),
                    is_active=True,
                    created_at=datetime.now(UTC)
                )

                # Set password for new admin
                if not new_role.set_password(password):
                    flash('Error setting password.', 'danger')
                    return redirect(url_for('manage_roles'))

                db.session.add(new_role)
                flash(f'New role created successfully for {name}!', 'success')

            db.session.commit()
            return redirect(url_for('manage_roles'))

        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Role management error: {str(e)}")
            flash(f'Error: {str(e)}', 'danger')
            return redirect(url_for('manage_roles'))

    roles = Admin.query.all()
    return render_template('admin/roles.html', roles=roles)

@app.route('/admin/roles/edit/<int:role_id>', methods=['GET', 'POST'])
@admin_required
def edit_role(role_id):
    role = Admin.query.get_or_404(role_id)

    if request.method == 'POST':
        try:
            # Get form data
            role.NAME = request.form.get('NAME')
            role.email_id = request.form.get('email_id')
            role.role = request.form.get('role')
            role.phone_number = request.form.get('phone_number')
            permissions = request.form.getlist('permissions[]')
            password = request.form.get('password')

            # Validate required fields
            if not all([role.NAME, role.email_id, role.role]):
                flash('Name, email and role are required fields.', 'danger')
                return redirect(url_for('edit_role', role_id=role_id))

            # Update password if provided
            if password and password.strip():
                if not role.set_password(password):
                    flash('Error updating password.', 'danger')
                    return redirect(url_for('edit_role', role_id=role_id))

            # Update other fields
            role.permission = permissions
            role.updated_at = datetime.now(UTC)

            db.session.commit()
            flash(f'Role updated successfully for {role.NAME}!', 'success')
            return redirect(url_for('manage_roles'))

        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Role update error: {str(e)}")
            flash(f'Error updating role: {str(e)}', 'danger')
            return redirect(url_for('edit_role', role_id=role_id))

    return render_template('admin/edit_role.html', 
                         role=role, 
                         role_permissions=role.permission if role.permission else [])
#-----------------------
# Search History
#-----------------------
@app.route('/admin/search_history', methods=['GET'])
@admin_required
def admin_search_history():
    email_id = session.get('email_id')
    
    if not Admin.check_permission(email_id, 'search_history'):
        flash("You don't have permission to access this page.", "danger")
        return redirect(url_for('admin_dashboard'))
    
    # Get all filter parameters
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    tool_filter = request.args.get('tool_filter', 'all')
    user_filter = request.args.get('user_filter', 'all')
    query_filter = request.args.get('query_filter')
    sort_by = request.args.get('sort_by', 'date_desc')
    page = request.args.get('page', 1, type=int)
    per_page = 20  # Number of items per page
    
    # Base query to fetch all search histories
    query = SearchHistory.query
    
    # Apply date filters if provided
    if start_date:
        try:
            start_date_obj = datetime.strptime(start_date, '%Y-%m-%d')
            query = query.filter(SearchHistory.created_at >= start_date_obj)
        except ValueError:
            flash("Invalid start date format. Please use YYYY-MM-DD.", "danger")
    
    if end_date:
        try:
            end_date_obj = datetime.strptime(end_date, '%Y-%m-%d')
            # Add one day to include the entire end date
            end_date_obj += timedelta(days=1)
            query = query.filter(SearchHistory.created_at < end_date_obj)
        except ValueError:
            flash("Invalid end date format. Please use YYYY-MM-DD.", "danger")
    
    # Apply tool filter if provided
    if tool_filter != 'all':
        query = query.filter(SearchHistory.usage_tool == tool_filter)
    
    # Apply user filter if provided
    if user_filter != 'all':
        query = query.filter(SearchHistory.u_id == user_filter)
    
    # Apply query filter if provided
    if query_filter:
        search_term = f"%{query_filter}%"
        query = query.filter(SearchHistory.search_history.like(search_term))
    
    # Apply sorting
    if sort_by == 'date_desc':
        query = query.order_by(SearchHistory.created_at.desc())
    elif sort_by == 'date_asc':
        query = query.order_by(SearchHistory.created_at.asc())
    elif sort_by == 'count_desc':
        query = query.order_by(SearchHistory.search_count.desc())
    elif sort_by == 'count_asc':
        query = query.order_by(SearchHistory.search_count.asc())
    
    # Calculate metrics for summary cards
    total_searches = db.session.query(db.func.sum(SearchHistory.search_count)).scalar() or 0
    active_users = db.session.query(db.func.count(db.distinct(SearchHistory.u_id))).scalar() or 0
    
    # Most popular tool
    popular_tool_query = db.session.query(
        SearchHistory.usage_tool, 
        db.func.sum(SearchHistory.search_count).label('total')
    ).group_by(SearchHistory.usage_tool).order_by(db.desc('total')).first()
    
    most_popular_tool = popular_tool_query[0] if popular_tool_query else "N/A"
    
    # Today's searches
    today = datetime.today().date()
    today_start = datetime.combine(today, datetime.min.time())
    today_end = datetime.combine(today, datetime.max.time())
    
    searches_today = db.session.query(
        db.func.sum(SearchHistory.search_count)
    ).filter(
        SearchHistory.created_at.between(today_start, today_end)
    ).scalar() or 0
    
    # Get available tools for dropdown
    available_tools = db.session.query(db.distinct(SearchHistory.usage_tool)).all()
    available_tools = [tool[0] for tool in available_tools]
    
    # Get available users for dropdown
    available_users = User.query.join(SearchHistory).distinct().all()
    
    # Paginate results
    paginated_history = query.paginate(page=page, per_page=per_page, error_out=False)
    
    # Fetch the most-used tool for each user
    user_most_used_tools = {}
    for entry in paginated_history.items:
        user_id = entry.u_id
        if user_id not in user_most_used_tools:
            # Fetch the most-used tool for the user
            tool_usage = db.session.query(SearchHistory.usage_tool, db.func.sum(SearchHistory.search_count))\
                .filter(SearchHistory.u_id == user_id)\
                .group_by(SearchHistory.usage_tool).all()
            if tool_usage:
                most_used_tool = max(tool_usage, key=lambda x: x[1])[0]  # Get the tool with the highest count
                user_most_used_tools[user_id] = most_used_tool
            else:
                user_most_used_tools[user_id] = "No tools used yet"
    
    # Pass the data to the template for rendering
    return render_template(
        'admin/search_history.html',
        history=paginated_history.items,
        pagination=paginated_history,
        user_most_used_tools=user_most_used_tools,
        start_date=start_date,
        end_date=end_date,
        tool_filter=tool_filter,
        user_filter=user_filter,
        query_filter=query_filter,
        sort_by=sort_by,
        available_tools=available_tools,
        available_users=available_users,
        total_searches=total_searches,
        active_users=active_users,
        most_popular_tool=most_popular_tool,
        searches_today=searches_today
    )


@app.route('/admin/search_history/export', methods=['GET'])
@admin_required
def admin_export_search_history():
    email_id = session.get('email_id')
    
    if not Admin.check_permission(email_id, 'search_history'):
        flash("You don't have permission to access this feature.", "danger")
        return redirect(url_for('admin_dashboard'))
    
    # Get the same filter parameters as the main view
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    tool_filter = request.args.get('tool_filter', 'all')
    user_filter = request.args.get('user_filter', 'all')
    query_filter = request.args.get('query_filter')
    
    # Base query to fetch all search histories
    query = SearchHistory.query
    
    # Apply the same filters as the main view
    # ... (copy the filter code from admin_search_history)
    
    # Fetch all matching records
    all_history = query.all()
    
    # Create a CSV in memory
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow(['User ID', 'User Name', 'Tool', 'Search Query/URL', 'Count', 'Date & Time'])
    
    # Write data rows
    for entry in all_history:
        writer.writerow([
            entry.u_id,
            entry.user.name,
            entry.usage_tool,
            entry.search_history,
            entry.search_count,
            entry.created_at.strftime('%Y-%m-%d %H:%M:%S')
        ])
    
    # Prepare the response
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode('utf-8')),
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'search_history_{datetime.now(UTC).strftime("%Y%m%d_%H%M%S")}.csv'
    )
#------------------------------
# admin Subscription Management
#------------------------------
@app.route('/admin/subscriptions')
def admin_subscriptions():
    email_id = session.get('email_id')
    
    if not Admin.check_permission(email_id, 'subscription_management'):
        flash("You don't have permission to access this page.", "danger")
        return redirect(url_for('admin_dashboard'))
    # Get all subscription plans with subscriber counts
    subscriptions = (
        db.session.query(
            Subscription,
            func.count(SubscribedUser.id).label('active_subscribers'),
            func.sum(case(
                (SubscribedUser.end_date > datetime.now(UTC), 1),
                else_=0
            )).label('active_count')
        )
        .outerjoin(SubscribedUser, Subscription.S_ID == SubscribedUser.S_ID)
        .group_by(Subscription.S_ID)
        .all()
    )
    
    # Extract the Subscription object and other data into a list of dictionaries
    subscription_data = [
        {
            "subscription": row[0],  # Subscription object
            "active_subscribers": row[1],
            "active_count": row[2]
        }
        for row in subscriptions
    ]
    
    return render_template('admin/subscriptions.html', subscriptions=subscription_data)

@app.route('/admin/subscriptions/new', methods=['GET', 'POST'])
def admin_new_subscription():
    if request.method == 'POST':
        plan = request.form.get('plan')
        price = float(request.form.get('price'))
        days = int(request.form.get('days'))
        usage_per_day = int(request.form.get('usage_per_day'))
        tier = int(request.form.get('tier', 1))  # Added tier field
        features = request.form.get('features', '')  # Added features field
        
        # Validate inputs
        if not plan or price <= 0 or days <= 0 or usage_per_day <= 0 or tier <= 0:
            flash('Invalid subscription details. Please check your input.', 'danger')
            return redirect(url_for('admin_new_subscription'))
        
        # Check if plan name already exists
        existing_plan = Subscription.query.filter_by(plan=plan).first()
        if existing_plan:
            flash('A subscription plan with this name already exists.', 'danger')
            return redirect(url_for('admin_new_subscription'))
        
        new_subscription = Subscription(
            plan=plan,
            price=price,
            days=days,
            usage_per_day=usage_per_day,
            tier=tier,  # Added tier
            features=features  # Added features
        )
        
        db.session.add(new_subscription)
        db.session.commit()
        
        flash('Subscription plan created successfully!', 'success')
        return redirect(url_for('admin_subscriptions'))
    
    return render_template('admin/new_subscription.html')

@app.route('/admin/subscriptions/edit/<int:id>', methods=['GET', 'POST'])
def admin_edit_subscription(id):
    subscription = Subscription.query.get_or_404(id)
    
    # Get active subscribers count
    active_subscribers = SubscribedUser.query.filter(
        SubscribedUser.S_ID == id,
        SubscribedUser.end_date > datetime.now(UTC)
    ).count()
    
    if request.method == 'POST':
        plan = request.form.get('plan')
        price = float(request.form.get('price'))
        days = int(request.form.get('days'))
        usage_per_day = int(request.form.get('usage_per_day'))
        tier = int(request.form.get('tier', subscription.tier))  # Added tier field
        features = request.form.get('features', subscription.features)  # Added features field
        
        # Validate inputs
        if not plan or price <= 0 or days <= 0 or usage_per_day <= 0 or tier <= 0:
            flash('Invalid subscription details. Please check your input.', 'danger')
            return redirect(url_for('admin_edit_subscription', id=id))
        
        # Check if plan name already exists with a different ID
        existing_plan = Subscription.query.filter(
            Subscription.plan == plan,
            Subscription.S_ID != id
        ).first()
        
        if existing_plan:
            flash('A subscription plan with this name already exists.', 'danger')
            return redirect(url_for('admin_edit_subscription', id=id))
        
        subscription.plan = plan
        subscription.price = price
        subscription.days = days
        subscription.usage_per_day = usage_per_day
        subscription.tier = tier  # Added tier
        subscription.features = features  # Added features
        
        db.session.commit()
        
        flash('Subscription plan updated successfully!', 'success')
        return redirect(url_for('admin_subscriptions'))
    
    return render_template('admin/edit_subscription.html', 
                          subscription=subscription,
                          active_subscribers=active_subscribers)

# Add these routes to your Flask application

@app.route('/admin/subscriptions/archive/<int:id>', methods=['POST'])
def admin_archive_subscription(id):
    subscription = Subscription.query.get_or_404(id)
    
    # Check if already archived
    if subscription.archived_at:
        flash('This subscription plan is already archived.', 'warning')
        return redirect(url_for('admin_subscriptions'))
    
    # Archive the subscription plan
    subscription.is_active = False
    subscription.archived_at = datetime.now(UTC)
    db.session.commit()
    
    flash('Subscription plan has been archived successfully.', 'success')
    return redirect(url_for('admin_subscriptions'))


@app.route('/admin/subscriptions/restore/<int:id>', methods=['POST'])
def admin_restore_subscription(id):
    subscription = Subscription.query.get_or_404(id)
    
    # Check if not archived
    if not subscription.archived_at:
        flash('This subscription plan is not archived.', 'warning')
        return redirect(url_for('admin_subscriptions'))
    
    # Restore the subscription plan
    subscription.is_active = True
    subscription.archived_at = None
    db.session.commit()
    
    flash('Subscription plan has been restored successfully.', 'success')
    return redirect(url_for('admin_subscriptions'))

@app.route('/admin/subscriptions/delete/<int:id>', methods=['POST'])
def admin_delete_subscription(id):
    subscription = Subscription.query.get_or_404(id)
    
    # Check if there are any users subscribed to this plan (active or inactive)
    if subscription.subscribed_users:
        flash('Cannot delete subscription plan as it has users associated with it. Please remove the user subscriptions first.', 'danger')
        return redirect(url_for('admin_subscriptions'))
    
    # Check if there are any payments or history records associated with this plan
    payment_count = Payment.query.filter_by(subscription_id=id).count()
    history_count = SubscriptionHistory.query.filter(
        (SubscriptionHistory.S_ID == id) | 
        (SubscriptionHistory.previous_S_ID == id)
    ).count()
    
    if payment_count > 0 or history_count > 0:
        # Instead of blocking, mark as archived
        subscription.is_active = False
        subscription.archived_at = datetime.now(UTC)
        db.session.commit()
        
        flash('Subscription plan has been archived as it has payment or history records associated with it.', 'warning')
        return redirect(url_for('admin_subscriptions'))
    
    # If no constraints, perform actual deletion
    db.session.delete(subscription)
    db.session.commit()
    
    flash('Subscription plan deleted successfully!', 'success')
    return redirect(url_for('admin_subscriptions'))
    
@app.route('/admin/subscribed-users')
def admin_subscribed_users():

    email_id = session.get('email_id')
    
    if not Admin.check_permission(email_id, 'subscribed_users_view'):
        flash("You don't have permission to access this page.", "danger")
        return redirect(url_for('admin_dashboard'))
    # Get filter parameters
    status_filter = request.args.get('status', 'all')
    plan_filter = request.args.get('plan', 'all')
    
    # Get current time - use naive datetime to match database storage
    now = datetime.now(UTC)
    
    # Base query with joins
    query = (
        db.session.query(
            SubscribedUser, 
            User, 
            Subscription
        )
        .join(User, SubscribedUser.U_ID == User.id)
        .join(Subscription, SubscribedUser.S_ID == Subscription.S_ID)
    )
    
    # Apply filters
    if status_filter == 'active':
        query = query.filter(SubscribedUser.end_date > now)
    elif status_filter == 'expired':
        query = query.filter(SubscribedUser.end_date <= now)
    
    if plan_filter != 'all':
        query = query.filter(Subscription.S_ID == plan_filter)
    
    # Get all subscription plans for the filter dropdown
    all_plans = Subscription.query.all()
    
    # Execute the query
    subscribed_users = query.order_by(SubscribedUser.end_date.desc()).all()
    for i, (sub_user, user, sub) in enumerate(subscribed_users):
        if sub_user.end_date.tzinfo is None:
            sub_user.end_date = sub_user.end_date.replace(tzinfo=UTC)
    # Define a function to check if a subscription is active
    def is_active(sub_user):
        return sub_user.end_date > now
    
    return render_template('admin/subscribed_users.html', 
                          subscribed_users=subscribed_users,
                          all_plans=all_plans,
                          status_filter=status_filter,
                          plan_filter=plan_filter,
                          now=now,
                          is_active=is_active)

@app.route('/admin/subscribed-users/new', methods=['GET', 'POST'])
def admin_new_subscribed_user():
    if request.method == 'POST':
        user_id = int(request.form.get('user_id'))
        subscription_id = int(request.form.get('subscription_id'))
        auto_renew = request.form.get('auto_renew', 'off') == 'on'  # Added auto-renewal field
        
        # Check if user exists
        user = User.query.get(user_id)
        if not user:
            flash('User not found.', 'danger')
            return redirect(url_for('admin_new_subscribed_user'))
        
        # Check if subscription exists
        subscription = Subscription.query.get(subscription_id)
        if not subscription:
            flash('Subscription plan not found.', 'danger')
            return redirect(url_for('admin_new_subscribed_user'))
        
        # Check if user already has this subscription
        existing_sub = SubscribedUser.query.filter(
            SubscribedUser.U_ID == user_id,
            SubscribedUser.S_ID == subscription_id,
            SubscribedUser.end_date > datetime.now(UTC)
        ).first()
        
        if existing_sub:
            flash('User already has an active subscription to this plan.', 'warning')
            return redirect(url_for('admin_subscribed_users'))
        
        # Calculate dates
        start_date = datetime.now(UTC)
        end_date = start_date + timedelta(days=subscription.days)
        
        new_subscribed_user = SubscribedUser(
            U_ID=user_id,
            S_ID=subscription_id,
            start_date=start_date,
            end_date=end_date,
            current_usage=0,
            is_auto_renew=auto_renew  # Added auto-renewal
        )
        
        new_payment = Payment(
            base_amount=subscription.price,  # Changed from 'amount' to 'base_amount'
            user_id=user_id,
            subscription_id=subscription_id,
            razorpay_order_id=f"manual_admin_{int(time.time())}",
            razorpay_payment_id=f"manual_admin_{int(time.time())}",
            currency='INR',
            status='completed',
            payment_type='new',
            created_at=datetime.now(UTC)
        )
        
        # Add subscription history record
        new_history = SubscriptionHistory(
            U_ID=user_id,
            S_ID=subscription_id,
            action='new',
            created_at=datetime.now(UTC)
        )
        
        db.session.add(new_subscribed_user)
        db.session.add(new_payment)
        db.session.add(new_history)
        db.session.commit()
        
        flash('User subscription added successfully with payment record!', 'success')
        return redirect(url_for('admin_subscribed_users'))
    
    # Get all active users (email confirmed)
    users = User.query.filter_by(email_confirmed=True).all()
    
    # Get all subscription plans
    subscriptions = Subscription.query.all()
    
    return render_template('admin/new_subscribed_user.html', 
                          users=users, 
                          subscriptions=subscriptions)

@app.route('/admin/subscribed-users/edit/<int:id>', methods=['GET', 'POST'])
def admin_edit_subscribed_user(id):
    # Fetch the subscribed user and related data
    subscribed_user = SubscribedUser.query.get_or_404(id)
    user = User.query.get(subscribed_user.U_ID)

    if request.method == 'POST':
        # Extract form data
        subscription_id = int(request.form.get('subscription_id'))
        start_date_str = request.form.get('start_date')
        end_date_str = request.form.get('end_date')
        current_usage = int(request.form.get('current_usage', 0))
        auto_renew = request.form.get('auto_renew', 'off') == 'on'  # Auto-renewal field

        # Validate the subscription plan exists
        subscription = Subscription.query.get(subscription_id)
        if not subscription:
            flash('Subscription plan not found.', 'danger')
            return redirect(url_for('admin_edit_subscribed_user', id=id))

        # Check if start_date and end_date are provided
        if not start_date_str or not end_date_str:
            flash('Start date and End date are required.', 'danger')
            return redirect(url_for('admin_edit_subscribed_user', id=id))

        # Parse dates
        try:
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d').replace(tzinfo=UTC)
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d').replace(tzinfo=UTC)
            if end_date <= start_date:
                raise ValueError("End date must be after start date")
        except Exception as e:
            flash(f'Invalid date format: {str(e)}', 'danger')
            return redirect(url_for('admin_edit_subscribed_user', id=id))

        # Validate current usage
        if current_usage < 0:
            flash('Current usage cannot be negative.', 'danger')
            return redirect(url_for('admin_edit_subscribed_user', id=id))

        # Check if subscription has changed and record history
        old_subscription_id = subscribed_user.S_ID
        if old_subscription_id != subscription_id:
            action = 'upgrade' if subscription.tier > Subscription.query.get(old_subscription_id).tier else 'downgrade'

            # Create subscription history record
            history_record = SubscriptionHistory(
                U_ID=subscribed_user.U_ID,
                S_ID=subscription_id,
                action=action,
                previous_S_ID=old_subscription_id,
                created_at=datetime.now(UTC)
            )
            db.session.add(history_record)

        # Update the subscribed user's details
        subscribed_user.S_ID = subscription_id
        subscribed_user.start_date = start_date
        subscribed_user.end_date = end_date
        subscribed_user.current_usage = current_usage
        subscribed_user.is_auto_renew = auto_renew  # Update auto-renewal status

        db.session.commit()  # Commit the changes to the database

        flash('User subscription updated successfully!', 'success')
        return redirect(url_for('admin_subscribed_users'))

    # Fetch all subscriptions for the dropdown
    subscriptions = Subscription.query.all()
    return render_template('admin/edit_subscribed_user.html', 
                           subscribed_user=subscribed_user,
                           user=user,
                           subscriptions=subscriptions)


@app.route('/admin/subscribed-users/extend/<int:id>', methods=['POST'])
def admin_extend_subscription(id):
    subscribed_user = SubscribedUser.query.get_or_404(id)
    extension_days = int(request.form.get('extension_days', 0))
    
    if extension_days <= 0:
        flash('Extension days must be positive.', 'danger')
    else:
        # Extend the subscription
        current_end_date = subscribed_user.end_date
        new_end_date = current_end_date + timedelta(days=extension_days)
        subscribed_user.end_date = new_end_date
        
        # Create a history record for this extension
        history_record = SubscriptionHistory(
            U_ID=subscribed_user.U_ID,
            S_ID=subscribed_user.S_ID,
            action='extend',
            created_at=datetime.now(UTC)
        )
        
        db.session.add(history_record)
        db.session.commit()
        flash(f'Subscription extended by {extension_days} days successfully!', 'success')
    
    return redirect(url_for('admin_subscribed_users'))

@app.route('/admin/subscribed-users/delete/<int:id>', methods=['POST'])
def admin_delete_subscribed_user(id):
    subscribed_user = SubscribedUser.query.get_or_404(id)
    
    # Get user details for the flash message
    user = User.query.get(subscribed_user.U_ID)
    subscription = Subscription.query.get(subscribed_user.S_ID)
    
    try:
        # Check if there are any usage logs associated with this subscription
        usage_logs = UsageLog.query.filter_by(subscription_id=id).all()
        
        if usage_logs:
            # Find if user has any other active subscription
            other_subscription = SubscribedUser.query.filter(
                SubscribedUser.U_ID == subscribed_user.U_ID,
                SubscribedUser.id != id,
                SubscribedUser.end_date > datetime.now(UTC)
            ).first()
            
            if other_subscription:
                # Reassign logs to that subscription
                for log in usage_logs:
                    log.subscription_id = other_subscription.id
                db.session.flush()  # Flush changes before deletion
            else:
                # Delete the usage logs since there's no other subscription
                for log in usage_logs:
                    db.session.delete(log)
                db.session.flush()  # Flush changes before deletion
        
        # Create a history record for cancellation
        history_record = SubscriptionHistory(
            U_ID=subscribed_user.U_ID,
            S_ID=subscribed_user.S_ID,
            action='cancel',
            created_at=datetime.now(UTC)
        )
        
        db.session.add(history_record)
        db.session.delete(subscribed_user)
        db.session.commit()
        
        flash(f'Subscription for {user.name} to {subscription.plan} plan deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting subscription: {str(e)}', 'danger')
        app.logger.error(f"Error deleting subscription: {str(e)}")
    
    return redirect(url_for('admin_subscribed_users'))

@app.route('/admin/users')
def admin_users():
    email_id = session.get('email_id')
    
    if not Admin.check_permission(email_id, 'user_management'):
        flash("You don't have permission to access this page.", "danger")
        return redirect(url_for('admin_dashboard'))

    # Get filter parameters
    status_filter = request.args.get('status', 'all')
    search_query = request.args.get('search', '')
    
    # Start with base query
    query = User.query
    
    # Apply filters
    if status_filter == 'active':
        query = query.filter_by(email_confirmed=True)
    elif status_filter == 'unconfirmed':
        query = query.filter_by(email_confirmed=False)
    elif status_filter == 'admin':
        query = query.filter_by(is_admin=True)
    
    # Apply search if provided
    if search_query:
        query = query.filter(
            or_(
                User.name.ilike(f'%{search_query}%'),
                User.company_email.ilike(f'%{search_query}%')
            )
        )
    
    # Execute query and sort by creation date
    users = query.order_by(User.created_at.desc()).all()
    
    # Get subscription status for each user
    user_subscriptions = {}
    for user in users:
        active_sub = (
            db.session.query(SubscribedUser, Subscription)
            .join(Subscription, SubscribedUser.S_ID == Subscription.S_ID)
            .filter(
                SubscribedUser.U_ID == user.id,
                SubscribedUser.end_date > datetime.now(UTC)
            )
            .first()
        )
        user_subscriptions[user.id] = active_sub
    
    return render_template('admin/users.html', 
                           users=users,
                           user_subscriptions=user_subscriptions,
                           status_filter=status_filter,
                           search_query=search_query)

@app.route('/admin/users/<int:user_id>')
def admin_user_details(user_id):
    user = User.query.get_or_404(user_id)
    
    # Get user's subscription history
    subscriptions = (
        db.session.query(SubscribedUser, Subscription)
        .join(Subscription, SubscribedUser.S_ID == Subscription.S_ID)
        .filter(SubscribedUser.U_ID == user_id)
        .order_by(SubscribedUser.start_date.desc())
        .all()
    )
    
    # Get user's payment history
    payments = (
        db.session.query(Payment, Subscription)
        .join(Subscription, Payment.subscription_id == Subscription.S_ID)
        .filter(Payment.user_id == user_id)
        .order_by(Payment.created_at.desc())
        .all()
    )
    
    # Calculate current date for checking subscription status
    now = datetime.now(UTC)
    
    return render_template('admin/user_details.html',
                          user=user,
                          subscriptions=subscriptions,
                          payments=payments,
                          now=now)

@app.route('/admin/remove_user/<int:user_id>', methods=['POST'])
def remove_user(user_id):
    """
    Remove a user and all associated data from the system.
    This function carefully handles all foreign key relationships
    by deleting related records in the correct order.
    """
    # Fetch the user by ID
    user = User.query.get_or_404(user_id)
    
    # Check if the user has active subscriptions
    active_subscription = SubscribedUser.query.filter(
        SubscribedUser.U_ID == user_id,
        SubscribedUser.end_date > datetime.now(UTC)
    ).first()
    
    if active_subscription:
        flash('Cannot delete user with active subscriptions. Please remove their subscriptions first.', 'warning')
        return redirect(url_for('admin_users'))
    
    # Check if user is an admin
    if user.is_admin:
        flash('Cannot delete an admin user.', 'danger')
        return redirect(url_for('admin_users'))
    
    # Store user details for the success message
    user_email = user.company_email
    
    try:
        # Begin a transaction
        db.session.begin_nested()
        
        # Delete all related records in the correct order to avoid foreign key constraint violations
        
        # 1. First delete invoice addresses associated with the user's payments
        payment_ids = [p.iid for p in Payment.query.filter_by(user_id=user_id).all()]
        if payment_ids:
            InvoiceAddress.query.filter(InvoiceAddress.payment_id.in_(payment_ids)).delete(synchronize_session=False)
        
        # 2. Delete payments
        Payment.query.filter_by(user_id=user_id).delete(synchronize_session=False)
        
        # 3. Delete search history
        SearchHistory.query.filter_by(u_id=user_id).delete(synchronize_session=False)
        
        # 4. Delete subscription history
        SubscriptionHistory.query.filter_by(U_ID=user_id).delete(synchronize_session=False)
        
        # 5. Delete subscribed users
        SubscribedUser.query.filter_by(U_ID=user_id).delete(synchronize_session=False)
        
        # 6. Finally, delete the user
        db.session.delete(user)
        
        # Commit the transaction
        db.session.commit()
        
        app.logger.info(f"User {user_id} ({user_email}) successfully deleted")
        flash(f'User {user_email} removed successfully.', 'success')
    except Exception as e:
        # Rollback in case of error
        db.session.rollback()
        app.logger.error(f"Error deleting user {user_id}: {str(e)}")
        flash(f'Error deleting user: {str(e)}', 'danger')
    
    return redirect(url_for('admin_users'))

@app.route('/admin/edit_user/<int:user_id>', methods=['POST'])
def admin_edit_user(user_id):
    user = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('company_email')
        is_active = 'email_confirmed' in request.form
        is_admin = 'is_admin' in request.form
        
        # Check if email is already taken by another user
        existing_email = User.query.filter(
            User.company_email == email, 
            User.id != user_id
        ).first()
        
        if existing_email:
            flash('Email already taken by another user.', 'danger')
            return redirect(url_for('admin_users'))
        
        # Update user details
        user.name = name
        user.company_email = email
        user.email_confirmed = is_active
        
        # Only update admin status if current user is not modifying themselves
        if 'user_id' not in session:
            flash("You need to log in first.", "warning")
            return redirect(url_for('login'))
        current_user_id = session['user_id']

        if user_id != current_user_id:
            user.is_admin = is_admin
        else:
            if not is_admin:
                flash('You cannot remove your own admin privileges.', 'warning')
        
        db.session.commit()
        flash('User updated successfully!', 'success')
    
    return redirect(url_for('admin_user_details', user_id=user_id))

@app.route('/admin/reset_user_password/<int:user_id>', methods=['POST'])
def admin_reset_user_password(user_id):
    user = User.query.get_or_404(user_id)
    
    # Generate a random password
    new_password = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
    
    # Update the user's password
    user.set_password(new_password)
    db.session.commit()
    
    # Here you would typically send an email to the user with their new password
    # For now, we'll just flash it (in production, you'd want to email it instead)
    flash(f'Password reset successfully! Temporary password: {new_password}', 'success')
    
    return redirect(url_for('admin_user_details', user_id=user_id))

@app.route('/admin/add_user', methods=['POST'])
def admin_add_user():
    if request.method == 'POST':
        name = request.form.get('name')
        company_email = request.form.get('company_email')
        password = request.form.get('password')
        email_confirmed = 'email_confirmed' in request.form
        
        # Print debug info to console
        print(f"Form data: name={name}, email={company_email}, password_length={len(password) if password else 0}")
        
        # Check if all required fields are provided
        if not name or not company_email or not password:
            flash('All fields are required.', 'danger')
            return redirect(url_for('admin_users'))
        
        # Check if email already exists
        existing_user = User.query.filter_by(company_email=company_email).first()
        if existing_user:
            flash('A user with that email already exists.', 'danger')
            return redirect(url_for('admin_users'))
        
        try:
            # Create new user
            new_user = User(
                name=name,
                company_email=company_email,
                email_confirmed=email_confirmed,
                created_at=datetime.now(UTC)
            )
            new_user.set_password(password)
            
            db.session.add(new_user)
            db.session.commit()
            flash(f'User {name} ({company_email}) created successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error creating user: {str(e)}', 'danger')
            print(f"Database error: {str(e)}")
        
        return redirect(url_for('admin_users'))



@app.route('/admin/payments')
def admin_payments():

    email_id = session.get('email_id')
    
    if not Admin.check_permission(email_id, 'payments'):
        flash("You don't have permission to access this page.", "danger")
        return redirect(url_for('admin_dashboard'))
    
    # Get filter parameters
    status_filter = request.args.get('status', 'all')
    date_filter = request.args.get('date_range', '30')
    search_query = request.args.get('search', '')
    payment_type_filter = request.args.get('payment_type', 'all')
    
    # Base query with joins
    query = (
        db.session.query(
            Payment,
            User,
            Subscription,
            InvoiceAddress
        )
        .join(User, Payment.user_id == User.id)
        .join(Subscription, Payment.subscription_id == Subscription.S_ID)
        .outerjoin(InvoiceAddress, InvoiceAddress.payment_id == Payment.iid)
    )
    
    # Apply filters
    if status_filter != 'all':
        query = query.filter(Payment.status == status_filter)
    
    if payment_type_filter != 'all':
        query = query.filter(Payment.payment_type == payment_type_filter)
    
    # Date filter
    now = datetime.now(UTC)
    date_ranges = {
        '7': now - timedelta(days=7),
        '30': now - timedelta(days=30),
        '90': now - timedelta(days=90)
    }
    if date_filter in date_ranges:
        query = query.filter(Payment.created_at >= date_ranges[date_filter])
    
    # Search filter with expanded search capabilities
    if search_query:
        search_filter = or_(
            User.name.ilike(f'%{search_query}%'),
            User.company_email.ilike(f'%{search_query}%'),
            Payment.invoice_number.ilike(f'%{search_query}%'),
            Payment.razorpay_order_id.ilike(f'%{search_query}%'),
            Payment.customer_number.ilike(f'%{search_query}%')
        )
        query = query.filter(search_filter)
    
    # Order and pagination
    payments = (
        query.order_by(Payment.created_at.desc())
        .paginate(page=request.args.get('page', 1, type=int), per_page=50)
    )
    
    # Advanced statistics
    stats = {
        'total_payments': payments.total,
        'total_revenue': db.session.query(func.sum(Payment.total_amount))
                            .filter(Payment.status == 'completed')
                            .scalar() or 0,
        'completed_payments': db.session.query(func.count(Payment.iid))
                                .filter(Payment.status == 'completed')
                                .scalar() or 0,
        'payment_type_breakdown': dict(
            db.session.query(Payment.payment_type, func.count(Payment.iid))
            .group_by(Payment.payment_type)
            .all()
        )
    }
    
    # Revenue trend for chart
    revenue_trend = (
        db.session.query(
            func.date_trunc('day', Payment.created_at).label('day'),
            func.sum(Payment.total_amount).label('total_revenue')
        )
        .filter(Payment.status == 'completed')
        .group_by('day')
        .order_by('day')
        .limit(30)
        .all()
    )
    
    return render_template('admin/payments.html',
                           payments=payments,
                           stats=stats,
                           revenue_trend=revenue_trend,
                           filters={
                               'status': status_filter,
                               'date_range': date_filter,
                               'search': search_query,
                               'payment_type': payment_type_filter
                           })

@app.route('/admin/payments/<string:order_id>')
def admin_payment_details(order_id):
    # Comprehensive payment details query
    payment_details = (
        db.session.query(
            Payment,
            User,
            Subscription,
            InvoiceAddress
        )
        .join(User, Payment.user_id == User.id)
        .join(Subscription, Payment.subscription_id == Subscription.S_ID)
        .outerjoin(InvoiceAddress, InvoiceAddress.payment_id == Payment.iid)
        .filter(Payment.invoice_number == order_id)
        .first_or_404()
    )
    
    # Unpack query results
    payment, user, subscription, invoice_address = payment_details
    
    # Fetch Razorpay details if applicable
    razorpay_details = None
    if payment.razorpay_payment_id and not payment.razorpay_payment_id.startswith('manual_'):
        try:
            razorpay_details = razorpay_client.payment.fetch(payment.razorpay_payment_id)
        except Exception as e:
            app.logger.warning(f"Razorpay fetch error: {str(e)}")
    
    # Related payments history
    related_payments = (
        Payment.query
        .filter(Payment.user_id == user.id)
        .order_by(Payment.created_at.desc())
        .limit(5)
        .all()
    )
    
    return render_template('admin/payment_details.html', 
                           payment=payment, 
                           user=user, 
                           subscription=subscription,
                           invoice_address=invoice_address,
                           razorpay_details=razorpay_details,
                           related_payments=related_payments)

@app.route('/admin/payments/update/<string:order_id>', methods=['POST'])
def admin_update_payment(order_id):
    payment = Payment.query.filter_by(invoice_number=order_id).first_or_404()
    
    # Validate and update payment status
    new_status = request.form.get('status')
    valid_statuses = ['created', 'completed', 'failed', 'cancelled']
    
    if new_status in valid_statuses:
        old_status = payment.status
        payment.status = new_status
        
        # Additional status change logic
        try:
            if new_status == 'completed' and old_status != 'completed':
                # Ensure invoice is generated
                if not payment.invoice_number:
                    payment.invoice_number = generate_unique_invoice_number()
                
                # Create or update subscription
                create_or_update_subscription(payment)
                
                # Generate invoice address if not exists
                create_invoice_address_for_payment(payment)
            
            db.session.commit()
            flash('Payment status updated successfully', 'success')
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Payment update error: {str(e)}")
            flash(f'Error updating payment: {str(e)}', 'danger')
    else:
        flash('Invalid status', 'danger')
    
    return redirect(url_for('admin_payment_details', order_id=order_id))

@app.route('/admin/payment/<order_id>/invoice')
@admin_required  
def admin_payment_invoice(order_id):
    """
    Generate and serve a PDF invoice for a specific payment order
    
    :param order_id: Razorpay order ID
    :return: PDF file response
    """
    # Find the payment by order_id
    payment = Payment.query.filter_by(razorpay_order_id=order_id).first_or_404()
    
    # Generate PDF invoice
    pdf_buffer = generate_invoice_pdf(payment)
    
    # Send the PDF as a download
    return send_file(
        pdf_buffer,
        download_name=f"invoice_{payment.invoice_number}.pdf",
        as_attachment=True,
        mimetype='application/pdf'
    )

def generate_unique_invoice_number():
    """
    Generate a unique invoice number
    """
    timestamp = datetime.now(UTC).strftime("%y%m%d")
    unique_id = str(uuid.uuid4().hex)[:8]
    return f"INV-{timestamp}-{unique_id}"

def create_or_update_subscription(payment):
    """
    Create or update subscription based on payment
    """
    # Check if subscription already exists
    existing_sub = SubscribedUser.query.filter_by(
        U_ID=payment.user_id,
        S_ID=payment.subscription_id
    ).first()
    
    if not existing_sub:
        subscription = Subscription.query.get(payment.subscription_id)
        start_date = datetime.now(UTC)
        end_date = start_date + timedelta(days=subscription.days)
        
        new_subscription = SubscribedUser(
            U_ID=payment.user_id,
            S_ID=payment.subscription_id,
            start_date=start_date,
            end_date=end_date,
            current_usage=0,
            is_auto_renew=True
        )
        
        # Record subscription history
        history_entry = SubscriptionHistory(
            U_ID=payment.user_id,
            S_ID=payment.subscription_id,
            action=payment.payment_type,
            previous_S_ID=payment.previous_subscription_id
        )
        
        db.session.add(new_subscription)
        db.session.add(history_entry)

def create_invoice_address_for_payment(payment):
    """
    Create invoice address for payment if not exists
    """
    existing_address = InvoiceAddress.query.filter_by(payment_id=payment.iid).first()
    
    if not existing_address:
        # Try to get user details
        user = User.query.get(payment.user_id)
        
        new_address = InvoiceAddress(
            payment_id=payment.iid,
            full_name=user.name,
            email=user.company_email,
            company_name=user.company_name if hasattr(user, 'company_name') else None,
            street_address=user.address if hasattr(user, 'address') else 'N/A',
            city=user.city if hasattr(user, 'city') else 'N/A',
            state=user.state if hasattr(user, 'state') else 'N/A',
            postal_code=user.postal_code if hasattr(user, 'postal_code') else 'N/A',
            gst_number=user.gst_number if hasattr(user, 'gst_number') else None
        )
        
        db.session.add(new_address)
# ----------------------
# Subscription Routes with Archive Handling
# ----------------------
# Update this route in your app.py file

@app.route('/subscriptions')
@login_required
def user_subscriptions():
    user_id = session.get('user_id')
    if not user_id:
        flash("You need to log in first.", "warning")
        return redirect(url_for('login'))
    
    # Get current time
    now = datetime.now(UTC)
    
    # Get the most recent active subscription for the user
    active_subscription = None
    subscriptions = (
        db.session.query(SubscribedUser, Subscription)
        .join(Subscription, SubscribedUser.S_ID == Subscription.S_ID)
        .filter(SubscribedUser.U_ID == user_id)
        .filter(SubscribedUser.end_date > now)
        .filter(SubscribedUser._is_active == True)  # Using the underlying column
        .filter(Subscription.archived_at.is_(None))  # Only non-archived plans
        .order_by(SubscribedUser.start_date.desc())  # Changed from created_at to start_date
        .all()
    )
    
    # If multiple active subscriptions exist (shouldn't happen normally)
    if len(subscriptions) > 1:
        # Keep only the most recent active subscription
        active_subscription = subscriptions[0]
        
        # Deactivate all other active subscriptions
        for sub, plan in subscriptions[1:]:
            sub.is_active = False
            flash(f'Duplicate subscription "{plan.plan}" has been deactivated.', 'info')
        
        db.session.commit()
    elif len(subscriptions) == 1:
        active_subscription = subscriptions[0]
    
    # Ensure all datetime objects are timezone-aware
    if active_subscription:
        sub, plan = active_subscription
        if sub.start_date and sub.start_date.tzinfo is None:
            sub.start_date = sub.start_date.replace(tzinfo=UTC)
        if sub.end_date and sub.end_date.tzinfo is None:
            sub.end_date = sub.end_date.replace(tzinfo=UTC)
    
    # Get payment history for the user
    payment_history = Payment.query.filter_by(user_id=user_id).order_by(Payment.created_at.desc()).all()
    
    # Get available active and non-archived subscription plans
    available_plans = (
        Subscription.query
        .filter(Subscription.is_active == True)
        .filter(Subscription.archived_at.is_(None))
        .all()
    )
    
    return render_template(
        'user/subscriptions.html',
        active_subscription=active_subscription,  # Pass only the single active subscription
        payment_history=payment_history,
        available_plans=available_plans,
        now=now,
        hasattr=hasattr
    )
@app.route('/subscribe/<int:plan_id>', methods=['POST'])
@login_required
def subscribe(plan_id):
    user_id = session.get('user_id')
    app.logger.info(f"Subscribe request received for plan {plan_id} by user {user_id}")

    # Check if user already has an active subscription
    now = datetime.now(UTC)
    active_subscription = SubscribedUser.query.filter(
        SubscribedUser.U_ID == user_id,
        SubscribedUser.end_date > now,
        SubscribedUser._is_active == True  # Using the underlying column name from your model
    ).first()
    
    if active_subscription:
        flash('You already have an active subscription. Please wait for it to expire or cancel it before subscribing to a new plan.', 'warning')
        return redirect(url_for('user_subscriptions'))

    # Get the subscription plan
    subscription = (
        Subscription.query
        .filter(Subscription.S_ID == plan_id)
        .filter(Subscription.is_active == True)
        .filter(Subscription.archived_at.is_(None))
        .first_or_404()
    )
    
    # Create Razorpay order
    try:
        # Consistent GST calculation
        gst_rate = 0.18  # 18% GST
        base_amount = subscription.price
        gst_amount = base_amount * gst_rate
        total_amount = base_amount + gst_amount
        
        # Convert to paisa and round to integer
        amount_in_paisa = int(total_amount * 100)
        currency = 'INR'
        
        # Robust price validation
        if total_amount <= 0 or amount_in_paisa <= 0:
            app.logger.error(f'Invalid subscription price for plan {plan_id}')
            flash('Invalid subscription price. Please contact support.', 'danger')
            return redirect(url_for('user_subscriptions'))
        
        # Create Razorpay order
        razorpay_order = razorpay_client.order.create({
            'amount': amount_in_paisa,
            'currency': currency,
            'payment_capture': '1',
            'notes': {
                'user_id': user_id,
                'plan_id': plan_id,
                'description': f'Subscription for {subscription.plan}'
            }
        })
        
        # Store order details in the database with consistent calculations
        payment = Payment(
            base_amount=base_amount,
            gst_amount=gst_amount,
            total_amount=total_amount,
            user_id=user_id,
            subscription_id=plan_id,
            razorpay_order_id=razorpay_order['id'],
            currency=currency,
            status='created',
            payment_type='new',
            gst_rate=gst_rate
        )
        db.session.add(payment)
        db.session.commit()
        
        # Redirect to checkout page with Razorpay details
        return redirect(url_for('checkout', order_id=razorpay_order['id']))
        
    except Exception as e:
        app.logger.error(f"Error in subscribe route: {str(e)}", exc_info=True)
        db.session.rollback()
        flash(f'Error creating payment. Please try again or contact support.', 'danger')
        return redirect(url_for('user_subscriptions'))


# Optional: Add a validation method to Payment model
def validate_razorpay_order(subscription, amount, payment):
    """
    Validate Razorpay order details
    
    :param subscription: Subscription object
    :param amount: Amount in paisa
    :param payment: Payment object
    :return: Boolean indicating if order is valid
    """
    try:
        expected_amount = int(payment.total_amount * 100)
        return amount == expected_amount
    except Exception as e:
        app.logger.error(f"Order validation error: {str(e)}")
        return False


@app.route('/get_available_plans')
@login_required
def get_available_plans():
    user_id = session.get('user_id')
    
    # Get current active subscription
    current_subscription = (
        SubscribedUser.query
        .filter(SubscribedUser.U_ID == user_id)
        .filter(SubscribedUser.end_date > datetime.now(UTC))
        .first()
    )
    
    # Get query parameter to exclude current plan
    exclude_plan_id = request.args.get('exclude', type=int)
    
    # Get available plans
    available_plans = (
        Subscription.query
        .filter(Subscription.is_active == True)
        .filter(Subscription.archived_at.is_(None))
        .filter(Subscription.S_ID != exclude_plan_id)
        .all()
    )
    
    # Convert to JSON
    plans_json = [
        {
            'S_ID': plan.S_ID,
            'plan': plan.plan,
            'price': plan.price,
            'days': plan.days,
            'tier': plan.tier
        } for plan in available_plans
    ]
    
    return jsonify(plans_json)

@app.route('/subscription_details/<int:subscription_id>')
@login_required
def subscription_details(subscription_id):
    user_id = session.get('user_id')
    page = request.args.get('page', 1, type=int)
    per_page = 10  # Number of records per page
    
    # Verify the subscription belongs to the logged-in user
    subscription = (
        db.session.query(SubscribedUser, Subscription)
        .join(Subscription, SubscribedUser.S_ID == Subscription.S_ID)
        .filter(SubscribedUser.id == subscription_id, SubscribedUser.U_ID == user_id)
        .first_or_404()
    )
    
    # Get paginated subscription usage history
    usage_query = (
        UsageLog.query
        .filter(UsageLog.subscription_id == subscription_id)
        .order_by(UsageLog.timestamp.desc())
    )
    
    # Paginate the results
    usage_history = usage_query.paginate(page=page, per_page=per_page, error_out=False)
    
    # Get payment records for this subscription
    payment_records = (
        Payment.query
        .filter_by(subscription_id=subscription[0].S_ID, user_id=user_id)
        .order_by(Payment.created_at.desc())
        .all()
    )
    
    # Calculate daily usage statistics
    daily_usage = {}
    # Using usage_query to get data for stats
    all_usage = usage_query.limit(100).all()  # Get recent usage for stats (limit to 100)
    
    if all_usage:
        for usage in all_usage:
            date_key = usage.timestamp.strftime('%Y-%m-%d')
            if date_key not in daily_usage:
                daily_usage[date_key] = 0
            daily_usage[date_key] += 1
    
    # Sort daily usage by date
    sorted_daily_usage = [(k, v) for k, v in sorted(daily_usage.items())]
    
    return render_template(
        'user/subscription_details.html',
        subscription=subscription[0],
        plan=subscription[1],
        usage_history=usage_history,
        payment_records=payment_records,
        daily_usage=sorted_daily_usage,
        current_date=datetime.now(UTC)
    )


@app.route('/subscription/<int:subscription_id>/usage_history')
@login_required
def get_usage_history(subscription_id):
    """AJAX endpoint to get paginated usage history"""
    user_id = session.get('user_id')
    page = request.args.get('page', 1, type=int)
    per_page = 10
    
    # Verify the subscription belongs to the logged-in user
    subscription = (
        db.session.query(SubscribedUser, Subscription)
        .join(Subscription, SubscribedUser.S_ID == Subscription.S_ID)
        .filter(SubscribedUser.id == subscription_id, SubscribedUser.U_ID == user_id)
        .first_or_404()
    )
    
    # Get paginated usage history
    usage_history = (
        UsageLog.query
        .filter(UsageLog.subscription_id == subscription_id)
        .order_by(UsageLog.timestamp.desc())
        .paginate(page=page, per_page=per_page, error_out=False)
    )
    
    # Check if this is an AJAX request
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return render_template(
            'user/partials/usage_history.html',
            subscription=subscription[0],
            usage_history=usage_history
        )
    
    # If not an AJAX request, redirect to the main page
    return redirect(url_for('subscription_details', subscription_id=subscription_id, page=page))

def generate_invoice_pdf(payment):
    """
    Generate a modern, visually aesthetic PDF invoice for a specific payment
    
    :param payment: Payment model instance
    :return: BytesIO buffer containing the PDF
    """
    from io import BytesIO
    import os
    from reportlab.lib.pagesizes import A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
    from reportlab.lib.units import inch, mm
    from reportlab.lib.enums import TA_LEFT, TA_RIGHT, TA_CENTER

    # Define brand colors to match the logo
    brand_color = colors.Color(0.73, 0.20, 0.04)  # Rust/orange color from logo
    secondary_color = colors.Color(0.95, 0.95, 0.95)  # Light gray for backgrounds
    text_color = colors.Color(0.25, 0.25, 0.25)  # Dark gray for text

    # Prepare buffer and document with reduced margins
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer, 
        pagesize=A4, 
        leftMargin=15*mm, 
        rightMargin=15*mm, 
        topMargin=15*mm, 
        bottomMargin=15*mm
    )
    width, height = A4
    
    # Create styles - use new style names to avoid conflict
    styles = getSampleStyleSheet()
    
    # Create custom styles without adding to stylesheet
    brand_title_style = ParagraphStyle(
        name='BrandTitleCustom',
        fontName='Helvetica-Bold',
        fontSize=20,
        textColor=brand_color,
        spaceAfter=3
    )
    
    company_name_style = ParagraphStyle(
        name='CompanyNameCustom',
        fontName='Helvetica-Bold',
        fontSize=14,
        textColor=brand_color,
        spaceAfter=3
    )
    
    invoice_title_style = ParagraphStyle(
        name='InvoiceTitleCustom',
        fontName='Helvetica-Bold',
        fontSize=16,
        alignment=TA_RIGHT,
        textColor=brand_color,
        spaceAfter=6
    )
    
    section_title_style = ParagraphStyle(
        name='SectionTitleCustom',
        fontName='Helvetica-Bold',
        fontSize=10,
        textColor=brand_color,
        spaceAfter=3
    )
    
    normal_style = ParagraphStyle(
        name='NormalCustom',
        fontName='Helvetica',
        fontSize=9,
        textColor=text_color,
        leading=12
    )
    
    right_aligned_style = ParagraphStyle(
        name='RightAlignedCustom',
        fontName='Helvetica',
        fontSize=9,
        alignment=TA_RIGHT,
        textColor=text_color
    )
    
    address_style = ParagraphStyle(
        name='AddressStyleCustom',
        fontName='Helvetica',
        fontSize=9,
        textColor=text_color,
        leading=12
    )

    # Prepare elements
    elements = []
    
    # Top Header with Logo and Invoice Title
    logo_path = os.path.join('assert', '4d-logo.webp')
    
    try:
        logo = Image(logo_path, width=1.7*inch, height=0.85*inch)
    except:
        # Fallback if image not found
        logo = Paragraph("Fourth Dimension", brand_title_style)
    
    # Header with logo on left and invoice title on right
    header_data = [
        [
            logo,
            Paragraph("TAX INVOICE", invoice_title_style)
        ]
    ]
    
    header_table = Table(header_data, colWidths=[doc.width/2, doc.width/2])
    header_table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('ALIGN', (0, 0), (0, 0), 'LEFT'),
        ('ALIGN', (1, 0), (1, 0), 'RIGHT'),
    ]))
    elements.append(header_table)
    
    # Add colored separator line
    elements.append(Spacer(1, 5))
    separator = Table([['']], colWidths=[doc.width], rowHeights=[2])
    separator.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), brand_color),
    ]))
    elements.append(separator)
    elements.append(Spacer(1, 10))
    
    # Company and Invoice Details section
    # Left: Company Details, Right: Invoice Details
    company_details = Table([
        [Paragraph("Fourth Dimension Media Solutions", company_name_style)],
        [Paragraph("24, Gopathi Narayanaswami Chetty Rd", address_style)],
        [Paragraph("Lakshimi Colony, T. Nagar", address_style)],
        [Paragraph("Chennai, Tamil Nadu-600017", address_style)],
        [Paragraph("GST: 783y823rh932h9 | PAN: 638uhio3iu3", address_style)]
    ])
    
    invoice_details = Table([
        [Paragraph("<b>Invoice Number:</b>", normal_style), 
         Paragraph(f"{payment.invoice_number}", right_aligned_style)],
        [Paragraph("<b>Invoice Date:</b>", normal_style), 
         Paragraph(f"{payment.invoice_date.strftime('%B %d, %Y')}", right_aligned_style)],
        [Paragraph("<b>Due Date:</b>", normal_style), 
         Paragraph(f"{payment.invoice_date.strftime('%B %d, %Y')}", right_aligned_style)],
        [Paragraph("<b>Status:</b>", normal_style), 
         Paragraph(f"{payment.status}", right_aligned_style)]
    ])
    
    details_row = [
        [company_details, invoice_details]
    ]
    
    details_table = Table(details_row, colWidths=[doc.width/2, doc.width/2])
    details_table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('ALIGN', (0, 0), (0, 0), 'LEFT'),
        ('ALIGN', (1, 0), (1, 0), 'RIGHT'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 15)
    ]))
    elements.append(details_table)
    
    # Bill To Section
    if payment.invoice_address:
        addr = payment.invoice_address
        customer_info = [
            [Paragraph("<b>BILL TO:</b>", section_title_style)],
            [Paragraph(f"{addr.full_name}", normal_style)],
            [Paragraph(f"{addr.company_name or ''}", normal_style)],
            [Paragraph(f"{addr.street_address}", normal_style)],
            [Paragraph(f"{addr.city}, {addr.state} {addr.postal_code}", normal_style)],
            [Paragraph(f"GST: {addr.gst_number or 'N/A'}", normal_style)]
        ]
    else:
        user = payment.user
        customer_info = [
            [Paragraph("<b>BILL TO:</b>", section_title_style)],
            [Paragraph(f"{user.name}", normal_style)],
            [Paragraph(f"Email: {user.company_email}", normal_style)]
        ]
    
    customer_table = Table(customer_info)
    customer_table.setStyle(TableStyle([
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3)
    ]))
    elements.append(customer_table)
    elements.append(Spacer(1, 15))
    
    # Invoice Items Table with modern styling
    table_header = ["Description", "Quantity", "Unit Price", "Total"]
    table_data = [table_header]
    
    # Add subscription item
    table_data.append([
        f"Subscription: {payment.subscription.plan}", 
        "1", 
        f"₹{payment.base_amount:.2f}", 
        f"₹{payment.base_amount:.2f}"
    ])
    
    # Add GST line
    table_data.append([
        "GST", 
        "", 
        f"{payment.gst_rate * 100:.0f}%", 
        f"₹{payment.gst_amount:.2f}"
    ])
    
    # Table styling
    col_widths = [doc.width*0.5, doc.width*0.15, doc.width*0.15, doc.width*0.2]
    items_table = Table(table_data, colWidths=col_widths)
    
    # Define table styles for a more modern look
    table_style = TableStyle([
        # Header row styling
        ('BACKGROUND', (0, 0), (-1, 0), brand_color),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, 0), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
        ('TOPPADDING', (0, 0), (-1, 0), 8),
        # Data rows
        ('BACKGROUND', (0, 1), (-1, -1), colors.white),
        ('TEXTCOLOR', (0, 1), (-1, -1), text_color),
        ('ALIGN', (0, 1), (0, -1), 'LEFT'),  # Description column left aligned
        ('ALIGN', (1, 1), (-1, -1), 'RIGHT'),  # All other columns right aligned
        # Borders - minimal modern look with only horizontal lines
        ('LINEBELOW', (0, 0), (-1, -2), 0.5, colors.lightgrey),
        ('TOPPADDING', (0, 1), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 1), (-1, -1), 6),
    ])
    items_table.setStyle(table_style)
    elements.append(items_table)
    
    # Total row separated from the main table for emphasis
    total_data = [
        ["", "", "Total Amount:", f"₹{payment.total_amount:.2f}"]
    ]
    total_table = Table(total_data, colWidths=col_widths)
    total_table.setStyle(TableStyle([
        ('BACKGROUND', (2, 0), (3, 0), secondary_color),
        ('TEXTCOLOR', (2, 0), (3, 0), brand_color),
        ('ALIGN', (2, 0), (3, 0), 'RIGHT'),
        ('FONTNAME', (2, 0), (3, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (2, 0), (3, 0), 10),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
    ]))
    elements.append(total_table)
    elements.append(Spacer(1, 15))
    
    # Payment information and terms in a bottom section
    payment_terms = [
        [
            Table([
                [Paragraph("<b>PAYMENT INFORMATION</b>", section_title_style)],
                [Paragraph(f"Payment Method: {payment.payment_type}", normal_style)],
                [Paragraph(f"Payment Status: {payment.status}", normal_style)]
            ]),
            Table([
                [Paragraph("<b>TERMS & CONDITIONS</b>", section_title_style)],
                [Paragraph("This is a computer-generated invoice.", normal_style)],
                [Paragraph("No signature required.", normal_style)]
            ])
        ]
    ]
    footer_table = Table(payment_terms, colWidths=[doc.width/2, doc.width/2])
    footer_table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('TOPPADDING', (0, 0), (-1, -1), 0),
    ]))
    elements.append(footer_table)
    
    # Add final colored separator line
    elements.append(Spacer(1, 15))
    elements.append(separator)
    
    # Final footer note
    elements.append(Spacer(1, 10))
    support_note = Paragraph("For any queries, please contact our support team at support@fourthdimension.com", 
                             normal_style)
    elements.append(support_note)
    
    # Build PDF
    doc.build(elements)
    
    # Reset buffer position
    buffer.seek(0)
    
    return buffer

# Example usage in a route
@app.route('/download_invoice/<int:payment_id>')
@login_required
def download_invoice(payment_id):
    # Fetch the payment
    payment = Payment.query.get_or_404(payment_id)
    
    # Verify user authorization (optional but recommended)
    if payment.user_id != current_user.id:
        flash('Unauthorized access to invoice', 'error')
        return redirect(url_for('dashboard'))
    
    # Generate the invoice PDF
    pdf_buffer = generate_invoice_pdf(payment)
    
    # Send the PDF as a download
    return send_file(
        pdf_buffer,
        download_name=f"invoice_{payment.invoice_number}.pdf",
        as_attachment=True,
        mimetype='application/pdf'
    )
        
@app.route('/subscription/<int:subscription_id>')
@login_required
def view_subscription_details(subscription_id):
    subscription = SubscribedUser.query.get_or_404(subscription_id)
    
    # Verify this subscription belongs to the current user
    if subscription.U_ID != session.get('user_id'):
        flash('Unauthorized action', 'danger')
        return redirect(url_for('user_subscriptions'))
    
    # Get plan details
    plan = Subscription.query.get(subscription.S_ID)
    
    # Get payment history
    payments = Payment.query.filter_by(
        user_id=session.get('user_id'),
        subscription_id=subscription.S_ID
    ).order_by(Payment.created_at.desc()).all()
    
    return render_template('user/subscription_details.html', 
                          subscription=subscription, 
                          plan=plan,
                          payments=payments)
@app.route('/checkout/<order_id>', methods=['GET', 'POST'])
@login_required
def checkout(order_id):
    user_id = session.get('user_id')
    
    # Get user details using get() method recommended for SQLAlchemy 2.0
    user = db.session.get(User, user_id)
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('login'))
    
    # Get payment and subscription details
    payment = Payment.query.filter_by(razorpay_order_id=order_id, user_id=user_id).first()
    if not payment:
        flash('Payment not found', 'danger')
        return redirect(url_for('user_subscriptions'))
    
    # Use get() method for subscription
    subscription = db.session.get(Subscription, payment.subscription_id)
    if not subscription:
        flash('Subscription not found', 'danger')
        return redirect(url_for('user_subscriptions'))
    
    if request.method == 'POST':
        # Validate required fields
        required_fields = [
            'full_name', 'street_address', 'city', 
            'state', 'postal_code', 'country', 
            'email', 'phone_number'
        ]
        
        # Check if all required fields are filled
        for field in required_fields:
            if not request.form.get(field):
                flash(f'Please fill in all required fields, especially {field.replace("_", " ")}', 'warning')
                return render_template(
                    'user/checkout.html',
                    user=user,
                    payment=payment,
                    subscription=subscription,
                    razorpay_key_id=app.config['RAZORPAY_KEY_ID']
                )
        
        # Create or update invoice address
        invoice_address = InvoiceAddress(
            payment_id=payment.iid,
            full_name=request.form.get('full_name'),
            company_name=request.form.get('company_name', ''),
            street_address=request.form.get('street_address'),
            city=request.form.get('city'),
            state=request.form.get('state'),
            postal_code=request.form.get('postal_code'),
            country=request.form.get('country', 'India'),
            email=request.form.get('email', user.company_email),
            phone_number=request.form.get('phone_number'),
            gst_number=request.form.get('gst_number', ''),
            pan_number=request.form.get('pan_number', '')
        )
        
        db.session.add(invoice_address)
        db.session.commit()
        
        return redirect(url_for('verify_payment', order_id=order_id))
    
    return render_template(
        'user/checkout.html',
        user=user,
        payment=payment,
        subscription=subscription,
        base_amount=payment.base_amount,
        gst_rate=payment.gst_rate,
        gst_amount=payment.gst_amount,
        total_amount=payment.total_amount,
        razorpay_key_id=app.config['RAZORPAY_KEY_ID']
    )

@app.route('/payment/verify/<order_id>', methods=['GET', 'POST'])
@login_required
def verify_payment(order_id):
    user_id = session.get('user_id')
    if not user_id:
        flash("You need to log in first.", "warning")
        return redirect(url_for('login'))
    
    # Get user details
    user = User.query.get_or_404(user_id)
    
    # Handle GET request - show payment verification page
    if request.method == 'GET':
        # Find pending payment for this order_id and user
        payment = Payment.query.filter_by(
            razorpay_order_id=order_id, 
            user_id=user_id, 
            status='created'
        ).first()
        
        if not payment:
            flash('No pending payment found for this order.', 'warning')
            return redirect(url_for('user_subscriptions'))
        
        # Load subscription details for display
        subscription = Subscription.query.get(payment.subscription_id)
        if not subscription:
            flash('Subscription not found.', 'danger')
            return redirect(url_for('user_subscriptions'))
        
        # Render verification page with all necessary data
        return render_template('payment/verify.html', 
                               payment=payment, 
                               subscription=subscription,
                               user=user,
                               razorpay_key_id=app.config['RAZORPAY_KEY_ID'])
    
    # Handle POST request - actual payment verification
    try:
        # Get payment details from Razorpay callback
        razorpay_payment_id = request.form.get('razorpay_payment_id')
        razorpay_order_id = request.form.get('razorpay_order_id')
        razorpay_signature = request.form.get('razorpay_signature')
        
        # Validate input parameters
        if not all([razorpay_payment_id, razorpay_order_id, razorpay_signature]):
            app.logger.error(f"Missing payment details for order: {order_id}")
            flash('Missing payment details. Please try again.', 'danger')
            return redirect(url_for('user_subscriptions'))
        
        # Find the payment record
        payment = Payment.query.filter_by(
            razorpay_order_id=razorpay_order_id, 
            user_id=user_id, 
            status='created'
        ).first()
        
        if not payment:
            app.logger.error(f"Payment record not found for order: {razorpay_order_id}, user: {user_id}")
            flash('Payment record not found.', 'danger')
            return redirect(url_for('user_subscriptions'))
        
        # Verify signature using custom method
        signature_valid = verify_razorpay_signature(
            razorpay_order_id, 
            razorpay_payment_id, 
            razorpay_signature, 
            app.config['RAZORPAY_KEY_SECRET']
        )
        
        if not signature_valid:
            app.logger.error(f"Signature verification failed for payment: {razorpay_payment_id}")
            flash('Payment verification failed. Please contact support.', 'danger')
            return redirect(url_for('user_subscriptions'))
        
        # Fetch payment details from Razorpay to verify amount
        try:
            payment_details = razorpay_client.payment.fetch(razorpay_payment_id)
            
            # Convert total_amount to paisa for comparison
            expected_amount_in_paisa = int(payment.total_amount * 100)
            
            # Verify the amount matches the expected amount
            if payment_details['amount'] != expected_amount_in_paisa:
                app.logger.error(
                    f"Amount mismatch: Expected {expected_amount_in_paisa}, "
                    f"Got {payment_details['amount']} for payment: {razorpay_payment_id}"
                )
                flash('Payment amount verification failed. Please contact support.', 'danger')
                return redirect(url_for('user_subscriptions'))
                
            # Verify payment is authorized/captured
            if payment_details['status'] not in ['authorized', 'captured']:
                app.logger.error(f"Payment not authorized: {payment_details['status']}")
                flash('Payment was not authorized. Please try again.', 'danger')
                return redirect(url_for('user_subscriptions'))
                
        except Exception as fetch_error:
            app.logger.error(f"Error fetching payment details from Razorpay: {str(fetch_error)}")
            flash('Unable to verify payment details with Razorpay.', 'danger')
            return redirect(url_for('user_subscriptions'))
        
        # Begin database transaction
        try:
            db.session.begin_nested()
            
            # Update payment details
            payment.razorpay_payment_id = razorpay_payment_id
            payment.status = 'completed'
            
            # Create new subscription (or update existing)
            subscription = Subscription.query.get(payment.subscription_id)
            
            # Calculate subscription dates
            start_date = datetime.now(UTC)
            end_date = start_date + timedelta(days=subscription.days)
            
            # Create new SubscribedUser record
            new_subscription = SubscribedUser(
                U_ID=user_id,
                S_ID=subscription.S_ID,
                start_date=start_date,
                end_date=end_date,
                is_auto_renew=True,  # Default to auto-renew
                current_usage=0,
                last_usage_reset=start_date,
                _is_active=True  # Set as active subscription
            )
            
            db.session.add(new_subscription)
            
            # Add subscription history entry
            history_entry = SubscriptionHistory(
                U_ID=user_id,
                S_ID=subscription.S_ID,
                action=payment.payment_type,  # 'new', 'upgrade', etc.
                previous_S_ID=payment.previous_subscription_id,
                created_at=datetime.now(UTC)
            )
            db.session.add(history_entry)
            
            # Send confirmation email (optional)
            try:
                send_payment_confirmation_email(user, payment, subscription)
            except Exception as email_error:
                # Log but don't fail if email sending fails
                app.logger.error(f"Failed to send confirmation email: {str(email_error)}")
            
            # Commit all changes
            db.session.commit()
            
            app.logger.info(f"Payment successful: {razorpay_payment_id} for user: {user_id}")
            flash(f'Payment successful! You are now subscribed to the {subscription.plan} plan.', 'success')
            return redirect(url_for('user_subscriptions'))
            
        except Exception as db_error:
            # Roll back transaction on error
            db.session.rollback()
            app.logger.error(f"Database error during payment processing: {str(db_error)}")
            flash('Error processing payment. Please contact support.', 'danger')
            return redirect(url_for('user_subscriptions'))
    
    except Exception as e:
        # Catch-all for unexpected errors
        app.logger.error(f"Unexpected error in payment verification: {str(e)}", exc_info=True)
        flash('An unexpected error occurred. Please try again or contact support.', 'danger')
        return redirect(url_for('user_subscriptions'))


def verify_razorpay_signature(razorpay_order_id, razorpay_payment_id, razorpay_signature, razorpay_key_secret):
    """
    Verify Razorpay payment signature using HMAC SHA-256
    
    Args:
        razorpay_order_id (str): Order ID from Razorpay
        razorpay_payment_id (str): Payment ID from Razorpay
        razorpay_signature (str): Signature from Razorpay
        razorpay_key_secret (str): Razorpay key secret
    
    Returns:
        bool: True if signature is valid, False otherwise
    """
    try:
        # Create signature payload
        payload = f"{razorpay_order_id}|{razorpay_payment_id}"
        
        # Import hmac and hashlib for signature generation
        import hmac
        import hashlib
        
        # Generate expected signature
        generated_signature = hmac.new(
            razorpay_key_secret.encode('utf-8'), 
            payload.encode('utf-8'), 
            hashlib.sha256
        ).hexdigest()
        
        # Use constant-time comparison to prevent timing attacks
        return hmac.compare_digest(generated_signature, razorpay_signature)
    
    except Exception as e:
        app.logger.error(f"Signature verification error: {str(e)}")
        return False


def send_payment_confirmation_email(user, payment, subscription):
    """
    Send payment confirmation email to user
    
    Args:
        user (User): User model instance
        payment (Payment): Payment model instance
        subscription (Subscription): Subscription model instance
    """
    subject = f"Payment Confirmation - {subscription.plan} Subscription"
    
    # Calculate subscription end date
    start_date = datetime.now(UTC)
    end_date = start_date + timedelta(days=subscription.days)
    
    message = Message(
        subject,
        sender=app.config['MAIL_USERNAME'],
        recipients=[user.company_email]
    )
    
    message.body = f"""Dear {user.name},

Thank you for your payment of {payment.total_amount} {payment.currency} for the {subscription.plan} subscription plan.

Payment Details:
- Order ID: {payment.razorpay_order_id}
- Payment ID: {payment.razorpay_payment_id}
- Invoice Number: {payment.invoice_number}
- Amount: {payment.total_amount} {payment.currency}
- Date: {datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S')} UTC

Subscription Details:
- Plan: {subscription.plan}
- Start Date: {start_date.strftime('%Y-%m-%d')}
- End Date: {end_date.strftime('%Y-%m-%d')}
- Daily Usage Limit: {subscription.usage_per_day} operations

You can download your invoice from your account dashboard.

Thank you for choosing our service!

Best regards,
The Team
"""
    
    mail.send(message)
        
@app.route('/subscription/change/<int:new_plan_id>', methods=['GET', 'POST'])
@login_required
def change_subscription(new_plan_id):
    user_id = session.get('user_id')
    
    # Extensive logging for debugging
    app.logger.info(f"Attempting to change subscription for user {user_id}")
    
    # Fetch all subscriptions for the user for detailed inspection
    all_subscriptions = (
        SubscribedUser.query
        .filter(SubscribedUser.U_ID == user_id)
        .all()
    )
    
    # Log details of all subscriptions
    for sub in all_subscriptions:
        app.logger.info(f"Subscription ID: {sub.id}")
        app.logger.info(f"Subscription Plan ID: {sub.S_ID}")
        app.logger.info(f"Start Date: {sub.start_date}")
        app.logger.info(f"End Date: {sub.end_date}")
        app.logger.info(f"Is Active (property): {sub.is_active}")
        app.logger.info(f"Is Active (column): {sub._is_active}")
        app.logger.info(f"Current Time (UTC): {datetime.now(UTC)}")
    
    # Get current active subscription with more detailed conditions
    current_subscription = (
        SubscribedUser.query
        .filter(SubscribedUser.U_ID == user_id)
        .filter(SubscribedUser.end_date > datetime.now(UTC))
        .filter(
            # Check both the property and the column
            or_(
                SubscribedUser._is_active == True, 
                SubscribedUser.is_active == True
            )
        )
        .first()
    )
    
    # If no subscription found, log detailed information
    if not current_subscription:
        app.logger.warning(f"No active subscription found for user {user_id}")
        
        # Additional checks
        expired_subs = (
            SubscribedUser.query
            .filter(SubscribedUser.U_ID == user_id)
            .filter(SubscribedUser.end_date <= datetime.now(UTC))
            .all()
        )
        
        if expired_subs:
            app.logger.warning("Found expired subscriptions:")
            for sub in expired_subs:
                app.logger.warning(f"Subscription ID: {sub.id}, End Date: {sub.end_date}")
        
        flash('You don\'t have an active subscription to change.', 'warning')
        return redirect(url_for('user_subscriptions'))
    
    if not current_subscription:
        flash('You don\'t have an active subscription to change.', 'warning')
        return redirect(url_for('user_subscriptions'))
    
    # Get the new subscription plan
    new_plan = Subscription.query.get_or_404(new_plan_id)
    
    # Determine if this is an upgrade or downgrade
    is_upgrade = new_plan.tier > current_subscription.subscription.tier
    
    # Calculate remaining value of current subscription
    remaining_value = current_subscription.remaining_value()
    
    if request.method == 'POST':
        try:
            # Start a database transaction
            db.session.begin_nested()
            
            # Calculate the amount to charge with GST consideration
            if is_upgrade:
                # Amount to charge after applying remaining value credit
                amount_to_charge = max(0, new_plan.price - remaining_value)
                
                # Create a Payment instance 
                payment = Payment(
                    user_id=user_id,
                    subscription_id=new_plan_id,
                    base_amount=amount_to_charge,
                    payment_type='upgrade',
                    previous_subscription_id=current_subscription.S_ID,
                    credit_applied=remaining_value,
                    razorpay_order_id=None,  # Will be set later
                    status='created',
                    currency='INR'
                )
                
                # If there's an amount to charge, create Razorpay order
                if payment.total_amount > 0:
                    razorpay_order = razorpay_client.order.create({
                        'amount': int(payment.total_amount * 100),
                        'currency': 'INR',
                        'payment_capture': '1'
                    })
                    
                    payment.razorpay_order_id = razorpay_order['id']
                    db.session.add(payment)
                    db.session.commit()
                    
                    return redirect(url_for('checkout', order_id=razorpay_order['id']))
                else:
                    # No additional payment needed
                    _process_subscription_change(
                        user_id, 
                        current_subscription, 
                        new_plan_id, 
                        is_upgrade=True, 
                        credit_applied=remaining_value
                    )
                    
                    flash(f'Your subscription has been upgraded to {new_plan.plan}!', 'success')
                    return redirect(url_for('user_subscriptions'))
            
            else:
                # Downgrade case - process change without payment
                _process_subscription_change(
                    user_id, 
                    current_subscription, 
                    new_plan_id, 
                    is_upgrade=False, 
                    credit_applied=remaining_value
                )
                
                flash(f'Your subscription has been changed to {new_plan.plan}.', 'success')
                return redirect(url_for('user_subscriptions'))
                
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error processing subscription change: {str(e)}")
            flash(f'Error processing subscription change: {str(e)}', 'danger')
            return redirect(url_for('user_subscriptions'))
    
    # GET request - show confirmation page
    return render_template(
        'user/change_subscription.html',
        current_subscription=current_subscription,
        new_plan=new_plan,
        is_upgrade=is_upgrade,
        remaining_value=remaining_value,
        amount_to_charge=max(0, new_plan.price - remaining_value) if is_upgrade else 0,
        gst_rate=0.18  # Standard GST rate
    )

def change_subscription(new_plan_id):
    """
    Handle subscription change with improved logic for upgrades and downgrades
    
    Workflow:
    1. Validate current active subscription
    2. Get new subscription plan
    3. Determine if it's an upgrade or downgrade
    4. Calculate prorated credit/charge
    5. Process subscription change
    """
    user_id = session.get('user_id')

    # Validate current active subscription
    current_subscription = (
        SubscribedUser.query
        .filter(SubscribedUser.U_ID == user_id)
        .filter(SubscribedUser.end_date > datetime.now(UTC))
        .filter(SubscribedUser.is_active == True)
        .first()
    )
    
    if not current_subscription:
        flash('You don\'t have an active subscription to change.', 'warning')
        return redirect(url_for('user_subscriptions'))
    
    # Get the new subscription plan
    new_plan = Subscription.query.get_or_404(new_plan_id)
    
    # Prevent changing to the same plan
    if current_subscription.S_ID == new_plan_id:
        flash('You are already on this plan.', 'info')
        return redirect(url_for('user_subscriptions'))
    
    # Determine upgrade or downgrade
    is_upgrade = new_plan.tier > current_subscription.subscription.tier
    
    # Calculate remaining subscription value
    remaining_days = (current_subscription.end_date - datetime.now(UTC)).days
    daily_rate_current = current_subscription.subscription.price / current_subscription.subscription.days
    remaining_value = daily_rate_current * remaining_days
    
    # Process the subscription change
    if request.method == 'POST':
        try:
            # Upgrade scenario
            if is_upgrade:
                # Calculate additional amount due
                amount_to_charge = max(0, new_plan.price - remaining_value)
                
                # Create payment record
                payment = Payment(
                    user_id=user_id,
                    subscription_id=new_plan_id,
                    base_amount=amount_to_charge,
                    payment_type='upgrade',
                    previous_subscription_id=current_subscription.S_ID,
                    credit_applied=remaining_value,
                    status='created',
                    currency='INR',
                    gst_rate=0.18  # Standard GST rate
                )
                
                # If there's an amount to charge, create Razorpay order
                if payment.total_amount > 0:
                    razorpay_order = razorpay_client.order.create({
                        'amount': int(payment.total_amount * 100),
                        'currency': 'INR',
                        'payment_capture': '1',
                        'notes': {
                            'user_id': user_id,
                            'plan_id': new_plan_id,
                            'action': 'upgrade'
                        }
                    })
                    
                    payment.razorpay_order_id = razorpay_order['id']
                    db.session.add(payment)
                    db.session.commit()
                    
                    return redirect(url_for('checkout', order_id=razorpay_order['id']))
                else:
                    # No additional payment needed
                    _process_subscription_change(
                        user_id, 
                        current_subscription, 
                        new_plan_id, 
                        is_upgrade=True, 
                        credit_applied=remaining_value
                    )
                    
                    flash(f'Your subscription has been upgraded to {new_plan.plan}!', 'success')
                    return redirect(url_for('user_subscriptions'))
            
            # Downgrade scenario
            else:
                # For downgrades, we might want to process immediately or pro-rate
                new_days = int(remaining_value / (new_plan.price / new_plan.days))
                
                _process_subscription_change(
                    user_id, 
                    current_subscription, 
                    new_plan_id, 
                    is_upgrade=False,
                    credit_applied=remaining_value,
                    additional_days=new_days
                )
                
                flash(f'Your subscription has been changed to {new_plan.plan}.', 'success')
                return redirect(url_for('user_subscriptions'))
                
        except Exception as e:
            app.logger.error(f"Error processing subscription change: {str(e)}")
            flash(f'Error processing subscription change: {str(e)}', 'danger')
            return redirect(url_for('user_subscriptions'))
    
    # GET request - show confirmation page
    return render_template(
        'user/change_subscription.html',
        current_subscription=current_subscription,
        new_plan=new_plan,
        is_upgrade=is_upgrade,
        remaining_value=remaining_value,
        amount_to_charge=max(0, new_plan.price - remaining_value) if is_upgrade else 0,
        remaining_days=remaining_days,
        gst_rate=0.18  # Standard GST rate
    )

def _process_subscription_change(user_id, current_subscription, new_plan_id, is_upgrade, credit_applied=0):
    """Process a subscription change (upgrade or downgrade)"""
    try:
        # Get the new subscription plan
        new_plan = Subscription.query.get(new_plan_id)
        
        # Deactivate current subscription
        current_subscription.is_active = False
        
        # Calculate new subscription dates
        start_date = datetime.now(UTC)
        
        if is_upgrade:
            # For upgrades, standard plan duration
            end_date = start_date + timedelta(days=new_plan.days)
        else:
            # For downgrades, calculate additional days from remaining credit
            new_plan_daily_price = new_plan.price / new_plan.days if new_plan.days > 0 else 0
            additional_days = int(credit_applied / new_plan_daily_price) if new_plan_daily_price > 0 else 0
            end_date = start_date + timedelta(days=new_plan.days + additional_days)
        
        # Create NEW active subscription
        new_subscription = SubscribedUser(
            U_ID=user_id,
            S_ID=new_plan_id,
            start_date=start_date,
            end_date=end_date,
            is_auto_renew=current_subscription.is_auto_renew,
            current_usage=0,
            last_usage_reset=start_date
        )
        
        # Add the new subscription
        db.session.add(new_subscription)
        
        # Log subscription change history
        history_entry = SubscriptionHistory(
            U_ID=user_id,
            S_ID=new_plan_id,
            action='upgrade' if is_upgrade else 'downgrade',
            previous_S_ID=current_subscription.S_ID,
            created_at=datetime.now(UTC)
        )
        db.session.add(history_entry)
        
        # Commit changes
        db.session.commit()
        
        return True
    
    except Exception as e:
        # Rollback in case of any errors
        db.session.rollback()
        app.logger.error(f"Subscription change error: {str(e)}")
        return False


# Add auto-renewal toggle route
@app.route('/subscription/auto-renew/<int:subscription_id>/<int:status>')
@login_required
def toggle_auto_renew(subscription_id, status):
    user_id = session.get('user_id')
    
    # Find the specific subscription
    subscription = (
        SubscribedUser.query
        .filter(SubscribedUser.id == subscription_id)
        .filter(SubscribedUser.U_ID == user_id)
        .first_or_404()
    )
    
    # Update auto-renew status
    subscription.is_auto_renew = bool(status)
    db.session.commit()
    
    if subscription.is_auto_renew:
        flash('Auto-renewal has been enabled for your subscription.', 'success')
    else:
        flash('Auto-renewal has been disabled for your subscription.', 'info')
    
    return redirect(url_for('user_subscriptions'))


# Add a route to handle subscription cancellation
@app.route('/subscription/cancel/<int:subscription_id>', methods=['GET', 'POST'])
@login_required
def cancel_subscription(subscription_id):
    user_id = session.get('user_id')
    
    # Find the specific subscription
    subscription = (
        SubscribedUser.query
        .filter(SubscribedUser.id == subscription_id)
        .filter(SubscribedUser.U_ID == user_id)
        .first_or_404()
    )
    
    if request.method == 'POST':
        # Disable auto-renewal and set is_active to False
        subscription.is_auto_renew = False
        subscription.is_active = False
        
        # Add history entry
        history_entry = SubscriptionHistory(
            U_ID=user_id,
            S_ID=subscription.S_ID,
            action='cancel',
            previous_S_ID=subscription.S_ID,
            created_at=datetime.now(UTC)
        )
        db.session.add(history_entry)
        db.session.commit()
        
        flash('Your subscription has been cancelled. You can continue using it until the end date.', 'info')
        return redirect(url_for('user_subscriptions'))
    
    # GET request - show confirmation page
    return render_template(
        'user/cancel_subscription.html',
        subscription=subscription
    )

def has_active_subscription(user_id):
    """
    Strict check to ensure only ONE active subscription exists
    - Must be active
    - End date in the future
    - Exactly one active subscription
    """
    now = datetime.now(UTC)
    active_subs = (
        SubscribedUser.query
        .filter(SubscribedUser.U_ID == user_id)
        .filter(SubscribedUser.end_date > now)
        .filter(SubscribedUser._is_active == True)
        .count()
    )
    
    return active_subs > 0  # Changed to check for at least one active subscription
# Helper function to increment usage with daily reset
def increment_usage(user_id):
    """
    Increment usage count and check limits
    Returns True if increment successful, False if limit reached
    """
    sub = (
        SubscribedUser.query
        .filter(SubscribedUser.U_ID == user_id)
        .filter(SubscribedUser.end_date > datetime.now(UTC))
        .filter(SubscribedUser._is_active == True)
        .first()
    )
    
    if sub:
        # Check if we need to reset the usage counter (new day)
        today = datetime.now(UTC).date()
        last_reset_date = getattr(sub, 'last_usage_reset', None)
        
        if not last_reset_date or last_reset_date.date() < today:
            # Reset counter for new day
            sub.current_usage = 0
            sub.last_usage_reset = datetime.now(UTC)
        
        # Check if already at limit before incrementing
        if sub.current_usage >= sub.subscription.usage_per_day:
            return False
            
        # Increment usage
        sub.current_usage += 1
        try:
            db.session.commit()
            return True
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error incrementing usage: {str(e)}")
            return False
    
    return False  # No active subscription found

def process_auto_renewals():
    """Process auto-renewals for expiring subscriptions"""
    # Get subscriptions expiring in the next 24 hours with auto-renew enabled
    now = datetime.now(UTC)
    expiring_soon = (
        SubscribedUser.query
        .filter(SubscribedUser.is_auto_renew == True)
        .filter(SubscribedUser.is_active == True)  # Only active subscriptions
        .filter(SubscribedUser.end_date <= now + timedelta(days=1))
        .filter(SubscribedUser.end_date > now)
        .options(joinedload(SubscribedUser.subscription))
        .all()
    )
    
    for sub in expiring_soon:
        try:
            # Deactivate current subscription before renewal
            sub.is_active = False
            
            # Get subscription details
            subscription = sub.subscription
            
            # Create Razorpay order for renewal
            # Use the Payment model's new constructor with base_amount
            payment = Payment(
                base_amount=subscription.price,
                user_id=sub.U_ID,
                subscription_id=sub.S_ID,
                razorpay_order_id=None,  # Will be set by Razorpay
                status='created',
                payment_type='renewal'
            )
            
            # Create Razorpay order
            razorpay_order = razorpay_client.order.create({
                'amount': int(payment.total_amount * 100),
                'currency': 'INR',
                'payment_capture': '1'
            })
            
            # Update with Razorpay order ID
            payment.razorpay_order_id = razorpay_order['id']
            db.session.add(payment)
            db.session.commit()
            
            # Send email notification to user about upcoming renewal
            # (implementation depends on your email system)
            
        except Exception as e:
            app.logger.error(f"Auto-renewal failed for user {sub.U_ID}: {str(e)}")
    
    # Handle expired subscriptions
    expired = (
        SubscribedUser.query
        .filter(SubscribedUser.is_active == True)  # Only active subscriptions
        .filter(SubscribedUser.end_date < now)
        .all()
    )
    
    for sub in expired:
        # Set subscription as inactive
        sub.is_active = False
        
        # Add history entry for expired subscription
        history_entry = SubscriptionHistory(
            U_ID=sub.U_ID,
            S_ID=sub.S_ID,
            action='expire',
            previous_S_ID=sub.S_ID,
            created_at=now
        )
        db.session.add(history_entry)
    
    db.session.commit()

def record_usage_log(user_id, subscription_id, operation_type, details=None):
    """
    Record a usage log entry for a subscription
    
    Args:
        user_id (int): ID of the user
        subscription_id (int): ID of the SubscribedUser record (not the subscription plan ID)
        operation_type (str): Type of operation performed (e.g., 'url_analysis', 'keyword_search')
        details (str, optional): Additional details about the operation in JSON format
    
    Returns:
        bool: True if recording succeeded, False otherwise
    """
    try:
        # Create new usage log entry
        usage_log = UsageLog(
            user_id=user_id,
            subscription_id=subscription_id,
            operation_type=operation_type,
            details=details,
            timestamp=datetime.now(UTC)
        )
        
        db.session.add(usage_log)
        db.session.commit()
        return True
        
    except Exception as e:
        app.logger.error(f"Error recording usage log: {str(e)}")
        db.session.rollback()
        return False

def subscription_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # First check if user is logged in
        if not current_user.is_authenticated:
            if 'user_id' not in session:
                flash("Please login to access this feature.", "warning")
                return redirect(url_for('login'))
            user_id = session.get('user_id')
        else:
            user_id = current_user.id
        
        # Check subscription
        now = datetime.now(UTC)
        active_subscription = (
            SubscribedUser.query
            .filter(SubscribedUser.U_ID == user_id)
            .filter(SubscribedUser.end_date > now)
            .filter(SubscribedUser._is_active == True)
            .first()
        )
        
        if not active_subscription:
            flash("Please subscribe to access this feature.", "warning")
            return redirect(url_for('user_subscriptions'))
        
        # Increment usage and check limits
        usage_result = increment_usage(user_id)
        
        if not usage_result:
            flash("You have reached your daily usage limit. Please try again tomorrow.", "warning")
            return redirect(url_for('subscription_details', subscription_id=active_subscription.id))
        
        # Record usage log
        operation_type = f.__name__
        record_usage_log(
            user_id=user_id,
            subscription_id=active_subscription.id,
            operation_type=operation_type,
            details=f"Accessed {operation_type}"
        )
        
        return f(*args, **kwargs)
    
    return decorated_function
# ---------------------------------------
# user login signup and reset password
# ---------------------------------------
from datetime import datetime

@app.route('/')
def landing():
    """Landing page route that doesn't require login"""
    current_year = datetime.now().year
    return render_template('landing.html', current_year=current_year)

@app.route('/dashboard', methods=['GET'])
@login_required
def index():
    # Get the user_id from session if user is logged in
    user_id = session.get('user_id')
    view_mode = "dashboard"  # Default to dashboard view
    # Initialize data
    recent_analyses = []
    today_usage_count = 0
    total_usage_count = 0
    top_operation_type = "N/A"
    weekly_trend = 0
    today_vs_yesterday = 0
    user_name = "User"
    tool_distribution = []
    milestone_progress = 0
    
    # Only fetch data if a user is logged in
    if user_id:
        # Get the user's name from the database
        user = User.query.get(user_id)
        if user:
            user_name = user.name
        
        # Get time ranges
        today = date.today()
        yesterday = today - timedelta(days=1)
        week_ago = today - timedelta(days=7)
        two_weeks_ago = today - timedelta(days=14)
        now = datetime.now(UTC)
        
        # Get the user's active subscription
        active_subscription = SubscribedUser.query.filter(
            SubscribedUser.U_ID == user_id,
            SubscribedUser.end_date > now
        ).first()
        
        # Only proceed with detailed analytics if user has an active subscription
        if active_subscription:
            # Query recent analyses from usage logs
            recent_logs = UsageLog.query.filter_by(user_id=user_id)\
                .order_by(UsageLog.timestamp.desc())\
                .limit(5)\
                .all()
                
            # Convert UsageLog entries to a format similar to SearchHistory for template
            recent_analyses = []
            for log in recent_logs:
                # Create a SearchHistory-like object with the necessary fields
                analysis = type('', (), {})()
                analysis.search_history = log.details if log.details else log.operation_type
                analysis.usage_tool = log.operation_type
                analysis.created_at = log.timestamp
                recent_analyses.append(analysis)
            
            # Today's usage count
            today_usage_count = db.session.query(func.count(UsageLog.id))\
                .filter(
                    UsageLog.user_id == user_id,
                    func.date(UsageLog.timestamp) == today
                ).scalar() or 0
            
            # Yesterday's usage count for comparison
            yesterday_usage_count = db.session.query(func.count(UsageLog.id))\
                .filter(
                    UsageLog.user_id == user_id,
                    func.date(UsageLog.timestamp) == yesterday
                ).scalar() or 0
            
            # Calculate percentage change vs yesterday
            if yesterday_usage_count > 0:
                today_vs_yesterday = ((today_usage_count - yesterday_usage_count) / yesterday_usage_count) * 100
            else:
                today_vs_yesterday = 100 if today_usage_count > 0 else 0
            
            # Total usage count
            total_usage_count = db.session.query(func.count(UsageLog.id))\
                .filter(UsageLog.user_id == user_id)\
                .scalar() or 0
            
            # Calculate milestone progress (e.g., next milestone at 100, 500, 1000, etc.)
            milestone_thresholds = [100, 500, 1000, 5000, 10000]
            next_milestone = next((m for m in milestone_thresholds if m > total_usage_count), milestone_thresholds[-1] * 2)
            previous_milestone = next((m for m in reversed(milestone_thresholds) if m < total_usage_count), 0)
            milestone_progress = int(((total_usage_count - previous_milestone) / (next_milestone - previous_milestone)) * 100)
            
            # Get the user's top operation type
            top_operation_query = db.session.query(
                UsageLog.operation_type, 
                func.count(UsageLog.id).label('total')
            )\
            .filter(UsageLog.user_id == user_id)\
            .group_by(UsageLog.operation_type)\
            .order_by(func.count(UsageLog.id).desc())\
            .first()
            
            if top_operation_query:
                top_operation_type = top_operation_query[0]
            
            # Get tool distribution for visualization
            tool_usage = db.session.query(
                UsageLog.operation_type,
                func.count(UsageLog.id).label('count')
            )\
            .filter(UsageLog.user_id == user_id)\
            .group_by(UsageLog.operation_type)\
            .order_by(func.count(UsageLog.id).desc())\
            .all()
            
            # Calculate percentages for tool distribution
            total_tool_usage = sum(usage[1] for usage in tool_usage)
            
            if total_tool_usage > 0:
                # Define CSS classes for different tools (add more as needed)
                css_classes = ['primary', 'secondary', 'tertiary', 'quaternary']
                
                tool_distribution = []
                for i, (tool, count) in enumerate(tool_usage):
                    percentage = (count / total_tool_usage) * 100
                    tool_distribution.append({
                        'name': tool,
                        'percentage': round(percentage, 1),
                        'class': css_classes[i % len(css_classes)]
                    })
            
            # Calculate weekly trend (this week vs. last week)
            this_week_count = db.session.query(func.count(UsageLog.id))\
                .filter(
                    UsageLog.user_id == user_id,
                    UsageLog.timestamp >= week_ago
                ).scalar() or 0
                
            last_week_count = db.session.query(func.count(UsageLog.id))\
                .filter(
                    UsageLog.user_id == user_id,
                    UsageLog.timestamp >= two_weeks_ago,
                    UsageLog.timestamp < week_ago
                ).scalar() or 0
            
            # Calculate percentage change (avoid division by zero)
            if last_week_count > 0:
                weekly_trend = ((this_week_count - last_week_count) / last_week_count) * 100
            else:
                weekly_trend = 100 if this_week_count > 0 else 0
    
    # Now you can pass all data to your template
    return render_template('index.html', 
                      user_name=user_name,
                      recent_analyses=recent_analyses,
                      websites_analyzed_today=today_usage_count,  # Changed from today_usage_count
                      total_analyses=total_usage_count,           # Changed from total_usage_count
                      favorite_tool=top_operation_type,           # Changed from top_operation_type
                      weekly_trend=weekly_trend,
                      today_vs_yesterday=today_vs_yesterday,
                      tool_distribution=tool_distribution,
                      milestone_progress=milestone_progress,
                      now=now,
                      links_data=None,
                      view_mode=view_mode,)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        company_email = request.form.get('companyEmail').lower().strip()
        password = request.form.get('password')
        
        # Validate user using SQLAlchemy
        user = User.query.filter(
            func.lower(User.company_email) == company_email
        ).first()
        if not user:
            flash("Invalid email or password.", "danger")
            return redirect(url_for('login'))
        
        if not user.email_confirmed:
            flash("Please verify your email before logging in. Check your inbox or request a new verification link.", "warning")
            return redirect(url_for('resend_verification'))
        
        if user.check_password(password):
            login_user(user)  # Using Flask-Login
            session['user_id'] = user.id
            session['user_name'] = user.name
            flash("Login successful!", "success")
            return redirect(url_for('index'))
        else:
            flash("Invalid email or password.", "danger")
            return redirect(url_for('login'))
            
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form.get('name')
        company_email = request.form.get('companyEmail').lower().strip()
        password = request.form.get('password')
        retype_password = request.form.get('retypePassword')
        
        # Enhanced input validation
        errors = []
        
        # Name validation
        if not name or len(name.strip()) < 2:
            errors.append("Name should be at least 2 characters long.")
        
        # Email validation
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not company_email or not re.match(email_pattern, company_email):
            errors.append("Please enter a valid email address.")
        
        # Password validation
        if not password:
            errors.append("Password is required.")
        elif len(password) < 8:
            errors.append("Password must be at least 8 characters long.")
        elif not re.search(r'[A-Z]', password):
            errors.append("Password must contain at least one uppercase letter.")
        elif not re.search(r'[a-z]', password):
            errors.append("Password must contain at least one lowercase letter.")
        elif not re.search(r'[0-9]', password):
            errors.append("Password must contain at least one number.")
        elif not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            errors.append("Password must contain at least one special character.")
        
        # Password confirmation validation
        if password != retype_password:
            errors.append("Passwords do not match.")
        
        # Check if email already exists
        existing_user = User.query.filter(
            func.lower(User.company_email) == company_email
        ).first()
        
        if existing_user:
            errors.append("This email is already registered.")
        # If there are any errors, flash them and redirect back to signup
        if errors:
            for error in errors:
                flash(error, "danger")
            return render_template('signup.html', name=name, company_email=company_email)
        
        # Create new user with email verification required
        new_user = User(name=name, company_email=company_email, email_confirmed=False)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        
        # Send verification email
        try:
            send_verification_email(new_user)
            flash("Signup successful! Please check your email to verify your account.", "success")
        except Exception as e:
            logging.error(f"Error sending verification email: {str(e)}")
            flash("Signup successful but there was an issue sending the verification email. Please contact support.", "warning")
        
        return redirect(url_for('verify_account'))
    
    return render_template('signup.html')

@app.route("/verify_account")
def verify_account():
    email = request.args.get('email')
    return render_template('verify_account.html', email=email)

@app.route('/verify_email/<token>')
def verify_email(token):
    user = User.verify_email_token(token)
    if user is None:
        flash('Invalid or expired verification link. Please request a new one.', 'danger')
        return redirect(url_for('resend_verification'))
    
    user.email_confirmed = True
    user.email_confirm_token = None
    user.email_token_created_at = None
    db.session.commit()
    
    flash('Your email has been verified! You can now log in.', 'success')
    return redirect(url_for('login'))

@app.route('/resend_verification', methods=['GET', 'POST'])
def resend_verification():
    if request.method == 'POST':
        email = request.form.get('companyEmail').lower().strip()
        user = User.query.filter(
            func.lower(User.company_email) == email
        ).first()
        if user and not user.email_confirmed:
            try:
                send_verification_email(user)
                flash('A new verification email has been sent.', 'success')
            except Exception as e:
                logging.error(f"Error resending verification email: {str(e)}")
                flash('There was an issue sending the verification email. Please try again later.', 'danger')
        elif user and user.email_confirmed:
            flash('This email is already verified. You can log in.', 'info')
        else:
            flash('Email not found. Please sign up first.', 'warning')
            
        return redirect(url_for('login'))
    
    return render_template('resend_verification.html')

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_request():
    if request.method == 'POST':
        email = request.form.get('companyEmail').lower().strip()
        user = User.query.filter(
            func.lower(User.company_email) == email
        ).first()
        if user:
            send_reset_email(user)
            flash('An email has been sent with instructions to reset your password.', 'info')
            return redirect(url_for('login'))
        else:
            flash('Email not found. Please register first.', 'warning')
    return render_template('reset_request.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_token(token):
    try:
        # Try to verify the token
        user = User.verify_reset_token(token)
        if not user:
            flash('Invalid or expired token. Please request a new password reset link.', 'danger')
            return redirect(url_for('reset_request'))

        if request.method == 'POST':
            # Handle password reset logic here
            password = request.form.get('password')
            confirm_password = request.form.get('confirm_password')
            
            # Validate passwords
            if not password or not confirm_password:
                flash('Both password fields are required', 'danger')
                return render_template('reset_token.html', token=token)
            
            if password != confirm_password:
                flash('Passwords do not match', 'danger')
                return render_template('reset_token.html', token=token)
            
            if len(password) < 8:
                flash('Password must be at least 8 characters long', 'danger')
                return render_template('reset_token.html', token=token)

            # Update password
            user.set_password(password)
            user.password_reset_at = datetime.now(UTC)
            db.session.commit()

            flash('Your password has been updated! You can now log in with your new password.', 'success')
            return redirect(url_for('login'))

    except Exception as e:
        # Log any errors
        logging.error(f"Error during password reset: {str(e)}")
        flash('An error occurred during the password reset process. Please try again.', 'danger')
        return redirect(url_for('reset_request'))

    # If method is GET, render the reset password page
    return render_template('reset_token.html', token=token)

@app.route('/logout')
def logout():
    logout_user()  # Flask-Login function
    session.clear()
    flash("Logged out successfully.", "success")
    return redirect(url_for('login'))
# ---------------------------------------
# Profile Management Routes
# ---------------------------------------
@app.route('/search_history', methods=['GET'])
@login_required
def search_history():
    # Import needed at the top of your file
    import pytz
    from datetime import datetime, timedelta

    user_id = session.get('user_id')

    # Fetch the user's name
    user = db.session.get(User, user_id)
    user_name = user.name if user else "Guest"

    # Get filter parameters from the request
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')

    # Base query to fetch search history for the logged-in user
    query = SearchHistory.query.filter_by(u_id=user_id)

    # Apply date filters if provided
    if start_date:
        try:
            start_date_obj = datetime.strptime(start_date, '%Y-%m-%d')
            query = query.filter(SearchHistory.created_at >= start_date_obj)
        except ValueError:
            flash("Invalid start date format. Please use YYYY-MM-DD.", "danger")

    if end_date:
        try:
            end_date_obj = datetime.strptime(end_date, '%Y-%m-%d')
            # Add one day to include the entire end date
            end_date_obj += timedelta(days=1)
            query = query.filter(SearchHistory.created_at < end_date_obj)
        except ValueError:
            flash("Invalid end date format. Please use YYYY-MM-DD.", "danger")

    # Fetch the filtered search histories
    history = query.order_by(SearchHistory.created_at.desc()).all()

    # Get the most used tool dynamically for each entry
    user_most_used_tools = {}
    for entry in history:
        if entry.u_id not in user_most_used_tools:
            # Fetch the most-used tool for the user
            tool_usage = db.session.query(SearchHistory.usage_tool, db.func.sum(SearchHistory.search_count))\
                .filter(SearchHistory.u_id == entry.u_id)\
                .group_by(SearchHistory.usage_tool).all()
            if tool_usage:
                most_used_tool = max(tool_usage, key=lambda x: x[1])[0]  # Get the tool with the highest count
                user_most_used_tools[entry.u_id] = most_used_tool
            else:
                user_most_used_tools[entry.u_id] = "No tools used yet"
        
        # Format the created_at timestamp in UTC format
        if entry.created_at:
            if entry.created_at.tzinfo is None:
                # If naive datetime, assume it's UTC and add tzinfo
                entry.formatted_date = pytz.UTC.localize(entry.created_at).strftime('%d-%m-%Y %I:%M:%S %p UTC')
            else:
                # If already has timezone, convert to UTC
                entry.formatted_date = entry.created_at.astimezone(pytz.UTC).strftime('%d-%m-%Y %I:%M:%S %p UTC')
        else:
            entry.formatted_date = 'N/A'

    return render_template(
        'search_history.html',
        history=history,
        user_name=user_name,
        user_most_used_tools=user_most_used_tools,
        start_date=start_date,
        end_date=end_date
    )

# ---------------------------------------
# Profile Management Routes
# ---------------------------------------

@app.route('/profile')
@login_required
def profile():
    user_id = session.get('user_id')
    user = User.query.get(user_id)
    
    # Get user's active subscription if any
    subscription = (
        db.session.query(SubscribedUser)
        .filter(SubscribedUser.U_ID == user_id)
        .filter(SubscribedUser.end_date > datetime.now(UTC))
        .join(Subscription, SubscribedUser.S_ID == Subscription.S_ID)
        .first()
    )
    
    # Get recent payments
    payments = (
        Payment.query
        .filter_by(user_id=user_id)
        .order_by(Payment.created_at.desc())
        .limit(10)
        .all()
    )
    
    return render_template('profile.html', user=user, subscription=subscription, payments=payments)

@app.route('/update_profile', methods=['POST'])
@login_required
def update_profile():
    user_id = session.get('user_id')
    user = User.query.get(user_id)
    
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('profile'))
    
    update_type = request.form.get('update_type', 'account')
    
    if update_type == 'account':
        # Update name
        name = request.form.get('name')
        if name and name.strip():
            user.name = name.strip()
            session['user_name'] = name.strip()  # Update session data too
            
        db.session.commit()
        flash('Profile information updated successfully', 'success')
        return redirect(url_for('profile') + '#account')
        
    elif update_type == 'security':
        # Process password change
        current_password = request.form.get('currentPassword')
        new_password = request.form.get('newPassword')
        confirm_password = request.form.get('confirmPassword')
        
        # Validate input fields
        if not all([current_password, new_password, confirm_password]):
            flash('All password fields are required', 'danger')
            return redirect(url_for('profile') + '#security')
        
        # Verify current password
        if not user.check_password(current_password):
            flash('Current password is incorrect', 'danger')
            return redirect(url_for('profile') + '#security')
        
        # Validate new password
        if new_password != confirm_password:
            flash('New passwords do not match', 'danger')
            return redirect(url_for('profile') + '#security')
        
        # Password complexity validation
        password_errors = []
        if len(new_password) < 8:
            password_errors.append('Password must be at least 8 characters long')
        if not re.search(r'[A-Z]', new_password):
            password_errors.append('Password must contain at least one uppercase letter')
        if not re.search(r'[a-z]', new_password):
            password_errors.append('Password must contain at least one lowercase letter')
        if not re.search(r'[0-9]', new_password):
            password_errors.append('Password must contain at least one number')
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', new_password):
            password_errors.append('Password must contain at least one special character')
        
        if password_errors:
            for error in password_errors:
                flash(error, 'danger')
            return redirect(url_for('profile') + '#security')
        
        # Check if new password is different from current
        if user.check_password(new_password):
            flash('New password must be different from current password', 'warning')
            return redirect(url_for('profile') + '#security')
        
        # Update password
        user.set_password(new_password)
        db.session.commit()
        
        # Log the password change (optional)
        logging.info(f"Password changed for user ID {user_id}")
        
        flash('Password updated successfully. Please use your new password next time you log in.', 'success')
        return redirect(url_for('profile') + '#security')
    
    # If we get here, something went wrong
    flash('Invalid update request', 'danger')
    return redirect(url_for('profile'))

# Generate a downloadable payment receipt
@app.route('/receipt/<payment_id>')
@login_required
def download_receipt(payment_id):
    user_id = session.get('user_id')
    
    # Get payment details
    payment = Payment.query.filter_by(id=payment_id, user_id=user_id).first_or_404()
    
    # TODO: Generate and return PDF receipt
    # This would typically use a PDF generation library like ReportLab or WeasyPrint
    
    flash('Receipt download feature coming soon!', 'info')
    return redirect(url_for('profile') + '#activity')

# --------------------------------
# app primary functions routes
# -------------------------------- 

@app.route('/url_analysis', methods=['GET', 'POST'])
@login_required
@subscription_required
def url_analysis():
    url_input = ""
    links_data = None
    robots_info = None
    
    if request.method == 'POST':
        url_input = request.form.get('url')
        if url_input:
            # Normalize URL format (add https:// if missing)
            if not url_input.startswith(('http://', 'https://')):
                url_input = 'https://' + url_input
            
            # Clear any previous robots info before performing a new analysis
            if 'robots_info' in session:
                session.pop('robots_info', None)
                
            # The analyze_links function from link_analyzer.py handles robots.txt checking
            home_links, other_links, robots_info = analyze_links(url_input)
            
            # Store the search history in the database - ensure user_id is available
            user_id = session.get('user_id')
            if user_id:
                # Use record_usage_log instead of just adding search history
                active_sub = SubscribedUser.query.filter(
                    SubscribedUser.U_ID == user_id,
                    SubscribedUser.end_date > datetime.now(UTC)
                ).first()
                
                if active_sub:
                    # Record in UsageLog for more detailed analytics
                    record_usage_log(
                        user_id=user_id,
                        subscription_id=active_sub.id,
                        operation_type="URL Analysis",
                        details=url_input
                    )
                
                # Also record in search history for backward compatibility
                usage_tool = "URL Analysis"
                add_search_history(user_id, usage_tool, url_input)
            
            # Store links and URL in session to persist across requests
            session['home_links'] = home_links
            session['other_links'] = other_links
            session['last_analyzed_url'] = url_input
            
            # Only store robots info if it actually exists
            if robots_info:
                session['robots_info'] = robots_info
            elif 'robots_info' in session:
                session.pop('robots_info', None)
            
            # Commit the session to ensure it's saved
            session.modified = True
            
            # Redirect to prevent form resubmission
            return redirect(url_for('url_analysis', url=url_input))
    
    # For GET requests with URL parameter
    if request.method == 'GET' and request.args.get('url'):
        url_input = request.args.get('url')
        
        # If it's an AJAX request looking for JSON data
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            home_links = session.get('home_links', [])
            other_links = session.get('other_links', [])
            robots_info = session.get('robots_info', {})
            return jsonify({
                'home': home_links,
                'other': other_links,
                'robots': robots_info
            })
    # For fresh page loads without URL parameter and no previous analysis
    elif request.method == 'GET' and not request.args.get('url') and not session.get('last_analyzed_url'):
        # Clear robots info to prevent old data showing up
        if 'robots_info' in session:
            session.pop('robots_info', None)
            session.modified = True
    
    # Retrieve stored links or set to empty lists
    url_input = request.args.get('url', session.get('last_analyzed_url', ""))
    
    # Only include robots info if we're actively viewing an analysis result
    robots_info = None
    if url_input and 'robots_info' in session:
        robots_info = session.get('robots_info')
    
    links_data = {
        'home': session.get('home_links', []),
        'other': session.get('other_links', []),
        'robots': robots_info
    } if url_input else None
    
    # Get current user data for the dashboard
    user_id = session.get('user_id')
    recent_analyses = []
    websites_analyzed_today = 0
    total_analyses = 0
    favorite_tool = "N/A"
    weekly_trend = 0
    today_vs_yesterday = 0  # Initialize the missing variable
    milestone_progress = 75  # Default milestone progress
    tool_distribution = []   # Initialize tool distribution
    
    if user_id:
        try:
            # Fetch recent analyses for this user
            recent_analyses = SearchHistory.query.filter_by(u_id=user_id)\
                .order_by(SearchHistory.created_at.desc())\
                .limit(5)\
                .all()
            
            # Other stats calculations as in the index route
            today = date.today()
            yesterday = today - timedelta(days=1)  # Add yesterday for comparison
            week_ago = today - timedelta(days=7)
            two_weeks_ago = today - timedelta(days=14)
            
            # Today's usage count
            websites_analyzed_today = db.session.query(func.sum(SearchHistory.search_count))\
                .filter(
                    SearchHistory.u_id == user_id,
                    func.date(SearchHistory.created_at) == today
                ).scalar() or 0
            
            # Yesterday's usage count for comparison
            yesterday_count = db.session.query(func.sum(SearchHistory.search_count))\
                .filter(
                    SearchHistory.u_id == user_id,
                    func.date(SearchHistory.created_at) == yesterday
                ).scalar() or 0
                
            # Calculate percentage change vs yesterday
            if yesterday_count > 0:
                today_vs_yesterday = ((websites_analyzed_today - yesterday_count) / yesterday_count) * 100
            else:
                today_vs_yesterday = 100 if websites_analyzed_today > 0 else 0
            
            # Total analyses
            total_analyses = db.session.query(func.sum(SearchHistory.search_count))\
                .filter(SearchHistory.u_id == user_id)\
                .scalar() or 0
            
            # Get the user's favorite/most used tool
            favorite_tool_query = db.session.query(
                    SearchHistory.usage_tool,
                    func.sum(SearchHistory.search_count).label('total')
                )\
                .filter(SearchHistory.u_id == user_id)\
                .group_by(SearchHistory.usage_tool)\
                .order_by(func.sum(SearchHistory.search_count).desc())\
                .first()
                
            if favorite_tool_query:
                favorite_tool = favorite_tool_query[0]
            
            # Generate tool distribution data for the visualization
            tool_usage = db.session.query(
                SearchHistory.usage_tool,
                func.sum(SearchHistory.search_count).label('count')
            )\
            .filter(SearchHistory.u_id == user_id)\
            .group_by(SearchHistory.usage_tool)\
            .order_by(func.sum(SearchHistory.search_count).desc())\
            .limit(4)\
            .all()
            
            # Calculate percentages for tool distribution
            total_tool_usage = sum(usage[1] for usage in tool_usage)
            
            if total_tool_usage > 0:
                # Define CSS classes for different tools
                css_classes = ['primary', 'secondary', 'tertiary', 'quaternary']
                
                tool_distribution = []
                for i, (tool, count) in enumerate(tool_usage):
                    percentage = (count / total_tool_usage) * 100
                    tool_distribution.append({
                        'name': tool,
                        'percentage': round(percentage, 1),
                        'class': css_classes[i % len(css_classes)]
                    })
            
            # Calculate weekly trend (this week vs. last week)
            this_week_count = db.session.query(func.sum(SearchHistory.search_count))\
                .filter(
                    SearchHistory.u_id == user_id,
                    SearchHistory.created_at >= week_ago
                ).scalar() or 0
                
            last_week_count = db.session.query(func.sum(SearchHistory.search_count))\
                .filter(
                    SearchHistory.u_id == user_id,
                    SearchHistory.created_at >= two_weeks_ago,
                    SearchHistory.created_at < week_ago
                ).scalar() or 0
            
            # Calculate percentage change (avoid division by zero)
            if last_week_count > 0:
                weekly_trend = ((this_week_count - last_week_count) / last_week_count) * 100
            else:
                weekly_trend = 100 if this_week_count > 0 else 0
                
            # Calculate milestone progress
            milestone_thresholds = [100, 500, 1000, 5000, 10000]
            next_milestone = next((m for m in milestone_thresholds if m > total_analyses), milestone_thresholds[-1] * 2)
            previous_milestone = next((m for m in reversed(milestone_thresholds) if m < total_analyses), 0)
            milestone_progress = int(((total_analyses - previous_milestone) / (next_milestone - previous_milestone)) * 100)
            
        except Exception as e:
            # Log the error but don't break the page
            app.logger.error(f"Error calculating dashboard stats: {str(e)}")
            app.logger.error(traceback.format_exc())
    
    # Pass all variables to the template
    return render_template('index.html', 
                          url_input=url_input, 
                          links_data=links_data,
                          recent_analyses=recent_analyses,
                          websites_analyzed_today=websites_analyzed_today,
                          total_analyses=total_analyses,
                          favorite_tool=favorite_tool,
                          weekly_trend=weekly_trend,
                          today_vs_yesterday=today_vs_yesterday,
                          tool_distribution=tool_distribution,
                          milestone_progress=milestone_progress,
                          view_mode="analysis")

@app.template_filter('urlparse')
def urlparse_filter(url):
    return urlparse(url)
# Add this to your app.py to replace the existing url_search route

# Regular route that handles both GET initial page load and non-AJAX POST
@app.route('/url_search', methods=['GET', 'POST'])
@login_required
@subscription_required
def url_search():
    links_data = None
    url_input = request.args.get('url', '')
    robots_info = None
    
    # Only process POST if it's not an AJAX request (for backward compatibility)
    if request.method == 'POST' and not request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        url_input = request.form.get('url')
        respect_robots = request.form.get('respect_robots') == 'on'
        
        if url_input:
            # Analyze links with robots.txt checking
            home_links, other_links, robots_info = analyze_links(
                url_input,
                respect_robots=respect_robots
            )
            
            # Extract domains for external links
            other_links_with_domains = []
            for link in other_links:
                try:
                    # Extract domain from link
                    parsed = urlparse(link)
                    domain = parsed.netloc
                    other_links_with_domains.append({
                        'url': link,
                        'domain': domain
                    })
                except:
                    other_links_with_domains.append({
                        'url': link,
                        'domain': 'unknown'
                    })
                    
            links_data = {
                'home': home_links, 
                'other': other_links,
                'other_with_domains': other_links_with_domains
            }
            
            # Capture the search history
            u_id = session.get('user_id')
            usage_tool = "URL Search"
            add_search_history(u_id, usage_tool, url_input)
            
            # Store serializable data in session (remove parser_id as it's not needed in template)
            if robots_info and 'parser_id' in robots_info:
                session_robots_info = robots_info.copy()
                session_robots_info.pop('parser_id', None)
                session['url_robots_info'] = session_robots_info
    
    # Only get robots_info from session if we're in a POST request
    # or if specific url parameter is provided in GET request
    if request.method == 'POST' and not robots_info:
        robots_info = session.get('url_robots_info')
    elif request.method == 'GET' and url_input:
        # Only get from session if we have a URL param (active search)
        robots_info = session.get('url_robots_info')
    else:
        # Clear robots info when just viewing the page with no parameters
        if 'url_robots_info' in session:
            session.pop('url_robots_info', None)
            session.modified = True
        robots_info = None
    
    return render_template(
        'url_search.html', 
        url_input=url_input, 
        links_data=links_data,
        robots_info=robots_info
    )

# New AJAX endpoint for processing URL search
@app.route('/url_search_ajax', methods=['POST'])
@login_required
@subscription_required
def url_search_ajax():
    links_data = None
    url_input = request.form.get('url', '')
    respect_robots = request.form.get('respect_robots') == 'on'
    robots_info = None
    
    if url_input:
        try:
            # Clear any previous robots info before doing a new search
            if 'url_robots_info' in session:
                session.pop('url_robots_info', None)
                session.modified = True
                
            # Analyze links with robots.txt checking
            home_links, other_links, robots_info = analyze_links(
                url_input,
                respect_robots=respect_robots
            )
            
            # Extract domains for external links
            other_links_with_domains = []
            for link in other_links:
                try:
                    # Extract domain from link
                    parsed = urlparse(link)
                    domain = parsed.netloc
                    other_links_with_domains.append({
                        'url': link,
                        'domain': domain
                    })
                except:
                    other_links_with_domains.append({
                        'url': link,
                        'domain': 'unknown'
                    })
                    
            links_data = {
                'home': home_links, 
                'other': other_links,
                'other_with_domains': other_links_with_domains
            }
            
            # Store serializable data in session (remove parser_id as it's not needed in template)
            if robots_info and 'parser_id' in robots_info:
                session_robots_info = robots_info.copy()
                session_robots_info.pop('parser_id', None)
                session['url_robots_info'] = session_robots_info
                session.modified = True
            
            # Note: We don't record search history here - we'll do that with a separate endpoint
            
        except Exception as e:
            # Handle errors
            app.logger.error(f"Error analyzing URL: {str(e)}")
            return jsonify({"error": f"Error analyzing URL: {str(e)}"}), 500
    
    # Only return the results part of the template
    return render_template(
        'url_search_results.html',
        url_input=url_input,
        links_data=links_data,
        robots_info=robots_info
    )

# AJAX endpoint for recording search history
@app.route('/record_search', methods=['POST'])
@login_required
@subscription_required
def record_search():
    data = request.get_json()
    if not data or 'url' not in data or 'tool' not in data:
        return jsonify({"success": False, "message": "Missing required parameters"}), 400
    
    try:
        u_id = session.get('user_id')
        add_search_history(u_id, data['tool'], data['url'])
        return jsonify({"success": True})
    except Exception as e:
        app.logger.error(f"Error recording search: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/download_url')
@login_required
def download_url():
    url_input = request.args.get('url')
    respect_robots = request.args.get('respect_robots', 'true') == 'true'
    
    if not url_input:
        flash("No URL provided for download.")
        return redirect(url_for('url_search'))

    # Get links with robots.txt checking
    home_links, other_links, robots_info = analyze_links(
        url_input, 
        respect_robots=respect_robots
    )

    # Prepare a list of dictionaries for CSV export
    data = []
    
    # Add home links
    for link in home_links:
        data.append({
            "Link": link,
            "Type": "Home",
            "Allowed": "Yes"
        })
    
    # Add external links
    for link in other_links:
        data.append({
            "Link": link,
            "Type": "External",
            "Allowed": "Yes"
        })
    
    # If robots.txt was analyzed, include disallowed links
    if robots_info and robots_info.get('parser_id'):
        # Get the parser from the global dictionary
        parser_id = robots_info.get('parser_id')
        parser = None
        
        if hasattr(analyze_robots_txt, 'parsers'):
            parser = analyze_robots_txt.parsers.get(parser_id)
        
        if parser:
            # Check if there are any disallowed links we filtered out
            base_domain = urlparse(url_input).netloc
            if base_domain.startswith("www."):
                base_domain = base_domain[4:]
                
            disallow_rules = robots_info.get('disallow_rules', [])
            
            # Add a section for disallowed links if we have rules
            if disallow_rules:
                data.append({
                    "Link": "--- DISALLOWED LINKS (NOT CRAWLED) ---",
                    "Type": "",
                    "Allowed": ""
                })
                
                # Add details about robots.txt
                data.append({
                    "Link": f"robots.txt for {base_domain}",
                    "Type": "Info",
                    "Allowed": "N/A"
                })
                
                for rule in disallow_rules:
                    data.append({
                        "Link": f"{urlparse(url_input).scheme}://{base_domain}{rule}",
                        "Type": "Disallowed",
                        "Allowed": "No"
                    })

    # Save CSV file in the download directory
    file_path = os.path.join(download_dir, 'links.csv')
    with open(file_path, 'w', newline='', encoding='utf-8') as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=["Link", "Type", "Allowed"])
        writer.writeheader()
        writer.writerows(data)

    # Add robots.txt information to the filename
    filename = 'links_with_robots.csv' if respect_robots else 'links.csv'

    return send_file(file_path, mimetype='text/csv', as_attachment=True, download_name=filename)

@app.route('/keyword_search', methods=['GET', 'POST'])
@login_required
def keyword_search():
    url_input = ""
    links_data = None
    robots_info = None
    
    if request.method == 'POST':
        url_input = request.form.get('url')
        respect_robots = request.form.get('respect_robots') == 'on'
        
        if url_input:
            # Use the enhanced analyze_links function with robots.txt support
            home_links, other_links, robots_info = analyze_links(
                url_input,
                respect_robots=respect_robots
            )
            
            # Store the search history
            u_id = session.get('user_id')
            usage_tool = "Keyword Search"
            add_search_history(u_id, usage_tool, url_input)
            
            # Store both in session to persist across requests (remove parser_id as it's not needed in template)
            session['home_links'] = home_links
            session['other_links'] = other_links
            
            if robots_info and 'parser_id' in robots_info:
                session_robots_info = robots_info.copy()
                session_robots_info.pop('parser_id', None)
                session['keyword_robots_info'] = session_robots_info

            # Redirect to prevent form resubmission
            return redirect(url_for('keyword_search', url=url_input))

    # Retrieve stored links or set to empty lists
    url_input = request.args.get('url', "")
    if url_input:
        links_data = {
            'home': session.get('home_links', []),
            'other': session.get('other_links', [])
        }
        robots_info = session.get('keyword_robots_info')

    return render_template(
        'keyword_search.html', 
        url_input=url_input, 
        links_data=links_data,
        robots_info=robots_info
    )

@app.route('/keyword_detail', methods=['GET', 'POST'])
@login_required
@subscription_required
def keyword_detail():
    link = request.args.get('link')
    if not link:
        flash("No link provided for keyword analysis.")
        return redirect(url_for('keyword_search'))
    home_links = session.get('home_links', [])
    extracted_text = extract_text(link)
    keyword_results = None
    corrected_results = None
    keywords_input = ""
    colors = ["blue", "green", "brown", "purple", "orange", "teal", "maroon", "navy", "olive", "magenta"]
    if request.method == 'POST':
        keywords_input = request.form.get('keywords', '')
        keywords_list = [k.strip() for k in keywords_input.split(',') if k.strip()]
        if len(keywords_list) > 10:
            keywords_list = keywords_list[:10]
        keyword_results = process_keywords(extracted_text, keywords_list)
        corrected_results = correct_text(extracted_text)
    keywords_colors = {}
    if keyword_results:
        for i, (kw, data) in enumerate(keyword_results["keywords"].items()):
            keywords_colors[kw] = colors[i] if i < len(colors) else 'black'
    return render_template('keyword_detail.html',
                           link=link,
                           extracted_text=extracted_text,
                           keyword_results=keyword_results,
                           corrected_results=corrected_results,
                           keywords_input=keywords_input,
                           colors=colors,
                           home_links=home_links,
                           keywords_colors=keywords_colors,
                           current_time=datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")  # Add this line
            )

@app.route('/download_keyword_txt')
@login_required

def download_keyword_txt():
    link = request.args.get('link')
    keywords_input = request.args.get('keywords_input', '')
    
    if not link:
        flash("No link provided for download.")
        return redirect(url_for('keyword_search'))
    
    extracted_text = extract_text(link)
    cleaned_text = " ".join(extracted_text.split())
    
    output_text = cleaned_text
    analysis_text = "No keywords provided for analysis."
    
    if keywords_input:
        keywords_list = [k.strip() for k in keywords_input.split(',') if k.strip()]
        if keywords_list:
            keyword_results = process_keywords(extracted_text, keywords_list)
            analysis_lines = []
            for keyword, data in keyword_results["keywords"].items():
                line = f"Keyword: {keyword}, Count: {data['count']}, Density: {round(data['density'], 2)}%"
                analysis_lines.append(line)
            analysis_text = "\n".join(analysis_lines)
    
    output = f"Extracted Text:\n{output_text}\n\nKeyword Analysis:\n{analysis_text}"
    file_path = os.path.join(download_dir, 'keyword_analysis.txt')
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(output)
    
    return send_file(file_path, mimetype='text/plain', as_attachment=True, download_name='keyword_analysis.txt')


@app.route('/image_search', methods=['GET', 'POST'])
@login_required
@subscription_required
def image_search():
    links_data = None
    url_input = ""
    robots_info = None
    
    # Check if this is a refresh request
    is_refresh = request.args.get('refresh') == 'true'
    
    # Check if we're coming from another page (not a form submission)
    coming_from_another_page = request.method == 'GET' and not is_refresh and request.referrer and 'image_search' not in request.referrer
    
    # Clear session data on refresh or when coming from another page
    if is_refresh or coming_from_another_page:
        session.pop('image_search_url', None)
        session.pop('image_search_links', None)
        session.pop('image_search_robots', None)
        if is_refresh:
            return redirect(url_for('image_search'))
    
    if request.method == 'POST':
        url_input = request.form.get('url')
        # Get URL from the mobile input if desktop input is empty
        if not url_input:
            url_input = request.form.get('mobile-url')
            
        respect_robots = request.form.get('respect_robots') == 'on'
        
        if url_input:
            # Use the enhanced analyze_links function with robots.txt support
            home_links, other_links, robots_info = analyze_links(
                url_input,
                respect_robots=respect_robots
            )
            
            links_data = {'home': home_links, 'other': other_links}
            
            # Store the search history
            u_id = session.get('user_id')
            usage_tool = "Image Search"
            add_search_history(u_id, usage_tool, url_input)
            
            # Store in session (remove parser_id as it's not needed in template)
            session['image_search_url'] = url_input
            session['image_search_links'] = links_data
            
            if robots_info and 'parser_id' in robots_info:
                session_robots_info = robots_info.copy()
                session_robots_info.pop('parser_id', None)
                session['image_search_robots'] = session_robots_info
    else:
        # Only retrieve stored session data if we're not coming from another page
        if not coming_from_another_page:
            stored_url = session.get('image_search_url')
            if stored_url:
                url_input = stored_url
                links_data = session.get('image_search_links')
                robots_info = session.get('image_search_robots')
    
    return render_template(
        'image_search.html',
        url_input=url_input,
        links_data=links_data,
        robots_info=robots_info
    )

@app.route('/image_detail', methods=['GET'])
@login_required
@subscription_required
def image_detail():
    link = request.args.get('link')
    if not link:
        flash("No link provided for image analysis.")
        return redirect(url_for('image_search'))
    cache_key = f"images_{link}"
    images = cache.get(cache_key)
    if images is None:
        images = extract_images(link)
        cache.set(cache_key, images)
    return render_template('image_detail.html', link=link, images=images)


@app.route('/download_image_csv')
@login_required
def download_image_csv():
    link = request.args.get('link')
    if not link:
        flash("No link provided for download.")
        return redirect(url_for('image_search'))

    cache_key = f"images_{link}"
    images = cache.get(cache_key)
    if images is None:
        images = extract_images(link)
        cache.set(cache_key, images)

    # Prepare a path for saving our CSV
    file_path = os.path.join(download_dir, 'images.csv')

    # Figure out which columns (field names) we have:
    # if `images` is empty, fall back to known columns
    if images:
        fieldnames = images[0].keys()  # e.g. ["image_number", "url", ...]
    else:
        fieldnames = ["image_number", "url", "alt_text", "title", "file_extension", "file_size", "resolution"]

    # Write CSV via built-in DictWriter
    with open(file_path, 'w', newline='', encoding='utf-8') as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(images)

    return send_file(file_path, mimetype='text/csv', as_attachment=True, download_name='images.csv')


@app.route('/h_search', methods=['GET', 'POST'])
@login_required
@subscription_required
def h_search():
    url_input = ""
    links_data = None
    robots_info = None
    
    if request.method == 'POST':
        url_input = request.form.get('url')
        respect_robots = request.form.get('respect_robots') == 'on'
        
        if url_input:
            # Use the enhanced analyze_links function with robots.txt support
            home_links, other_links, robots_info = analyze_links(
                url_input,
                respect_robots=respect_robots
            )
            
            # Store the search history
            u_id = session.get('user_id')
            usage_tool = "Heading Search"
            add_search_history(u_id, usage_tool, url_input)
            
            # Store values in session to persist across requests (remove parser_id)
            session['home_links'] = home_links
            session['other_links'] = other_links
            session['h_url'] = url_input
            
            if robots_info and 'parser_id' in robots_info:
                session_robots_info = robots_info.copy()
                session_robots_info.pop('parser_id', None)
                session['h_robots_info'] = session_robots_info

            # Redirect to prevent form resubmission
            return redirect(url_for('h_search', url=url_input))

    # Clear session if there's no URL parameter (fresh page load)
    if 'url' not in request.args:
        session.pop('home_links', None)
        session.pop('other_links', None)
        session.pop('h_url', None)
        session.pop('h_robots_info', None)
        url_input = ""
        links_data = None
        robots_info = None
    else:
        # Retrieve stored values or initialize them
        url_input = request.args.get('url', session.get('h_url', ""))
        if url_input:
            links_data = {
                'home': session.get('home_links', []),
                'other': session.get('other_links', [])
            }
            robots_info = session.get('h_robots_info')

    return render_template(
        'h_search.html', 
        url_input=url_input, 
        links_data=links_data,
        robots_info=robots_info
    )

@app.route('/h_detail', methods=['GET'])
@login_required
@subscription_required
def h_detail():
    url_input = request.args.get('url')
    if not url_input:
        flash("No URL provided for H Tags analysis.")
        return redirect(url_for('h_search'))

    # 1) Extract headings in DOM order
    headings_in_order = extract_headings_in_order(url_input)

    # 2) Count how many of each tag (e.g. h1, h2, h3)
    tag_counts = Counter(h["tag"] for h in headings_in_order)
    # For example: {'h1': 2, 'h2': 5, 'h3': 3, ...}

    # 3) If you want to display 'home_links' or other info
    home_links = session.get('home_links', [])

    # -- NEW CODE to compute "all H1 under 60 chars" --
    # Collect all h1 headings
    h1_headings = [h for h in headings_in_order if h['tag'] == 'h1']
    # Check if each H1's text is < 60 chars
    all_h1_under_60 = all(len(h['text']) < 60 for h in h1_headings)

    # 4) Pass everything to the template
    return render_template(
        'h_detail.html',
        url_input=url_input,
        headings_in_order=headings_in_order,
        tag_counts=tag_counts,
        home_links=home_links,
        all_h1_under_60=all_h1_under_60  # <-- pass our boolean
    )

@app.route('/download_h_csv')
@login_required
def download_h_csv():
    url_input = request.args.get('url')
    if not url_input:
        flash("No URL provided for download.")
        return redirect(url_for('h_search'))
    
    # Use the function that returns headings in order
    headings_in_order = extract_headings_in_order(url_input)

    # Convert data into a list of dictionaries for CSV
    data = []
    for h in headings_in_order:
        data.append({
            'Tag': h['tag'].upper(),
            'Heading': h['text'],
            'HeadingLength': len(h['text']),
            'Level': h['level']
        })

    # Ensure the download directory exists
    os.makedirs(download_dir, exist_ok=True)

    # Write CSV via built-in csv library
    file_path = os.path.join(download_dir, 'headings.csv')
    with open(file_path, 'w', newline='', encoding='utf-8') as csv_file:
        fieldnames = ['Tag', 'Heading', 'HeadingLength', 'Level']
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(data)

    return send_file(
        file_path,
        mimetype='text/csv',
        as_attachment=True,
        download_name='headings.csv'
    )

@app.route('/meta_search', methods=['GET', 'POST'])
@login_required
@subscription_required
def meta_search():
    links_data = None
    url_input = ""
    robots_info = None
    
    # Check if this is a refresh request
    is_refresh = request.args.get('refresh') == 'true'
    
    # Check if we're coming from another page (not a form submission)
    coming_from_another_page = request.method == 'GET' and not is_refresh and request.referrer and 'meta_search' not in request.referrer
    
    # Clear session data on refresh or when coming from another page
    if is_refresh or coming_from_another_page:
        session.pop('meta_search_url', None)
        session.pop('meta_search_links', None)
        session.pop('meta_search_robots', None)
        if is_refresh:
            return redirect(url_for('meta_search'))
    
    if request.method == 'POST':
        url_input = request.form.get('url')
        # Get URL from the mobile input if desktop input is empty
        if not url_input:
            url_input = request.form.get('mobile-url')
            
        respect_robots = request.form.get('respect_robots') == 'on'
        
        if url_input:
            # Use the enhanced analyze_links function with robots.txt support
            home_links, other_links, robots_info = analyze_links(
                url_input,
                respect_robots=respect_robots
            )
            
            links_data = {'home': home_links, 'other': other_links}
            
            # Store the search history
            u_id = session.get('user_id')
            usage_tool = "Meta Search"
            add_search_history(u_id, usage_tool, url_input)
            
            # Store in session (remove parser_id as it's not needed in template)
            session['meta_search_url'] = url_input
            session['meta_search_links'] = links_data
            
            if robots_info and 'parser_id' in robots_info:
                session_robots_info = robots_info.copy()
                session_robots_info.pop('parser_id', None)
                session['meta_search_robots'] = session_robots_info
    else:
        # Only retrieve stored session data if we're not coming from another page
        if not coming_from_another_page:
            stored_url = session.get('meta_search_url')
            if stored_url:
                url_input = stored_url
                links_data = session.get('meta_search_links')
                robots_info = session.get('meta_search_robots')
    
    return render_template(
        'meta_search.html',
        url_input=url_input,
        links_data=links_data,
        robots_info=robots_info
    )

@app.route('/meta_detail')
@login_required
@subscription_required
def meta_detail():
    link = request.args.get('link')
    if not link:
        flash("No link provided for meta analysis.", "warning")
        return redirect(url_for('meta_search'))

    try:
        # Unpack all three return values from analyze_links
        home_links, other_links, robots_info = analyze_links(link)
        
        # Create links_data dictionary
        links_data = {
            'home': home_links,
            'other': other_links
        }

        # Extract meta information
        meta_info = extract_seo_data(link)
        
        if meta_info.get('error'):
            flash(meta_info['error'], 'danger')
            return redirect(url_for('meta_search'))
        
        return render_template(
            'meta_detail.html', 
            link=link, 
            meta_info=meta_info, 
            links_data=links_data,
            robots_info=robots_info  # Optional: pass robots_info to template if needed
        )
    
    except Exception as e:
        # Log the full error for debugging
        app.logger.error(f"Error in meta_detail: {str(e)}")
        app.logger.error(traceback.format_exc())
        
        flash("An error occurred while analyzing the URL.", "danger")
        return redirect(url_for('meta_search'))

@app.route('/download_meta_csv')
@login_required
def download_meta_csv():
    link = request.args.get('link')
    if not link:
        flash("No link provided for download.")
        return redirect(url_for('meta_search'))
    
    meta_info = extract_seo_data(link)
    if meta_info.get('error'):
        flash(meta_info['error'])
        return redirect(url_for('meta_search'))

    # Convert the SEO data into a CSV-friendly format
    data = []
    # Title row
    data.append({
        'Type': 'title',
        'Attribute': 'title',
        'Content': meta_info['title']
    })
    # Meta tags
    for m in meta_info['meta_tags']:
        data.append({
            'Type': 'meta',
            'Attribute': m['attribute'],
            'Content': m['content']
        })
    # Schema (JSON-LD)
    for s in meta_info['schema']:
        data.append({
            'Type': 'schema',
            'Attribute': 'JSON-LD',
            'Content': json.dumps(s)  # convert the schema object to a JSON string
        })

    # Ensure the download directory exists
    os.makedirs(download_dir, exist_ok=True)

    # Write CSV file using built-in csv
    file_path = os.path.join(download_dir, 'meta_data.csv')
    with open(file_path, 'w', newline='', encoding='utf-8') as csv_file:
        fieldnames = ['Type', 'Attribute', 'Content']
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(data)

    return send_file(
        file_path,
        mimetype='text/csv',
        as_attachment=True,
        download_name='meta_data.csv'
    )
# ----------------------
# Site Structure Routes
# ----------------------

@app.route("/site_structure", methods=["GET", "POST"])
@subscription_required
@login_required
def site_structure():
    if request.method == "POST":
        start_url = request.form["url"]
        
        if not start_url:
            return render_template("index.html", error="Please provide a URL.")
        if not start_url.startswith("http"):
            start_url = "http://" + start_url

        
        # Store the search history in the database
        u_id = session.get('user_id')
        usage_tool = "Site Structure"
        add_search_history(u_id, usage_tool, start_url)  # Add the search query to the search history


        # Create a unique ID for this crawl job
        job_id = str(uuid.uuid4())
        session['job_id'] = job_id
        crawl_status[job_id] = {
            'status': 'running',
            'progress': 0,
            'url': start_url,
            'start_time': time.time()
        }
        
        # Run the crawler in a background thread
        try:
            executor.submit(run_async_in_thread_with_progress, main_crawl(start_url, job_id), job_id)

        except Exception as e:
            print(f"Error during crawling: {e}")
            crawl_status[job_id]['status'] = 'failed'
            return render_template("site_structure.html", error="An error occurred while crawling the URL.")
        
        return redirect(url_for("loading"))

    return render_template("site_structure.html")



def run_async_in_thread_with_progress(coro, job_id):
    """Run an async coroutine in a thread and update progress"""
    try:
        result = run_async_in_thread(coro)
        crawl_status[job_id]['status'] = 'completed'
        crawl_status[job_id]['progress'] = 100
        return result
    except Exception as e:
        print(f"Error in background task: {e}")
        crawl_status[job_id]['status'] = 'failed'
        return None


@app.route("/loading")
def loading():
    job_id = session.get('job_id')
    if not job_id or job_id not in crawl_status:
        return redirect(url_for("site_structure"))
        
    return render_template("loading.html", job_id=job_id)


@app.route("/progress/<job_id>")
def progress(job_id):
    if job_id not in crawl_status:
        return jsonify({"status": "unknown"})
        
    status_data = crawl_status[job_id]
    
    # Calculate elapsed time
    elapsed = time.time() - status_data['start_time']
    
    # Simulate progress if we don't have real metrics
    if status_data['status'] == 'running' and status_data['progress'] < 95:
        # Gradually increase progress - exponentially slower as it approaches 95%
        progress_increment = max(0.5, 10 * (1 - status_data['progress']/100))
        status_data['progress'] += progress_increment
        
    return jsonify({
        "status": status_data['status'],
        "progress": min(round(status_data['progress'], 1), 100),
        "elapsed": round(elapsed, 1),
        "url": status_data['url']
    })


@app.route("/visualize")
@login_required
def visualize():
    job_id = session.get('job_id')
    if job_id and job_id in crawl_status:
        if crawl_status[job_id]['status'] == 'running':
            return redirect(url_for("loading"))
            
    return render_template("visualize.html")


@app.route("/data")
def get_data():
    """Ensure JSON is returned correctly."""
    data = load_results()
    print("DEBUG: JSON Data Sent ->", json.dumps(data, indent=2))  # Debugging Output
    return jsonify({"home_links": data["home_links"], "status_codes": data["status_codes"]})

@app.route('/download_results')
def download_results():
    # Retrieve the crawl job ID from the session
    job_id = session.get('job_id')
    if not job_id:
        flash("No crawl job found. Please start a new crawl and upload the files again.")
        return redirect(url_for('site_structure'))

    # Build the CSV file path using the job ID
    csv_path = f"crawled_data/crawl_{job_id}.csv"
    
    if not os.path.exists(csv_path):
        flash("Crawl results file not found or expired. Please start a new crawl and upload the files again.")
        return redirect(url_for('site_structure'))
    
    return send_file(csv_path, mimetype='text/csv', as_attachment=True, download_name=f'crawl_results_{job_id}.csv')

async def main_crawl(start_url, job_id):
    """Run the crawler asynchronously and save results with the job ID."""
    url_status, home_links, other_links = await crawl(start_url)
    save_to_json(url_status, home_links, other_links, job_id)


@app.route('/sitemap_analysis')
@login_required
@subscription_required
def sitemap_analysis():
    """Display sitemap analysis page"""
    url = request.args.get('url')
    check_status = request.args.get('check_status', 'true').lower() == 'true'
    
    if not url:
        flash("Please provide a URL to analyze sitemaps.", "warning")
        return redirect(url_for('url_search'))
    
    # Import the sitemap analyzer
    from sitemap_analyzer import extract_sitemap_urls
    
    # Extract sitemap URLs with status checking
    sitemap_data = extract_sitemap_urls(url, check_status=check_status)
    
    # Sort URLs by path hierarchy
    if sitemap_data.get('urls'):
        sitemap_data['urls'] = sorted(
            sitemap_data['urls'], 
            key=lambda x: '/'.join(x.get('path_hierarchy', []))
        )
    
    # Store the search history
    u_id = session.get('user_id')
    usage_tool = "Sitemap Analysis"
    add_search_history(u_id, usage_tool, url)
    
    return render_template(
        'sitemap_analysis.html',
        url=url,
        sitemap_data=sitemap_data,
        check_status=check_status
    )

@app.route('/filter_sitemap_urls')
@login_required
def filter_sitemap_urls():
    """Filter sitemap URLs based on criteria"""
    url = request.args.get('url')
    filter_type = request.args.get('filter_type')
    
    if not url:
        return jsonify({
            'success': False,
            'message': 'URL parameter is required'
        })
    
    # Import the sitemap analyzer
    from sitemap_analyzer import extract_sitemap_urls
    
    # Extract sitemap URLs
    sitemap_data = extract_sitemap_urls(url)
    
    if not sitemap_data.get('success', False):
        return jsonify({
            'success': False,
            'message': 'Failed to extract sitemap data'
        })
    
    # Apply filter
    filtered_urls = sitemap_data.get('urls', [])
    
    if filter_type == 'blog':
        filtered_urls = [url for url in filtered_urls if url.get('is_blog', False)]
    elif filter_type == 'search':
        filtered_urls = [url for url in filtered_urls if url.get('is_search', False)]
    elif filter_type.startswith('status_'):
        status_group = filter_type.replace('status_', '')
        filtered_urls = [url for url in filtered_urls if url.get('status_group') == status_group]
    elif filter_type.startswith('path_'):
        path_level = int(filter_type.replace('path_', ''))
        filtered_urls = [url for url in filtered_urls if url.get('path_level') == path_level]
    
    # Sort URLs by path hierarchy
    filtered_urls = sorted(filtered_urls, key=lambda x: '/'.join(x.get('path_hierarchy', [])))
    
    return jsonify({
        'success': True,
        'urls': filtered_urls
    })

@app.route('/download_sitemap_urls')
@login_required
def download_sitemap_urls():
    """Download URLs from sitemaps as CSV"""
    url = request.args.get('url')
    filter_type = request.args.get('filter_type', 'all')
    
    if not url:
        flash("No URL provided for sitemap analysis.")
        return redirect(url_for('url_search'))
    
    # Import the sitemap analyzer
    from sitemap_analyzer import extract_sitemap_urls

    
    # Extract sitemap URLs
    sitemap_data = extract_sitemap_urls(url)
    
    if not sitemap_data.get('success', False) or not sitemap_data.get('urls', []):
        flash("No sitemap URLs found or could not analyze sitemaps.", "warning")
        return redirect(url_for('sitemap_analysis', url=url))
    
    # Apply filter if needed
    urls_to_export = sitemap_data.get('urls', [])
    
    if filter_type == 'blog':
        urls_to_export = [url for url in urls_to_export if url.get('is_blog', False)]
        file_suffix = 'blogs'
    elif filter_type == 'search':
        urls_to_export = [url for url in urls_to_export if url.get('is_search', False)]
        file_suffix = 'search'
    elif filter_type.startswith('status_'):
        status_group = filter_type.replace('status_', '')
        urls_to_export = [url for url in urls_to_export if url.get('status_group') == status_group]
        file_suffix = f'status_{status_group}'
    else:
        file_suffix = 'all'
    
    # Create CSV file
    file_path = os.path.join(download_dir, f'sitemap_urls_{file_suffix}.csv')
    
    with open(file_path, 'w', newline='', encoding='utf-8') as csv_file:
        # Determine fields based on the data we have
        all_fields = set()
        for url_data in urls_to_export:
            all_fields.update(url_data.keys())
        
        # Remove complex fields
        for field in ['alternates', 'path_hierarchy', 'search_terms']:
            if field in all_fields:
                all_fields.remove(field)
        
        # Sort fields for consistent output
        fieldnames = sorted(list(all_fields))
        # Put important fields first
        priority_fields = ['url', 'status_code', 'status_group', 'is_blog', 'is_search', 'path', 'path_level']
        for field in reversed(priority_fields):
            if field in fieldnames:
                fieldnames.remove(field)
                fieldnames = [field] + fieldnames
        
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        
        for url_data in urls_to_export:
            # Make a copy without the complex fields
            row_data = {k: v for k, v in url_data.items() if k in fieldnames}
            writer.writerow(row_data)
    
    return send_file(
        file_path,
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'sitemap_urls_{urlparse(url).netloc}_{file_suffix}.csv'
    )

# Register the custom test
@app.template_test('match')
def match_test(value, pattern):
    return re.search(pattern, value) is not None

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        try:
            # Get form data
            name = request.form.get('name')
            email = request.form.get('email')
            message = request.form.get('message')
            
            # Validate required fields
            if not all([name, email, message]):
                flash('Please fill in all required fields.', 'warning')
                return render_template('contact.html')
            
            # Compose the email
            subject = f"Web Analyzer Pro Contact Form: {name}"
            msg = Message(
                subject=subject,
                sender=app.config['MAIL_USERNAME'],
                recipients=[app.config['MAIL_USERNAME']]  # Send to your own email address
            )
            
            # Create email body
            msg.body = f"""
            Contact Form Submission:
            
            Name: {name}
            Email: {email}
            
            Message:
            {message}
            """
            
            # Send the email
            mail.send(msg)
            
            # Send an auto-reply to the user
            auto_reply = Message(
                subject="Thank you for contacting Web Analyzer Pro",
                sender=app.config['MAIL_USERNAME'],
                recipients=[email]
            )
            
            auto_reply.body = f"""
            Dear {name},
            
            Thank you for contacting Web Analyzer Pro. We have received your message and will get back to you as soon as possible, typically within 24 hours during business days.
            
            For urgent inquiries, please call our support line at +1 (800) 123-4567.
            
            Best Regards,
            The Web Analyzer Pro Team
            """
            
            mail.send(auto_reply)
            
            # Show success message
            flash('Your message has been sent successfully! We will contact you soon.', 'success')
            return redirect(url_for('contact'))
            
        except Exception as e:
            app.logger.error(f"Error sending contact email: {str(e)}")
            flash('There was an error sending your message. Please try again later.', 'danger')
            
    return render_template('contact.html')

@app.route('/privacy')
def privacy():
    return render_template('privacy.html')
@app.route('/terms')
def terms():
    return render_template('terms.html')
@app.route('/about')
def about():
    return render_template('about.html')
@app.route('/cookie-policy')
def cookie_policy():
    return render_template('cookie_policy.html')

@app.route('/time-date')
def time_and_date_today():
    current_time = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")
    return jsonify({"current_time": current_time})

# Register the custom test
@app.template_test('match')
def match_test(value, pattern):
    return re.search(pattern, value) is not None
# Add these custom filters to your app.py file after the app initialization

import json
import re

@app.template_filter('parse_json_features')
def parse_json_features(features_str):
    """
    Parse JSON features string and return a dictionary
    or list of features for display
    """
    if not features_str:
        return []
    
    # Remove any extra whitespace
    features_str = features_str.strip()
    
    # Try to parse as JSON
    try:
        # If it's a JSON object
        if features_str.startswith('{') and features_str.endswith('}'):
            features_dict = json.loads(features_str)
            # Convert to list of tuples for easier template iteration
            return [(key, value) for key, value in features_dict.items()]
        # If it's a comma-separated list
        else:
            return [(feature.strip(), True) for feature in features_str.split(',') if feature.strip()]
    except (json.JSONDecodeError, AttributeError):
        # Fallback to treating as comma-separated string
        try:
            return [(feature.strip(), True) for feature in features_str.split(',') if feature.strip()]
        except:
            return []

@app.template_filter('format_feature_name')
def format_feature_name(name):
    """
    Format feature names for display
    Examples:
    - 'feature1' -> 'Feature 1'
    - 'some_feature' -> 'Some Feature'
    - 'feature1' -> 'Feature 1'
    - 'feature2' -> 'Feature 2'
    """
    if not name:
        return ''
    
    # Convert to string if not already
    name = str(name)
    
    # Handle special patterns like 'feature1', 'feature2' etc.
    if name.startswith('feature') and len(name) > 7 and name[-1].isdigit():
        # Extract the number
        match = re.match(r'feature(\d+)', name)
        if match:
            num = match.group(1)
            return f'Feature {num}'
    
    # Replace underscores with spaces
    name = name.replace('_', ' ')
    
    # Replace camelCase with spaces (e.g., 'someFeature' -> 'some Feature')
    name = re.sub('([a-z])([A-Z])', r'\1 \2', name)
    
    # Capitalize first letter of each word
    name = ' '.join(word.capitalize() for word in name.split())
    
    return name.strip()

@app.template_filter('feature_icon')
def feature_icon(value):
    """
    Return appropriate icon class based on feature value
    """
    if value is True or str(value).lower() == 'true':
        return 'fa-check-circle text-secondary'
    elif value is False or str(value).lower() == 'false':
        return 'fa-times-circle text-gray-400'
    else:
        # For non-boolean values, always show check
        return 'fa-check-circle text-secondary'

@app.template_filter('format_feature')
def format_feature(value):
    """
    Format the display of a feature based on its value
    """
    if isinstance(value, bool):
        # For boolean values, we just use the icon
        return ''
    elif isinstance(value, (int, float)):
        # Continue with number formatting...
        return str(value)
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# Add this function to your app.py file to clean up duplicate subscriptions

def cleanup_duplicate_subscriptions():
    """
    Utility function to clean up duplicate active subscriptions for users.
    Keeps only the most recent active subscription per user.
    """
    from sqlalchemy import and_
    
    # Get current time
    now = datetime.now(UTC)
    
    # Get all users
    users = User.query.all()
    
    deactivated_count = 0
    
    for user in users:
        # Get all active subscriptions for this user
        active_subscriptions = (
            SubscribedUser.query
            .filter(SubscribedUser.U_ID == user.id)
            .filter(SubscribedUser.end_date > now)
            .filter(SubscribedUser._is_active == True)
            .order_by(SubscribedUser.start_date.desc())  # Changed from created_at to start_date
            .all()
        )
        
        # If user has more than one active subscription
        if len(active_subscriptions) > 1:
            # Keep the first (most recent) one, deactivate the rest
            for sub in active_subscriptions[1:]:
                sub.is_active = False
                deactivated_count += 1
                app.logger.info(f"Deactivated duplicate subscription {sub.id} for user {user.id}")
    
    if deactivated_count > 0:
        db.session.commit()
        app.logger.info(f"Cleaned up {deactivated_count} duplicate subscriptions")
    
    return deactivated_count

# You can run this function in a Flask shell or at startup
# To run it when the app starts, add this after your database initialization:
# with app.app_context():
#     cleanup_duplicate_subscriptions()
# Add this to the bottom of your app.py file, before app.run():

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        # Create super admin if it doesn't exist
        create_super_admin()
        
        # Clean up any duplicate subscriptions
        try:
            deactivated_count = cleanup_duplicate_subscriptions()
            if deactivated_count > 0:
                print(f"Cleaned up {deactivated_count} duplicate subscriptions")
        except Exception as e:
            print(f"Error cleaning up subscriptions: {str(e)}")
            app.logger.error(f"Error cleaning up subscriptions: {str(e)}")
        
app.run(debug=True)
