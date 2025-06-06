from flask import Flask, flash, render_template, request, redirect, url_for, session, make_response, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from datetime import datetime, timezone 
from functools import wraps
import pdfkit # Imported for PDF generation
import io # Used for handling PDF bytes in memory
from decimal import Decimal # For precise monetary calculations


# Configure pdfkit to point to wkhtmltopdf executable
# IMPORTANT: Update this path if wkhtmltopdf.exe is installed elsewhere on your system
PDFKIT_CONFIG = pdfkit.configuration(wkhtmltopdf=r'C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe') 

app = Flask(__name__)


# Configure the MySQL database connection
app.config['SECRET_KEY'] = 'your_secret_key' # Replace with a strong, random key
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:root@localhost/scrap_business'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['TEMPLATES_AUTO_RELOAD'] = True # Added for easier development/debugging

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.Enum('admin', 'seller', 'agent'), nullable=False)
    contact = db.Column(db.String(20))
    scrap_items = db.relationship('ScrapItem', backref='seller', lazy=True)
    pickup_requests_seller = db.relationship('PickupRequest', backref='seller', foreign_keys='PickupRequest.seller_id', lazy=True)
    pickup_requests_agent = db.relationship('PickupRequest', backref='agent', foreign_keys='PickupRequest.agent_id', lazy=True)
    # Removed the problematic 'transactions' relationship from User model.
    # A user's transactions can be accessed by iterating through their pickup requests:
    # e.g., for req in user.pickup_requests_seller: if req.transaction: print(req.transaction.total_amount)

    def __repr__(self):
        return f'<User {self.name}>'


class ScrapItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    scrap_type = db.Column(db.String(100), nullable=False)
    weight_kg = db.Column(db.DECIMAL(10, 2), nullable=False)
    price_per_kg = db.Column(db.DECIMAL(10, 2), nullable=False)
    date_added = db.Column(db.TIMESTAMP, default=lambda: datetime.now(timezone.utc)) 
    pickup_request = db.relationship('PickupRequest', backref='scrap_item', lazy=True)

    def __repr__(self):
        return f'<ScrapItem {self.scrap_type} ({self.weight_kg}kg)>'


class PickupRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    seller_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    scrap_item_id = db.Column(db.Integer, db.ForeignKey('scrap_item.id'), nullable=False)
    pickup_date = db.Column(db.Date, nullable=False)
    status = db.Column(db.Enum('Pending', 'Assigned', 'In Transit', 'Arrived', 'Completed', 'Cancelled', 'Failed'), default='Pending')
    agent_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    request_date = db.Column(db.TIMESTAMP, default=lambda: datetime.now(timezone.utc)) 
    transaction = db.relationship('Transaction', backref='pickup_request', uselist=False, lazy=True)

    def __repr__(self):
        return f'<PickupRequest for Item {self.scrap_item_id} on {self.pickup_date}>'
    
class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    pickup_request_id = db.Column(db.Integer, db.ForeignKey('pickup_request.id'), unique=True, nullable=False)
    total_amount = db.Column(db.DECIMAL(10, 2), nullable=False)
    bill_generated = db.Column(db.Boolean, default=False)
    payment_status = db.Column(db.Enum('Pending', 'Paid', 'Failed'), default='Pending')
    transaction_date = db.Column(db.TIMESTAMP, default=lambda: datetime.now(timezone.utc)) 

    def __repr__(self):
        return f'<Transaction ID {self.id}, Amount: {self.total_amount}>'


# Decorator to ensure user is logged in
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please log in to access this page.", "info")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Decorator to ensure user is an admin
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please log in to access this page.", "info")
            return redirect(url_for('login'))
        user = User.query.get(session['user_id'])
        if not user or user.role != 'admin':
            flash("You do not have permission to access this page.", "danger")
            return redirect(url_for('home')) # Redirect to home or login
        return f(*args, **kwargs)
    return decorated_function

# Decorator to ensure user is an agent
def agent_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please log in to access this page.", "info")
            return redirect(url_for('login'))
        user = User.query.get(session['user_id'])
        if not user or user.role != 'agent':
            flash("You are not authorized to access this page.", "danger")
            return redirect(url_for('home')) # Redirect to home or login
        return f(*args, **kwargs)
    return decorated_function


@app.route('/')
def home():
    return "Welcome to the Scrap Business Web App!"


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        role = request.form['role']
        contact = request.form['contact']

        # Basic validation for email uniqueness
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash("Email already registered. Please use a different email or log in.", "warning")
            return render_template('register.html')

        new_user = User(name=name, email=email, password_hash=hashed_password, role=role, contact=contact)
        db.session.add(new_user)
        db.session.commit()
        flash("Registration successful! Please log in.", "success")
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['user_role'] = user.role # Save role in session for easier access and decorator checks
            flash(f"Welcome, {user.name}!", "success")
            # Redirect based on user role
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif user.role == 'agent':
                return redirect(url_for('agent_dashboard'))
            elif user.role == 'seller':
                return redirect(url_for('seller_dashboard'))
            else:
                return redirect(url_for('home')) # Fallback for undefined roles (shouldn't happen with enum)
        else:
            flash("Invalid email or password.", "danger")
            return render_template('login.html') # Stay on login page with error
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('user_role', None) # Also pop user role
    flash("You have been logged out.", "info")
    return redirect(url_for('login')) # Redirect to login after logout


@app.route('/add_scrap_item', methods=['GET', 'POST'])
@login_required
def add_scrap_item():
    if request.method == 'POST':
        try:
            scrap_type = request.form['scrap_type']
            weight_kg = float(request.form['weight_kg'])
            price_per_kg = float(request.form['price_per_kg'])
            user_id = session['user_id']
            # Get current time and make it timezone-naive for MySQL
            date_added = datetime.now(timezone.utc).replace(tzinfo=None) 

            new_item = ScrapItem(scrap_type=scrap_type, weight_kg=weight_kg, price_per_kg=price_per_kg, user_id=user_id, date_added=date_added)
            db.session.add(new_item)
            db.session.commit()
            flash("Scrap item added successfully!", "success")
            return redirect(url_for('view_my_listings')) 

        except ValueError:
            flash("Invalid input. Please enter numeric values for weight and price.", "danger")
            return render_template('add_scrap_item.html') # Stay on the form with error
    return render_template('add_scrap_item.html')


@app.route('/my_listings')
@login_required
def view_my_listings():
    user_id = session['user_id']
    scrap_items = ScrapItem.query.filter_by(user_id=user_id).all()
    return render_template('my_listings.html', scrap_items=scrap_items)


@app.route('/seller_dashboard')
@login_required
def seller_dashboard():
    # This route should ideally also use @seller_required if you want to strictly enforce it
    if session.get('user_role') != 'seller':
        flash("You are not authorized to access the seller dashboard.", "danger")
        return redirect(url_for('home')) # Or login
    return render_template('seller_dashboard.html')


@app.route('/agent/dashboard')
@agent_required
def agent_dashboard():
    user_id = session.get('user_id')
    if user_id is None:
        flash("Your session has expired. Please log in again.", "danger")
        return redirect(url_for('login'))
    assigned_pickups = PickupRequest.query.filter_by(agent_id=user_id).all()
    return render_template('agent_dashboard.html', assigned_pickups=assigned_pickups)


@app.route('/edit_scrap_item/<int:item_id>', methods=['GET', 'POST'])
@login_required
def edit_scrap_item(item_id):
    item = ScrapItem.query.get_or_404(item_id)
    if item.user_id != session['user_id']:
        flash("You are not authorized to edit this item.", "danger")
        return redirect(url_for('view_my_listings')) # Redirect with error

    if request.method == 'POST':
        try:
            item.scrap_type = request.form['scrap_type']
            item.weight_kg = float(request.form['weight_kg']) # Ensure float conversion
            item.price_per_kg = float(request.form['price_per_kg']) # Ensure float conversion
            db.session.commit()
            flash("Scrap item updated successfully!", "success")
            return redirect(url_for('view_my_listings'))
        except ValueError:
            flash("Invalid input. Please enter numeric values for weight and price.", "danger")
            return render_template('edit_scrap_item.html', item=item) # Stay on form with error
    return render_template('edit_scrap_item.html', item=item)


@app.route('/delete_scrap_item/<int:item_id>', methods=['POST']) # Changed to POST method
@login_required
def delete_scrap_item(item_id):
    item = ScrapItem.query.get_or_404(item_id)

    # Ensure the current user is the seller
    if item.user_id != session['user_id']:
        flash('You are not authorized to delete this item.', 'danger')
        return redirect(url_for('view_my_listings'))

    db.session.delete(item)
    db.session.commit()
    flash('Item deleted successfully.', 'success')
    return redirect(url_for('view_my_listings'))


@app.route('/request_pickup/<int:item_id>', methods=['GET', 'POST'])
@login_required
def request_pickup(item_id):
    item = ScrapItem.query.get_or_404(item_id)

    if item.user_id != session['user_id']:
        flash("You are not authorized to request pickup for this item.", "danger")
        return redirect(url_for('view_my_listings')) # Redirect with error

    if request.method == 'POST':
        seller_id = session['user_id']
        # Check for active requests (status not in Completed, Cancelled, Failed)
        active_request = PickupRequest.query.filter(
            PickupRequest.seller_id == seller_id,
            PickupRequest.status.notin_(['Completed', 'Cancelled', 'Failed'])
        ).first()

        if active_request:
            flash("You already have an active pickup request. Please wait for it to be completed or cancelled.", "warning")
            return redirect(url_for('view_pending_pickups')) # Redirect to pending pickups

        pickup_date_str = request.form['pickup_date']
        try:
            # Convert string to datetime and make it timezone-naive
            pickup_date = datetime.strptime(pickup_date_str, '%Y-%m-%d').replace(tzinfo=None) 
        except ValueError:
            flash("Invalid date format. Please use 'YYYY-MM-DD'.", "danger")
            return render_template('request_pickup.html', item=item) # Stay on form with error

        new_request = PickupRequest(
            seller_id=seller_id,
            scrap_item_id=item.id,
            pickup_date=pickup_date
        )
        db.session.add(new_request)
        db.session.commit()
        flash("Pickup request submitted successfully!", "success")
        return redirect(url_for('view_pending_pickups'))

    return render_template('request_pickup.html', item=item)


@app.route('/pending_pickups')
@login_required
def view_pending_pickups():
    user_id = session['user_id']
    # Filter by seller_id and only show pending requests
    pending_requests = PickupRequest.query.filter_by(seller_id=user_id, status='Pending').all()
    return render_template('pending_pickups.html', pending_requests=pending_requests)


@app.route('/admin')
@admin_required
def admin_dashboard():
    total_users = User.query.count()
    total_scrap_items = ScrapItem.query.count()
    pending_pickups_count = PickupRequest.query.filter_by(status='Pending').count()
    all_pickup_requests = PickupRequest.query.all()
    pickup_agents = User.query.filter_by(role='agent').all()
    total_transactions = Transaction.query.count() 
    return render_template('admin_dashboard.html',
                           total_users=total_users,
                           total_scrap_items=total_scrap_items,
                           pending_pickups_count=pending_pickups_count,
                           all_pickup_requests=all_pickup_requests,
                           pickup_agents=pickup_agents, # Pass agents for dropdown
                           total_transactions=total_transactions)


@app.route('/assign_agent/<int:request_id>', methods=['POST'])
@admin_required
def assign_agent(request_id):
    pickup_request = PickupRequest.query.get_or_404(request_id)
    if pickup_request.status == 'Pending':
        agent_id = request.form.get('agent_id') # Use .get() for safer access
        if agent_id:
            agent = User.query.get_or_404(agent_id)
            if agent.role == 'agent':
                pickup_request.agent_id = agent.id
                pickup_request.status = 'Assigned'
                db.session.commit()
                flash(f"Pickup request {request_id} assigned to {agent.name} and status updated to 'Assigned'.", "success")
            else:
                flash("Invalid agent selected. Please select a user with 'agent' role.", "danger")
        else: # Handle case where no agent is selected (e.g., if dropdown allows empty)
            pickup_request.agent_id = None 
            pickup_request.status = 'Pending' # Reset status if unassigned
            db.session.commit()
            flash(f"Pickup request {request_id} unassigned. Status reset to 'Pending'.", "info")
        return redirect(url_for('admin_dashboard'))
    else:
        flash(f"Pickup request {request_id} is not pending and cannot be assigned.", "warning")
        return redirect(url_for('admin_dashboard'))


@app.route('/view_pickup_details/<int:request_id>', endpoint='admin_view_pickup')
@admin_required
def view_pickup_details(request_id):
    pickup_request = PickupRequest.query.get_or_404(request_id)
    return render_template('pickup_details.html', pickup_request=pickup_request)


@app.route('/calculate_transaction/<int:request_id>', methods=['POST'])
@admin_required
def calculate_transaction(request_id):
    pickup_request = PickupRequest.query.get_or_404(request_id)
    # Only allow transaction calculation if status is 'Completed' and no transaction exists
    if pickup_request.status == 'Completed' and not pickup_request.transaction:
        try:
            actual_weight_kg = Decimal(request.form['actual_weight_kg'])
            # Ensure price_per_kg is also Decimal for accurate calculation
            price_per_kg = Decimal(str(pickup_request.scrap_item.price_per_kg)) 
            total_amount = actual_weight_kg * price_per_kg

            transaction = Transaction(
                pickup_request_id=pickup_request.id,
                total_amount=total_amount,
                payment_status='Pending', # Default status for new transaction
                bill_generated=False # Default status for new transaction
            )
            db.session.add(transaction)
            db.session.commit()
            flash('Transaction calculated and created successfully!', 'success')
            return redirect(url_for('admin_view_pickup', request_id=request_id)) # Redirect back to details page
        except ValueError:
            flash("Invalid weight entered. Please enter a numeric value.", "danger")
            return redirect(url_for('admin_view_pickup', request_id=request_id)) # Redirect back to details page with error
        except Exception as e:
            flash(f"An error occurred during transaction calculation: {e}", "danger")
            return redirect(url_for('admin_view_pickup', request_id=request_id))
    else:
        flash('Transaction cannot be calculated for this request (status not Completed or transaction already exists).', 'warning')
        return redirect(url_for('admin_view_pickup', request_id=request_id)) # Redirect back to details page


@app.route('/update_transaction_status/<int:transaction_id>', methods=['POST'])
@admin_required
def update_transaction_status(transaction_id):
    transaction = Transaction.query.get_or_404(transaction_id)
    payment_status = request.form['payment_status']
    bill_generated = 'bill_generated' in request.form # Check if the checkbox was checked

    transaction.payment_status = payment_status
    transaction.bill_generated = bill_generated
    db.session.commit()
    flash("Transaction status updated successfully.", "success")

    # Do NOT auto-generate bill after marking as Paid
    # if payment_status == 'Paid':
    #     return redirect(url_for('generate_bill', transaction_id=transaction.id))
    return redirect(url_for('admin_view_pickup', request_id=transaction.pickup_request_id))


@app.route('/generate_bill/<int:transaction_id>')
@admin_required
def generate_bill(transaction_id):
    transaction = Transaction.query.get_or_404(transaction_id)
    pickup_request = transaction.pickup_request
    seller = pickup_request.seller
    agent = pickup_request.agent
    scrap_item = pickup_request.scrap_item

    rendered = render_template('bill.html', transaction=transaction, pickup_request=pickup_request, seller=seller, agent=agent, scrap_item=scrap_item)
    
    try:
        # Generate PDF from HTML using pdfkit
        # Ensure wkhtmltopdf is installed and its path is correctly set in PDFKIT_CONFIG
        pdf = pdfkit.from_string(rendered, False, configuration=PDFKIT_CONFIG)
        
        # Send PDF as a file download
        response = send_file(
            io.BytesIO(pdf),
            mimetype='application/pdf'
        )
        response.headers['Content-Disposition'] = f'inline; filename=bill_{transaction.id}.pdf'
        return response
    except Exception as e:
        flash(f"Error generating PDF: {e}. Make sure wkhtmltopdf is installed and configured correctly.", "danger")
        return redirect(url_for('admin_view_pickup', request_id=transaction.pickup_request_id))


@app.route('/agent/pickup_details/<int:request_id>')
@agent_required
def agent_pickup_details(request_id):
    pickup_request = PickupRequest.query.get_or_404(request_id)
    if pickup_request.agent_id != session['user_id']:
        flash("You are not authorized to view this pickup request.", "danger")
        return redirect(url_for('agent_dashboard')), 403
    return render_template('agent_pickup_details.html', pickup_request=pickup_request)


@app.route('/agent/update_status/<int:request_id>', methods=['POST'])
@agent_required
def update_pickup_status(request_id):
    pickup_request = PickupRequest.query.get_or_404(request_id)
    if pickup_request.agent_id != session['user_id']:
        flash("You are not authorized to update this pickup request.", "danger")
        return redirect(url_for('agent_dashboard'))
    new_status = request.form['status']
    allowed_statuses = ['In Transit', 'Arrived', 'Completed', 'Failed', 'Cancelled']
    if new_status in allowed_statuses:
        pickup_request.status = new_status
        db.session.commit()
        flash("Pickup status updated.", "success")
    else:
        flash("Invalid status selected.", "warning")
    return redirect(url_for('agent_dashboard'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)