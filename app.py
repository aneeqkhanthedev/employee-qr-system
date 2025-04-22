from flask import Flask, render_template, request, Response
import pandas as pd
import qrcode
import os
from io import BytesIO
import base64
import hashlib
import logging
from PIL import Image
import pyzbar.pyzbar as pyzbar
import shutil

app = Flask(__name__)

EMPLOYEE_CSV = 'employees.csv'
QR_FOLDER = 'static/qrcodes'
SECRET_KEY = 'secure_employee_key_2025_x9z7q3w8'
BASE_URL = 'https://devserver-master--qrverify.netlify.app'  # Update this for production

# Set up logging
logging.basicConfig(level=logging.DEBUG)

# Ensure QR code folder exists
os.makedirs(QR_FOLDER, exist_ok=True)

def generate_secure_qr_data(emp_id):
    """Generate secure QR data with emp_id only, as a URL"""
    data_to_sign = f"{emp_id}"
    signature = hashlib.sha256((data_to_sign + SECRET_KEY).encode()).hexdigest()
    qr_data = f"{BASE_URL}/verify_qr_url/{emp_id}/{signature}"
    logging.debug(f"Generated QR data: {qr_data}")
    return qr_data, signature

def verify_qr_data(emp_id, signature):
    """Verify QR data integrity"""
    try:
        data_to_verify = f"{emp_id}"
        expected_signature = hashlib.sha256((data_to_verify + SECRET_KEY).encode()).hexdigest()
        
        if signature != expected_signature:
            logging.error(f"Signature mismatch for emp_id: {emp_id}")
            return False, "QR code tampered with"
        
        logging.debug(f"QR data verified for emp_id: {emp_id}")
        return True, "Valid QR code"
    except Exception as e:
        logging.error(f"Verification error: {str(e)}")
        return False, f"Verification error: {str(e)}"

def generate_qr(emp_id):
    """Generate and save QR code"""
    qr_data,signature = generate_secure_qr_data(emp_id)
    
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(qr_data)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    img_path = os.path.join(QR_FOLDER, f"{emp_id}.png")
    
    os.makedirs(os.path.dirname(img_path), exist_ok=True)
    img.save(img_path)
    
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode()
    logging.debug(f"Generated QR code for {emp_id} at {img_path}")
    return f"data:image/png;base64,{img_str}", img_path, signature

def load_employees():
    """Load and normalize employee data from CSV"""
    if not os.path.exists(EMPLOYEE_CSV):
        default_data = pd.DataFrame({
            'emp_id': ['EMP001', 'EMP002', 'EMP003'],
            'name': ['Siddiqui Ali', 'Jane Smith', 'Bob Johnson'],
            'status': ['authorze', 'authorize', 'unauthorize']
        })
        default_data.to_csv(EMPLOYEE_CSV, index=False)
        logging.info("Created default employees.csv")
    
    df = pd.read_csv(EMPLOYEE_CSV)
    df['status'] = df['status'].str.lower().str.strip()
    logging.debug(f"Loaded employees: {df.to_dict()}")
    return df

@app.route('/', methods=['GET', 'POST'])
def index():
    """Home page to generate or view QR code"""
    if request.method == 'POST':
        emp_id = request.form.get('emp_id', '').strip().upper()
        if not emp_id:
            logging.warning("No employee ID provided")
            return render_template('verify.html', error="Please provide an employee ID")
        
        try:
            df = load_employees()
            emp = df[df['emp_id'] == emp_id]
            
            if emp.empty:
                logging.warning(f"Employee not found: {emp_id}")
                return render_template('verify.html', error="Employee not found")
            
            emp_data = emp.iloc[0]
            img_path = os.path.join(QR_FOLDER, f"{emp_id}.png")
            
            # Always regenerate QR code to ensure it uses the new format
            img_data, img_path,signature = generate_qr(emp_id)
            
            return render_template(
                'verify.html',
                emp_id=emp_id,
                name=emp_data['name'],
                status=emp_data['status'],
                qr_img=img_data,
                signature=signature
            )
        except Exception as e:
            logging.error(f"Error in index: {str(e)}")
            return render_template('verify.html', error=f"Error: {str(e)}")
    
    return render_template('index.html')

@app.route('/verify_qr', methods=['POST'])
def verify_qr():
    """Verify QR code and return current status (for API use)"""
    qr_data = request.form.get('qr_data', '')
    if not qr_data:
        logging.warning("No QR data provided")
        return {'valid': False, 'message': 'No QR data provided', 'status': None}
    
    # Handle both old format (emp_id|status|signature) and new format (URL)
    if qr_data.startswith(BASE_URL):
        parts = qr_data.split('/')
        emp_id = parts[-2]
        signature = parts[-1]
    else:
        parts = qr_data.split('|')
        if len(parts) == 3:  # emp_id|status|signature
            emp_id, _, signature = parts
        elif len(parts) == 2:  # emp_id|signature
            emp_id, signature = parts
        else:
            logging.error(f"Invalid QR format: {qr_data}")
            return {'valid': False, 'message': 'Invalid QR format', 'status': None}
    
    is_valid, message = verify_qr_data(emp_id, signature)
    if not is_valid:
        return {'valid': False, 'message': message, 'status': None}
    
    df = load_employees()
    emp = df[df['emp_id'] == emp_id]
    
    if emp.empty:
        logging.warning(f"Employee not found: {emp_id}")
        return {'valid': False, 'message': 'Employee not found', 'status': None}
    
    current_status = emp.iloc[0]['status']
    logging.debug(f"Verifying {emp_id}: current_status={current_status}")
    
    if current_status == 'active':
        return {'valid': True, 'message': 'Employee is Authorize', 'status': current_status}
    else:
        return {'valid': False, 'message': 'Employee is Unauthorize', 'status': current_status}

@app.route('/verify_qr_url/<emp_id>/<signature>')
def verify_qr_url(emp_id, signature):
    """Return formatted result for QR code scans"""
    is_valid, message = verify_qr_data(emp_id, signature)
    if not is_valid:
        return Response(message, mimetype='text/plain', status=400)
    
    df = load_employees()
    emp = df[df['emp_id'] == emp_id]
    
    if emp.empty:
        logging.warning(f"Employee not found: {emp_id}")
        return Response("Employee not found", mimetype='text/plain', status=404)
    
    emp_data = emp.iloc[0]
    current_status = emp_data['status']
    logging.debug(f"Verifying {emp_id}: current_status={current_status}")
    
    result = (
        f"Emp ID: {emp_id}\n"
        f"Name: {emp_data['name']}\n"
        # f"Status: {current_status.capitalize()}"
        f"Status: {'Authorized' if current_status == 'active' else 'Unauthorized'}\n"
    )
    return Response(result, mimetype='text/plain')

@app.route('/update_status', methods=['GET', 'POST'])
def update_status():
    """Update employee status"""
    if request.method == 'POST':
        emp_id = request.form.get('emp_id', '').strip().upper()
        new_status = request.form.get('status', '').strip().lower()
        
        if not emp_id or not new_status:
            logging.warning("Missing employee ID or status")
            return render_template('update_status.html', error="Missing employee ID or status")
        
        try:
            df = load_employees()
            if emp_id not in df['emp_id'].values:
                logging.warning(f"Employee not found for update: {emp_id}")
                return render_template('update_status.html', error="Employee not found")
            
            df.loc[df['emp_id'] == emp_id, 'status'] = new_status
            df.to_csv(EMPLOYEE_CSV, index=False)
            logging.info(f"Updated status for {emp_id} to {new_status}")
            return render_template('update_status.html', success=f"Status updated for {emp_id} to {new_status}")
        except Exception as e:
            logging.error(f"Error updating status: {str(e)}")
            return render_template('update_status.html', error=f"Error: {str(e)}")
    
    return render_template('update_status.html')

@app.route('/scan', methods=['GET', 'POST'])
def scan():
    """Scan QR code by uploading an image (fallback)"""
    if request.method == 'POST':
        if 'qr_image' not in request.files:
            return render_template('scan.html', error="No file uploaded")
        
        file = request.files['qr_image']
        if file.filename == '':
            return render_template('scan.html', error="No file selected")
        
        try:
            img = Image.open(file).convert('RGB')
            decoded_objects = pyzbar.decode(img)
            
            if not decoded_objects:
                return render_template('scan.html', error="No QR code found in the image")
            
            qr_data = decoded_objects[0].data.decode('utf-8')
            logging.debug(f"Scanned QR data: {qr_data}")
            
            if qr_data.startswith(BASE_URL):
                parts = qr_data.split('/')
                emp_id = parts[-2]
                signature = parts[-1]
            else:
                parts = qr_data.split('|')
                if len(parts) == 3:  # emp_id|status|signature
                    emp_id, _, signature = parts
                elif len(parts) == 2:  # emp_id|signature
                    emp_id, signature = parts
                else:
                    return render_template('scan.html', error="Invalid QR format")
            
            is_valid, message = verify_qr_data(emp_id, signature)
            if not is_valid:
                return render_template('scan.html', error=message)
            
            df = load_employees()
            emp = df[df['emp_id'] == emp_id]
            
            if emp.empty:
                return render_template('scan.html', error="Employee not found")
            
            emp_data = emp.iloc[0]
            current_status = emp_data['status']
            logging.debug(f"Scanned {emp_id}: current_status={current_status}")
            
            return render_template(
                'scan.html',
                emp_id=emp_id,
                name=emp_data['name'],
                status=current_status,
                message='Employee is active' if current_status == 'active' else 'Employee is inactive',
                valid=current_status == 'active'
            )
        except Exception as e:
            logging.error(f"Error scanning QR code: {str(e)}")
            return render_template('scan.html', error=f"Error: {str(e)}")
    
    return render_template('scan.html')

if __name__ == '__main__':
    app.run(debug=True, port=5000)